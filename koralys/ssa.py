"""SSA (Static Single Assignment) construction for Luau bytecode.

Transforms the register-based Luau bytecode into SSA form where every
register "version" has exactly one definition point. This enables:
  - Def-use chain tracking (which definition reaches which use)
  - Copy propagation (R3 = R1 -> replace uses of R3 with R1)
  - Expression folding (R2 = R0 + R1; CALL R2 -> CALL (R0 + R1))
  - Dead code elimination

Algorithm (Cytron et al. 1991):
  1. For each register, find all definition points (blocks where it's written)
  2. Place phi nodes at the dominance frontier of definition blocks
     (iterated dominance frontier — keep adding until fixed point)
  3. Rename: walk dominator tree with a per-register version stack
     - Each definition creates a new version (R0_1, R0_2, ...)
     - Each use resolves to the current version on the stack
     - Phi nodes at join points select between predecessor versions

Luau register semantics:
  - Registers R0..R(maxstacksize-1) are the "variables"
  - MOVE, LOADK, LOADN, LOADB, LOADNIL, GETGLOBAL, etc. are definitions
  - ADD, SUB, CALL, etc. both use and define registers
  - FORNPREP/FORNLOOP define loop variables in specific register ranges
  - FORGLOOP defines iteration variables in specific register ranges
  - CAPTURE reads a register but doesn't define any (for closures)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict

from koralys.cfg import CFG, BasicBlock, CONDITIONAL_JUMPS, UNCONDITIONAL_JUMPS
from koralys.dominator import DominatorTree
from koralys.luau import (
    get_opcode, get_arg_a, get_arg_b, get_arg_c,
    get_arg_Bx, get_arg_sBx, get_op_table,
)


# ---------------------------------------------------------------------------
# Instruction semantics: which registers each opcode reads and writes
# ---------------------------------------------------------------------------

def _get_defs_uses(
    name: str, inst: int, aux: Optional[int], proto: Dict[str, Any]
) -> Tuple[List[int], List[int]]:
    """Return (list_of_defined_regs, list_of_used_regs) for an instruction.

    This encodes the register-level semantics of every Luau opcode.
    """
    A = get_arg_a(inst)
    B = get_arg_b(inst)
    C = get_arg_c(inst)

    defs: List[int] = []
    uses: List[int] = []

    # --- Loads (define A, no register uses) ---
    if name in ("LOADNIL", "LOADN", "LOADK", "LOADKX", "GETGLOBAL",
                "GETIMPORT", "DUPCLOSURE", "NEWCLOSURE", "NEWTABLE",
                "DUPTABLE", "PREPVARARGS", "COVERAGE", "NOP", "BREAK",
                "NATIVECALL"):
        defs = [A]

    elif name == "LOADB":
        defs = [A]

    elif name == "MOVE":
        defs = [A]
        uses = [B]

    # --- Upvalue ops ---
    elif name == "GETUPVAL":
        defs = [A]

    elif name == "SETUPVAL":
        uses = [A]

    elif name == "CLOSEUPVALS":
        pass  # No register defs/uses in our model

    # --- Table access ---
    elif name == "GETTABLE":
        defs = [A]
        uses = [B, C]

    elif name == "SETTABLE":
        uses = [A, B, C]  # A=value, B=table, C=key

    elif name == "GETTABLEKS":
        defs = [A]
        uses = [B]  # C is constant index (aux), not register

    elif name == "SETTABLEKS":
        uses = [A, B]  # A=value, B=table, C is constant (aux)

    elif name == "GETTABLEN":
        defs = [A]
        uses = [B]  # C is literal index

    elif name == "SETTABLEN":
        uses = [A, B]  # A=value, B=table, C is literal index

    # --- Global access ---
    elif name == "SETGLOBAL":
        uses = [A]

    # --- Arithmetic (A = B op C, all registers) ---
    elif name in ("ADD", "SUB", "MUL", "DIV", "MOD", "POW", "IDIV"):
        defs = [A]
        uses = [B, C]

    # --- Arithmetic with constant (A = B op K[C]) ---
    elif name in ("ADDK", "SUBK", "MULK", "DIVK", "MODK", "POWK", "IDIVK"):
        defs = [A]
        uses = [B]  # C is constant index

    # --- Reverse arithmetic with constant (A = K[B] op C) ---
    elif name in ("SUBRK", "DIVRK"):
        defs = [A]
        uses = [C]  # B is constant index

    # --- Unary ops ---
    elif name in ("NOT", "MINUS", "LENGTH"):
        defs = [A]
        uses = [B]

    # --- Logical ops ---
    elif name in ("AND", "OR"):
        defs = [A]
        uses = [B, C]

    elif name in ("ANDK", "ORK"):
        defs = [A]
        uses = [B]  # C is constant

    # --- Concat ---
    elif name == "CONCAT":
        defs = [A]
        uses = list(range(B, C + 1))

    # --- Call ---
    elif name == "CALL":
        # CALL A B C: call R[A] with B-1 args (R[A+1]..R[A+B-1])
        # Returns C-1 results into R[A]..R[A+C-2]
        # B=0 means use all from A+1 to top; C=0 means return all
        arg_count = B - 1 if B > 0 else 0
        ret_count = C - 1 if C > 0 else 0

        uses = [A]  # Function register
        if B > 1:
            uses.extend(range(A + 1, A + B))
        elif B == 0:
            # Variable args: use A+1 to some unknown top
            # Conservatively mark just A+1
            uses.append(A + 1)

        if C > 1:
            defs = list(range(A, A + C - 1))
        elif C == 1:
            defs = []  # No return values
        else:
            defs = [A]  # Variable returns, at least A

    # --- Return ---
    elif name == "RETURN":
        if B == 0:
            # Return all from A to top
            uses = [A]
        elif B >= 2:
            uses = list(range(A, A + B - 1))
        # B=1 means return nothing

    # --- Jumps (mostly no register side-effects) ---
    elif name in ("JUMP", "JUMPBACK", "JUMPX"):
        pass

    elif name == "JUMPIF" or name == "JUMPIFNOT":
        uses = [A]

    elif name in ("JUMPIFEQ", "JUMPIFLE", "JUMPIFLT",
                   "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT"):
        uses = [A]
        # aux word contains the register to compare against
        if aux is not None:
            aux_reg = aux & 0xFF
            uses.append(aux_reg)

    elif name in ("JUMPXEQKNIL", "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS"):
        uses = [A]  # Comparing A against a constant (in aux)

    # --- Numeric for ---
    elif name == "FORNPREP":
        # FORNPREP A sBx: initializes for loop, defines R[A], R[A+1], R[A+2]
        # Uses R[A] (limit), R[A+1] (step), R[A+2] (init/index)
        uses = [A, A + 1, A + 2]
        defs = [A, A + 1, A + 2]

    elif name == "FORNLOOP":
        # FORNLOOP A sBx: increments R[A+2], compares, defines R[A+2]
        uses = [A, A + 1, A + 2]
        defs = [A + 2]

    # --- Generic for ---
    elif name in ("FORGPREP", "FORGPREP_INEXT", "FORGPREP_NEXT"):
        # FORGPREP A sBx: prepares generic for loop
        # R[A] = iterator, R[A+1] = state, R[A+2] = control
        uses = [A, A + 1, A + 2]
        defs = [A, A + 1, A + 2]

    elif name == "FORGLOOP":
        # FORGLOOP A sBx: calls iterator, returns values into R[A+3]..R[A+2+C]
        # aux word contains the number of iteration variables
        uses = [A, A + 1, A + 2]
        if aux is not None:
            nresults = aux & 0xFF
            defs = list(range(A + 3, A + 3 + nresults))
            # Also re-defines control variable
            defs.append(A + 2)
        else:
            defs = [A + 2, A + 3]  # At minimum control + first iter var

    # --- NAMECALL ---
    elif name == "NAMECALL":
        # NAMECALL A B C: R[A] = R[B], R[A+1] = R[B][K[aux]]
        # Prepares for a method call: self = R[B], method = R[B]["name"]
        defs = [A, A + 1]
        uses = [B]

    # --- GETVARARGS ---
    elif name == "GETVARARGS":
        if B == 0:
            defs = [A]  # Variable count
        else:
            defs = list(range(A, A + B - 1))

    # --- SETLIST ---
    elif name == "SETLIST":
        # SETLIST A B C: R[A][aux..aux+C-2] = R[B]..R[B+C-2]
        uses = [A]
        if C > 1:
            uses.extend(range(B, B + C - 1))
        elif C == 0:
            uses.append(B)  # Variable count

    # --- CAPTURE ---
    elif name == "CAPTURE":
        # CAPTURE type A: captures register A for a closure
        if B == 1:  # CAP_VALUE
            uses = [A]
        elif B == 2:  # CAP_REF
            uses = [A]
        # CAP_UPVAL (B=0) doesn't use a register

    # --- FASTCALL variants ---
    elif name == "FASTCALL":
        pass  # Just a hint, CALL follows

    elif name == "FASTCALL1":
        uses = [B]  # Single arg in B

    elif name == "FASTCALL2":
        uses = [B]  # First arg in B
        if aux is not None:
            uses.append(aux & 0xFF)  # Second arg in aux

    elif name == "FASTCALL2K":
        uses = [B]  # First arg in B, second is constant (aux)

    elif name == "FASTCALL3":
        uses = [B]  # Args are in B, C, aux
        uses.append(C)
        if aux is not None:
            uses.append(aux & 0xFF)

    return defs, uses


# ---------------------------------------------------------------------------
# SSA data structures
# ---------------------------------------------------------------------------

@dataclass
class PhiNode:
    """A phi node at a join point in the CFG.

    Phi nodes resolve the "which definition reaches here?" question when
    multiple control flow paths merge at a block.

    Attributes:
        register: The register number this phi is for.
        block_id: The block this phi is placed at (beginning of block).
        version: The SSA version this phi defines (assigned during renaming).
        operands: Maps predecessor block ID -> SSA version from that path.
    """
    register: int
    block_id: int
    version: int = -1  # Set during renaming
    operands: Dict[int, int] = field(default_factory=dict)

    def __repr__(self) -> str:
        ops = ", ".join(
            f"BB{bid}:R{self.register}_{ver}"
            for bid, ver in sorted(self.operands.items())
        )
        return f"R{self.register}_{self.version} = phi({ops})"


@dataclass
class SSADef:
    """A single SSA definition (one version of one register).

    Attributes:
        register: Original register number.
        version: SSA version number (unique per register).
        block_id: Block where this definition occurs.
        pc: Instruction PC of the definition (-1 for phi nodes).
        is_phi: True if this is a phi node definition.
    """
    register: int
    version: int
    block_id: int
    pc: int
    is_phi: bool = False


@dataclass
class SSAUse:
    """A single SSA use (a read of a specific version of a register).

    Attributes:
        register: Original register number.
        version: SSA version being read.
        block_id: Block where this use occurs.
        pc: Instruction PC of the use.
    """
    register: int
    version: int
    block_id: int
    pc: int


@dataclass
class SSAForm:
    """Complete SSA representation of a proto.

    Attributes:
        phi_nodes: Maps block_id -> list of phi nodes at that block.
        defs: Maps (register, version) -> SSADef.
        uses: List of all SSA uses.
        version_count: Maps register -> total number of versions created.
        pc_defs: Maps PC -> list of (register, version) defined there.
        pc_uses: Maps PC -> list of (register, version) used there.
    """
    phi_nodes: Dict[int, List[PhiNode]]
    defs: Dict[Tuple[int, int], SSADef]
    uses: List[SSAUse]
    version_count: Dict[int, int]
    pc_defs: Dict[int, List[Tuple[int, int]]]
    pc_uses: Dict[int, List[Tuple[int, int]]]

    def get_def(self, reg: int, ver: int) -> Optional[SSADef]:
        return self.defs.get((reg, ver))

    def get_phi_nodes(self, block_id: int) -> List[PhiNode]:
        return self.phi_nodes.get(block_id, [])

    def __repr__(self) -> str:
        total_phis = sum(len(v) for v in self.phi_nodes.values())
        total_defs = len(self.defs)
        total_uses = len(self.uses)
        return f"SSAForm({total_defs} defs, {total_uses} uses, {total_phis} phis)"


# ---------------------------------------------------------------------------
# SSA construction
# ---------------------------------------------------------------------------

def _find_def_blocks(
    cfg: CFG, proto: Dict[str, Any], luau_version: int
) -> Dict[int, Set[int]]:
    """Find all blocks where each register is defined.

    Returns: register -> set of block IDs where it's defined.
    """
    code = proto["codeTable"]
    OP_TABLE = get_op_table(luau_version)
    opcode_to_name = {info.number: info.name for info in OP_TABLE}
    aux_opcodes = {info.name for info in OP_TABLE if info.get("aux", False)}

    reg_def_blocks: Dict[int, Set[int]] = defaultdict(set)

    for block in cfg.blocks:
        pc = block.start_pc
        while pc <= block.end_pc and pc < len(code):
            inst = code[pc]
            opc = get_opcode(inst)
            name = opcode_to_name.get(opc, "UNKNOWN")

            aux = None
            if name in aux_opcodes and pc + 1 < len(code):
                aux = code[pc + 1]

            defs_list, _ = _get_defs_uses(name, inst, aux, proto)
            for reg in defs_list:
                reg_def_blocks[reg].add(block.id)

            if name in aux_opcodes and pc + 1 < len(code):
                pc += 2
            else:
                pc += 1

    return dict(reg_def_blocks)


def _place_phi_nodes(
    cfg: CFG, dtree: DominatorTree, reg_def_blocks: Dict[int, Set[int]]
) -> Dict[int, List[PhiNode]]:
    """Place phi nodes using the iterated dominance frontier.

    For each register, we iteratively add phi nodes at the dominance
    frontier of all definition blocks until no more are added.

    Returns: block_id -> list of PhiNodes at that block.
    """
    phi_map: Dict[int, List[PhiNode]] = defaultdict(list)

    for reg, def_blocks in reg_def_blocks.items():
        # Iterated dominance frontier (IDF)
        # Start with blocks where reg is defined
        worklist = list(def_blocks)
        ever_on_worklist = set(def_blocks)
        phi_placed: Set[int] = set()  # Blocks where we placed a phi for this reg

        while worklist:
            block_id = worklist.pop()
            for frontier_block in dtree.dom_frontier.get(block_id, set()):
                if frontier_block not in phi_placed:
                    phi_placed.add(frontier_block)
                    phi_map[frontier_block].append(
                        PhiNode(register=reg, block_id=frontier_block)
                    )
                    # Phi node is itself a definition -> add to worklist
                    if frontier_block not in ever_on_worklist:
                        ever_on_worklist.add(frontier_block)
                        worklist.append(frontier_block)

    return dict(phi_map)


def _rename_variables(
    cfg: CFG, dtree: DominatorTree,
    phi_map: Dict[int, List[PhiNode]],
    proto: Dict[str, Any], luau_version: int
) -> SSAForm:
    """Rename all register references to SSA versions.

    Walk the dominator tree. At each block:
    1. Process phi nodes (each phi defines a new version)
    2. Process instructions (each def creates new version, each use resolves)
    3. Fill in phi operands for successor blocks
    4. Recurse into dominated children
    5. Pop version stacks on return

    Returns a complete SSAForm.
    """
    code = proto["codeTable"]
    OP_TABLE = get_op_table(luau_version)
    opcode_to_name = {info.number: info.name for info in OP_TABLE}
    aux_opcodes = {info.name for info in OP_TABLE if info.get("aux", False)}

    # Per-register version counter and stack
    counter: Dict[int, int] = defaultdict(int)  # reg -> next version number
    stack: Dict[int, List[int]] = defaultdict(list)  # reg -> stack of versions

    # Output
    all_defs: Dict[Tuple[int, int], SSADef] = {}
    all_uses: List[SSAUse] = []
    pc_defs: Dict[int, List[Tuple[int, int]]] = defaultdict(list)
    pc_uses: Dict[int, List[Tuple[int, int]]] = defaultdict(list)

    def new_version(reg: int) -> int:
        """Create a new SSA version for a register."""
        ver = counter[reg]
        counter[reg] += 1
        stack[reg].append(ver)
        return ver

    def current_version(reg: int) -> int:
        """Get the current SSA version of a register (top of stack)."""
        if stack[reg]:
            return stack[reg][-1]
        # No definition seen yet — version 0 (parameter or uninitialized)
        ver = new_version(reg)
        all_defs[(reg, ver)] = SSADef(
            register=reg, version=ver, block_id=-1, pc=-1
        )
        return ver

    def rename_block(block_id: int):
        """Process a single block during SSA renaming."""
        block = cfg.get_block(block_id)

        # Track how many versions we pushed (to pop later)
        push_counts: Dict[int, int] = defaultdict(int)

        # --- 1. Process phi nodes at this block ---
        for phi in phi_map.get(block_id, []):
            ver = new_version(phi.register)
            phi.version = ver
            push_counts[phi.register] += 1
            all_defs[(phi.register, ver)] = SSADef(
                register=phi.register, version=ver,
                block_id=block_id, pc=-1, is_phi=True
            )

        # --- 2. Process instructions ---
        pc = block.start_pc
        while pc <= block.end_pc and pc < len(code):
            inst = code[pc]
            opc = get_opcode(inst)
            name = opcode_to_name.get(opc, "UNKNOWN")

            aux = None
            if name in aux_opcodes and pc + 1 < len(code):
                aux = code[pc + 1]

            defs_list, uses_list = _get_defs_uses(name, inst, aux, proto)

            # Resolve uses first (before this instruction's defs)
            for reg in uses_list:
                ver = current_version(reg)
                all_uses.append(SSAUse(
                    register=reg, version=ver,
                    block_id=block_id, pc=pc
                ))
                pc_uses[pc].append((reg, ver))

            # Then process definitions
            for reg in defs_list:
                ver = new_version(reg)
                push_counts[reg] += 1
                all_defs[(reg, ver)] = SSADef(
                    register=reg, version=ver,
                    block_id=block_id, pc=pc
                )
                pc_defs[pc].append((reg, ver))

            if name in aux_opcodes and pc + 1 < len(code):
                pc += 2
            else:
                pc += 1

        # --- 3. Fill phi operands for successors ---
        for succ_id in block.successors:
            for phi in phi_map.get(succ_id, []):
                ver = current_version(phi.register)
                phi.operands[block_id] = ver

        # --- 4. Recurse into dominator tree children ---
        for child_id in sorted(dtree.children.get(block_id, [])):
            rename_block(child_id)

        # --- 5. Pop version stacks ---
        for reg, count in push_counts.items():
            for _ in range(count):
                stack[reg].pop()

    # Start renaming from entry block
    rename_block(cfg.entry_id)

    version_count = dict(counter)

    return SSAForm(
        phi_nodes=phi_map,
        defs=all_defs,
        uses=all_uses,
        version_count=version_count,
        pc_defs=dict(pc_defs),
        pc_uses=dict(pc_uses),
    )


def build_ssa(
    cfg: CFG, dtree: DominatorTree,
    proto: Dict[str, Any], luau_version: int
) -> SSAForm:
    """Build SSA form for a proto.

    This is the main entry point. Combines phi placement and renaming.

    Args:
        cfg: Control flow graph of the proto.
        dtree: Dominator tree of the CFG.
        proto: Deserialized proto dict.
        luau_version: Bytecode version (5 or 6).

    Returns:
        Complete SSA form with phi nodes, defs, and uses.
    """
    reg_def_blocks = _find_def_blocks(cfg, proto, luau_version)
    phi_map = _place_phi_nodes(cfg, dtree, reg_def_blocks)
    return _rename_variables(cfg, dtree, phi_map, proto, luau_version)


# ---------------------------------------------------------------------------
# Display / debugging
# ---------------------------------------------------------------------------

def ssa_to_text(ssa: SSAForm, cfg: CFG, proto: Dict[str, Any],
                luau_version: int) -> str:
    """Generate a human-readable SSA dump."""
    code = proto["codeTable"]
    OP_TABLE = get_op_table(luau_version)
    opcode_to_name = {info.number: info.name for info in OP_TABLE}
    aux_opcodes = {info.name for info in OP_TABLE if info.get("aux", False)}

    lines = [str(ssa), ""]

    # Show phi nodes and instructions per block
    for block in cfg.blocks:
        lines.append(f"BB{block.id} (pc {block.start_pc}..{block.end_pc}):")

        # Phi nodes
        for phi in ssa.get_phi_nodes(block.id):
            lines.append(f"  PHI: {phi}")

        # Instructions with SSA annotations
        pc = block.start_pc
        while pc <= block.end_pc and pc < len(code):
            inst = code[pc]
            opc = get_opcode(inst)
            name = opcode_to_name.get(opc, "UNKNOWN")

            # Gather SSA info
            def_strs = [f"R{r}_{v}" for r, v in ssa.pc_defs.get(pc, [])]
            use_strs = [f"R{r}_{v}" for r, v in ssa.pc_uses.get(pc, [])]

            detail = f"  [{pc:03}] {name:<20}"
            if def_strs:
                detail += f" defs=[{', '.join(def_strs)}]"
            if use_strs:
                detail += f" uses=[{', '.join(use_strs)}]"
            lines.append(detail)

            if name in aux_opcodes and pc + 1 < len(code):
                pc += 2
            else:
                pc += 1

        lines.append("")

    return "\n".join(lines)
