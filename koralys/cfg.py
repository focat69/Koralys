"""Control Flow Graph construction for Luau bytecode.

Splits a proto's instruction stream into basic blocks and connects them
with successor/predecessor edges. This is the foundation for all higher-level
analyses (dominator trees, SSA, loop detection, AST lifting).

A "basic block" is a maximal sequence of instructions where:
  - Only the first instruction can be a jump target
  - Only the last instruction can be a branch/jump/return
  - All other instructions execute sequentially

Algorithm:
  1. Scan instructions, identify "leaders" (first instruction of each block):
     - PC 0 (entry point)
     - Target of any jump instruction
     - Instruction immediately after any jump or return (fall-through)
  2. Create blocks between consecutive leaders
  3. Connect blocks with successor/predecessor edges based on terminators
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set

from koralys.luau import (
    get_opcode,
    get_arg_a,
    get_arg_b,
    get_arg_c,
    get_arg_Bx,
    get_arg_sBx,
    get_arg_sAx,
    get_op_table,
)


@dataclass
class BasicBlock:
    """A maximal sequence of instructions with no internal branches.

    Attributes:
        id: Unique block identifier within this CFG.
        start_pc: PC of the first instruction in this block (inclusive).
        end_pc: PC of the last instruction in this block (inclusive).
            This is the terminator instruction (jump, return, or fall-through).
        successors: List of block IDs this block can transfer control to.
        predecessors: List of block IDs that can transfer control to this block.
    """
    id: int
    start_pc: int
    end_pc: int
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"BB{self.id}(pc {self.start_pc}..{self.end_pc}, "
            f"succ={self.successors}, pred={self.predecessors})"
        )


@dataclass
class CFG:
    """Control Flow Graph for a single Luau proto.

    Attributes:
        blocks: All basic blocks in program order.
        entry_id: Block ID of the entry block (always 0).
        pc_to_block: Maps every instruction PC to its containing block ID.
        block_map: Maps block ID to BasicBlock for O(1) lookup.
    """
    blocks: List[BasicBlock]
    entry_id: int
    pc_to_block: Dict[int, int]
    block_map: Dict[int, BasicBlock]

    def get_block(self, block_id: int) -> BasicBlock:
        return self.block_map[block_id]

    def entry_block(self) -> BasicBlock:
        return self.block_map[self.entry_id]

    def __repr__(self) -> str:
        return f"CFG({len(self.blocks)} blocks, entry=BB{self.entry_id})"


# --- Opcode classification ---
# These sets classify instructions by their control-flow behavior.

# Unconditional jumps: single successor = jump target, no fall-through
UNCONDITIONAL_JUMPS = frozenset({
    "JUMP", "JUMPBACK", "JUMPX",
    # FORGPREP always jumps to the FORGLOOP instruction
    "FORGPREP", "FORGPREP_INEXT", "FORGPREP_NEXT",
})

# Conditional jumps: two successors = fall-through + jump target
CONDITIONAL_JUMPS = frozenset({
    "JUMPIF", "JUMPIFNOT",
    "JUMPIFEQ", "JUMPIFLE", "JUMPIFLT",
    "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT",
    "JUMPXEQKNIL", "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS",
    # Numeric for: FORNPREP jumps past loop if condition fails, falls through to body
    "FORNPREP",
    # FORNLOOP jumps back to body if condition holds, falls through to exit
    "FORNLOOP",
    # FORGLOOP jumps back to body if iterator returns non-nil, falls through to exit
    "FORGLOOP",
})

# Terminators with no successors
NO_SUCCESSOR_OPS = frozenset({"RETURN"})


def _get_jump_target(opname: str, pc: int, inst: int) -> int:
    """Compute the absolute jump target PC for a jump/branch instruction.

    All Luau jumps encode a *signed* offset relative to (pc + 1).
    JUMPX uses the 24-bit sAx (E) field; everything else uses 16-bit sBx (D) field.
    """
    if opname == "JUMPX":
        return pc + 1 + get_arg_sAx(inst)
    else:
        return pc + 1 + get_arg_sBx(inst)


def build_cfg(proto: Dict[str, Any], luau_version: int) -> CFG:
    """Build a control flow graph from a proto's instruction stream.

    Args:
        proto: Deserialized proto dict with at least 'codeTable'.
        luau_version: Bytecode version (5 or 6) for opcode table selection.

    Returns:
        A CFG with basic blocks connected by successor/predecessor edges.
    """
    code = proto["codeTable"]
    if not code:
        block = BasicBlock(id=0, start_pc=0, end_pc=0)
        return CFG(
            blocks=[block], entry_id=0,
            pc_to_block={0: 0}, block_map={0: block},
        )

    OP_TABLE = get_op_table(luau_version)
    opcode_to_name = {info.number: info.name for info in OP_TABLE}
    aux_opcodes = {info.name for info in OP_TABLE if info.get("aux", False)}

    # --- Build instruction PC list (skipping aux words) ---
    # The codeTable is a flat array of uint32 words. Instructions with aux
    # consume two consecutive words. We need to distinguish instruction PCs
    # from aux-word PCs so we iterate correctly.
    inst_pcs: List[int] = []
    pc = 0
    while pc < len(code):
        inst_pcs.append(pc)
        inst = code[pc]
        opc = get_opcode(inst)
        name = opcode_to_name.get(opc, "UNKNOWN")
        if name in aux_opcodes and pc + 1 < len(code):
            pc += 2
        else:
            pc += 1

    inst_pc_set = set(inst_pcs)
    pc_to_inst_idx = {pc: idx for idx, pc in enumerate(inst_pcs)}

    def next_inst_pc(pc: int) -> Optional[int]:
        """Get the PC of the instruction after the one at `pc`."""
        idx = pc_to_inst_idx.get(pc)
        if idx is not None and idx + 1 < len(inst_pcs):
            return inst_pcs[idx + 1]
        return None

    # --- Pass 1: Identify leaders ---
    leaders: Set[int] = {0}  # Entry point is always a leader

    for pc in inst_pcs:
        inst = code[pc]
        opc = get_opcode(inst)
        name = opcode_to_name.get(opc, "UNKNOWN")

        if name in UNCONDITIONAL_JUMPS:
            target = _get_jump_target(name, pc, inst)
            leaders.add(target)
            npc = next_inst_pc(pc)
            if npc is not None:
                leaders.add(npc)

        elif name in CONDITIONAL_JUMPS:
            target = _get_jump_target(name, pc, inst)
            leaders.add(target)
            npc = next_inst_pc(pc)
            if npc is not None:
                leaders.add(npc)

        elif name in NO_SUCCESSOR_OPS:
            npc = next_inst_pc(pc)
            if npc is not None:
                leaders.add(npc)

        elif name == "LOADB":
            c = get_arg_c(inst)
            if c != 0:
                # LOADB with C!=0 skips C instructions ahead
                target = pc + 1 + c
                leaders.add(target)
                npc = next_inst_pc(pc)
                if npc is not None:
                    leaders.add(npc)

    # Filter to valid instruction PCs only and sort
    leaders_sorted = sorted(l for l in leaders if l in inst_pc_set)

    # --- Pass 2: Create basic blocks ---
    blocks: List[BasicBlock] = []
    leader_to_block_id: Dict[int, int] = {}

    for i, leader_pc in enumerate(leaders_sorted):
        # Block ends just before the next leader (or at end of function)
        if i + 1 < len(leaders_sorted):
            next_leader = leaders_sorted[i + 1]
            end_pc = None
            for p in reversed(inst_pcs):
                if leader_pc <= p < next_leader:
                    end_pc = p
                    break
        else:
            end_pc = inst_pcs[-1]

        if end_pc is None:
            continue

        block = BasicBlock(id=i, start_pc=leader_pc, end_pc=end_pc)
        blocks.append(block)
        leader_to_block_id[leader_pc] = i

    # --- Build PC-to-block mapping ---
    pc_to_block_id: Dict[int, int] = {}
    block_idx = 0
    for pc in inst_pcs:
        # Advance block_idx if this PC is past the current block
        while (block_idx + 1 < len(blocks)
               and blocks[block_idx + 1].start_pc <= pc):
            block_idx += 1
        if block_idx < len(blocks):
            b = blocks[block_idx]
            if b.start_pc <= pc <= b.end_pc:
                pc_to_block_id[pc] = b.id

    block_map: Dict[int, BasicBlock] = {b.id: b for b in blocks}

    # --- Pass 3: Connect successor/predecessor edges ---
    for block in blocks:
        term_pc = block.end_pc
        term_inst = code[term_pc]
        term_opc = get_opcode(term_inst)
        term_name = opcode_to_name.get(term_opc, "UNKNOWN")

        if term_name in UNCONDITIONAL_JUMPS:
            target = _get_jump_target(term_name, term_pc, term_inst)
            if target in leader_to_block_id:
                block.successors.append(leader_to_block_id[target])

        elif term_name in CONDITIONAL_JUMPS:
            # Fall-through edge (first successor)
            npc = next_inst_pc(term_pc)
            if npc is not None and npc in leader_to_block_id:
                block.successors.append(leader_to_block_id[npc])
            # Jump target edge (second successor)
            target = _get_jump_target(term_name, term_pc, term_inst)
            if target in leader_to_block_id:
                block.successors.append(leader_to_block_id[target])

        elif term_name in NO_SUCCESSOR_OPS:
            pass  # RETURN — no successors

        elif term_name == "LOADB" and get_arg_c(term_inst) != 0:
            # LOADB with skip
            target = term_pc + 1 + get_arg_c(term_inst)
            if target in leader_to_block_id:
                block.successors.append(leader_to_block_id[target])

        else:
            # Normal fall-through to next block
            npc = next_inst_pc(term_pc)
            if npc is not None and npc in leader_to_block_id:
                block.successors.append(leader_to_block_id[npc])

    # Build predecessor lists from successors
    for block in blocks:
        for succ_id in block.successors:
            if succ_id in block_map:
                block_map[succ_id].predecessors.append(block.id)

    return CFG(
        blocks=blocks,
        entry_id=blocks[0].id if blocks else 0,
        pc_to_block=pc_to_block_id,
        block_map=block_map,
    )


def cfg_to_dot(cfg: CFG, proto: Dict[str, Any], luau_version: int) -> str:
    """Generate a Graphviz DOT representation of the CFG.

    Can be rendered with: dot -Tpng cfg.dot -o cfg.png
    """
    code = proto["codeTable"]
    OP_TABLE = get_op_table(luau_version)
    opcode_to_name = {info.number: info.name for info in OP_TABLE}
    aux_opcodes = {info.name for info in OP_TABLE if info.get("aux", False)}

    lines = [
        "digraph CFG {",
        '  node [shape=record, fontname="Courier", fontsize=10];',
        '  edge [fontname="Courier", fontsize=9];',
    ]

    for block in cfg.blocks:
        # Collect instruction mnemonics for the block label
        inst_strs = []
        pc = block.start_pc
        while pc <= block.end_pc and pc < len(code):
            inst = code[pc]
            opc = get_opcode(inst)
            name = opcode_to_name.get(opc, "UNKNOWN")
            inst_strs.append(f"[{pc:03}] {name}")
            if name in aux_opcodes and pc + 1 < len(code):
                pc += 2
            else:
                pc += 1

        label = f"BB{block.id}\\n" + "\\l".join(inst_strs) + "\\l"
        lines.append(f'  bb{block.id} [label="{label}"];')

    for block in cfg.blocks:
        for succ_id in block.successors:
            lines.append(f"  bb{block.id} -> bb{succ_id};")

    lines.append("}")
    return "\n".join(lines)


def cfg_to_text(cfg: CFG, proto: Dict[str, Any], luau_version: int) -> str:
    """Generate a human-readable text representation of the CFG.

    Shows each block with its instruction range, predecessor/successor lists,
    and all instruction mnemonics.
    """
    code = proto["codeTable"]
    OP_TABLE = get_op_table(luau_version)
    opcode_to_name = {info.number: info.name for info in OP_TABLE}
    aux_opcodes = {info.name for info in OP_TABLE if info.get("aux", False)}

    lines = [f"CFG: {len(cfg.blocks)} basic blocks, entry = BB{cfg.entry_id}", ""]

    for block in cfg.blocks:
        pred_str = ", ".join(f"BB{p}" for p in block.predecessors) or "(none)"
        succ_str = ", ".join(f"BB{s}" for s in block.successors) or "(none)"
        lines.append(
            f"BB{block.id} (pc {block.start_pc}..{block.end_pc}) "
            f"| pred: {pred_str} | succ: {succ_str}"
        )

        # Print instructions
        pc = block.start_pc
        while pc <= block.end_pc and pc < len(code):
            inst = code[pc]
            opc = get_opcode(inst)
            name = opcode_to_name.get(opc, "UNKNOWN")

            # Decode basic operands for display
            a = get_arg_a(inst)
            b = get_arg_b(inst)
            c = get_arg_c(inst)
            bx = get_arg_Bx(inst)
            sbx = get_arg_sBx(inst)

            detail = ""
            if name in UNCONDITIONAL_JUMPS or name in CONDITIONAL_JUMPS:
                target = _get_jump_target(name, pc, inst)
                detail = f"  -> target pc {target}"
            elif name in NO_SUCCESSOR_OPS:
                detail = f"  (B={b})"
            elif name == "LOADB" and c != 0:
                detail = f"  skip +{c} -> pc {pc + 1 + c}"

            lines.append(f"  [{pc:03}] {name:<20}{detail}")

            if name in aux_opcodes and pc + 1 < len(code):
                pc += 2
            else:
                pc += 1

        lines.append("")

    return "\n".join(lines)
