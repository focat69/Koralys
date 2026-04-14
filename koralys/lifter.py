"""AST lifter and Luau source emitter.

Converts the analyzed bytecode (CFG + structures + SSA) into an AST,
then emits readable Luau source code.

Pipeline:
  1. Instruction lifting: convert each bytecode instruction into raw AST nodes
  2. Expression folding: inline single-use temporaries into compound expressions
  3. Structure walking: emit nested Luau structures using structurizer output
  4. Source emission: pretty-print the AST as Luau source text

This is the final step in the decompilation pipeline:
  bytecode -> deserialize -> CFG -> dominators -> structures -> SSA -> lifter -> source
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict

from koralys.cfg import CFG, BasicBlock, CONDITIONAL_JUMPS
from koralys.dominator import DominatorTree
from koralys.structurizer import (
    StructureInfo, LoopInfo, LoopType, IfInfo,
    identify_structures,
)
from koralys.ssa import SSAForm, build_ssa
from koralys.ast_nodes import (
    Expr, Stmt, Block,
    NumberLit, StringLit, BoolLit, NilLit, VarargLit,
    VarRef, UpvalueRef, GlobalRef,
    IndexExpr, FieldExpr, BinOp, UnOp, ConcatExpr,
    FunctionCallExpr, MethodCallExpr,
    TableConstructor, FunctionExpr, ClosureExpr,
    LocalDecl, Assign, FunctionCallStmt, MethodCallStmt,
    ReturnStmt, WhileStmt, RepeatUntilStmt,
    NumericForStmt, GenericForStmt, IfStmt,
    BreakStmt, ContinueStmt, CommentStmt,
)
from koralys.luau import (
    get_opcode, get_arg_a, get_arg_b, get_arg_c,
    get_arg_Bx, get_arg_sBx, get_arg_sAx, get_op_table,
)
from koralys.constants import (
    LBC_CONSTANT_NIL, LBC_CONSTANT_BOOLEAN, LBC_CONSTANT_NUMBER,
    LBC_CONSTANT_STRING, LBC_CONSTANT_IMPORT, LBC_CONSTANT_TABLE,
    LBC_CONSTANT_CLOSURE, LBC_CONSTANT_VECTOR,
    builtin_name,
)


# ---------------------------------------------------------------------------
# Helper: resolve constants, variable names, imports
# ---------------------------------------------------------------------------

def _resolve_constant(proto: Dict[str, Any], idx: int) -> Expr:
    """Resolve a constant pool entry to an AST expression."""
    if idx >= len(proto["kTable"]):
        return VarRef(name=f"K{idx}")
    k = proto["kTable"][idx]
    t = k["type"]
    v = k["value"]
    if t == LBC_CONSTANT_NIL:
        return NilLit()
    elif t == LBC_CONSTANT_BOOLEAN:
        return BoolLit(value=bool(v))
    elif t == LBC_CONSTANT_NUMBER:
        return NumberLit(value=v)
    elif t == LBC_CONSTANT_STRING:
        return StringLit(value=v)
    elif t == LBC_CONSTANT_VECTOR:
        # Vector constants: return as a constructor call
        return FunctionCallExpr(
            func=GlobalRef(name="Vector3"),
            args=[NumberLit(v[0]), NumberLit(v[1]), NumberLit(v[2])]
            if isinstance(v, (list, tuple)) and len(v) >= 3
            else [NumberLit(0), NumberLit(0), NumberLit(0)]
        )
    else:
        return VarRef(name=f"K{idx}")


def _resolve_import(proto: Dict[str, Any], string_table: List[str], ids: int) -> str:
    """Resolve an import ID to a dotted path string (e.g. 'math.floor')."""
    count = ids >> 30
    parts = []
    if count > 0:
        id1 = (ids >> 20) & 1023
        k = proto["kTable"][id1]
        if k["type"] == LBC_CONSTANT_STRING:
            parts.append(k["value"])
    if count > 1:
        id2 = (ids >> 10) & 1023
        k = proto["kTable"][id2]
        if k["type"] == LBC_CONSTANT_STRING:
            parts.append(k["value"])
    if count > 2:
        id3 = ids & 1023
        k = proto["kTable"][id3]
        if k["type"] == LBC_CONSTANT_STRING:
            parts.append(k["value"])
    return ".".join(parts) if parts else f"import({ids})"


class NameResolver:
    """Resolves register numbers to variable names using debug info and SSA."""

    def __init__(self, proto: Dict[str, Any], ssa: SSAForm):
        self.proto = proto
        self.ssa = ssa
        self.debug_info = proto.get("debugInfo")
        # Track which SSA versions have been declared as locals
        self.declared: Set[Tuple[int, int]] = set()
        # Auto-increment for unnamed variables
        self._next_id = 0
        # Cache: (register, version) -> name
        self._name_cache: Dict[Tuple[int, int], str] = {}
        self._debug_names: Set[str] = set()

    def get_name(self, reg: int, version: int, pc: int = -1) -> str:
        """Get the variable name for a register at a given version."""
        key = (reg, version)
        if key in self._name_cache:
            return self._name_cache[key]

        # Try debug info first
        name = self._debug_name(reg, pc)
        if name:
            self._name_cache[key] = name
            self._debug_names.add(name)
            return name

        # Fall back to auto-generated name
        name = f"v{reg}"
        if version > 0:
            name = f"v{reg}_{version}"
        self._name_cache[key] = name
        return name

    def _debug_name(self, reg: int, pc: int) -> Optional[str]:
        """Look up variable name from debug info."""
        if self.debug_info is None or pc < 0:
            return None
        for var in self.debug_info.get("varInfo", []):
            if var["reg"] == reg and (var["startpc"] - 1) <= pc < var["endpc"]:
                return var["name"]
        return None

    def debug_name_at(self, reg: int, pc: int) -> Optional[str]:
        """Look up a debug name for a register at a specific PC, bypassing the cache.

        Useful for for-loop variables where the same register has different
        names in different loops.
        """
        return self._debug_name(reg, pc)

    def has_debug_name(self, name: str) -> bool:
        return name in self._debug_names

    def get_upvalue_name(self, idx: int) -> str:
        """Get upvalue name from debug info."""
        if self.debug_info and idx < len(self.debug_info.get("upvalueInfo", [])):
            return self.debug_info["upvalueInfo"][idx]
        return f"upval{idx}"

    def get_param_names(self) -> List[str]:
        """Get parameter names for the function signature."""
        names = []
        for i in range(self.proto["numParams"]):
            name = self._debug_name(i, 0)
            names.append(name if name else f"v{i}")
        return names


# ---------------------------------------------------------------------------
# Instruction lifter: bytecode instruction -> AST nodes
# ---------------------------------------------------------------------------

class InstructionLifter:
    """Converts a single bytecode instruction into AST statement(s).

    This handles expression construction for each opcode. It produces
    "raw" statements — one per instruction — which are later folded.
    """

    def __init__(
        self, proto: Dict[str, Any], luau_version: int,
        ssa: SSAForm, names: NameResolver,
        string_table: List[str],
    ):
        self.proto = proto
        self.code = proto["codeTable"]
        self.luau_version = luau_version
        self.ssa = ssa
        self.names = names
        self.string_table = string_table

        OP_TABLE = get_op_table(luau_version)
        self.opcode_to_name = {info.number: info.name for info in OP_TABLE}
        self.aux_opcodes = {info.name for info in OP_TABLE if info.get("aux", False)}

    def _var(self, reg: int, pc: int, is_def: bool = False) -> VarRef:
        """Create a VarRef for a register at a given PC."""
        # Look up SSA version
        if is_def:
            defs = self.ssa.pc_defs.get(pc, [])
            for r, v in defs:
                if r == reg:
                    name = self.names.get_name(reg, v, pc)
                    return VarRef(name=name, register=reg, ssa_version=v)
        else:
            uses = self.ssa.pc_uses.get(pc, [])
            for r, v in uses:
                if r == reg:
                    name = self.names.get_name(reg, v, pc)
                    return VarRef(name=name, register=reg, ssa_version=v)

        # Fallback: no SSA info
        name = self.names.get_name(reg, 0, pc)
        return VarRef(name=name, register=reg)

    def _const(self, idx: int) -> Expr:
        """Resolve constant pool index to expression."""
        return _resolve_constant(self.proto, idx)

    def _const_string(self, idx: int) -> str:
        """Get string value from constant pool."""
        if idx < len(self.proto["kTable"]):
            k = self.proto["kTable"][idx]
            if k["type"] == LBC_CONSTANT_STRING:
                return k["value"]
        return f"K{idx}"

    def lift_instruction(self, pc: int) -> List[Stmt]:
        """Convert a single instruction at pc into AST statement(s).

        Returns a list of statements (usually 1, sometimes 0 for NOPs/hints).
        """
        inst = self.code[pc]
        opc = get_opcode(inst)
        name = self.opcode_to_name.get(opc, "UNKNOWN")
        A = get_arg_a(inst)
        B = get_arg_b(inst)
        C = get_arg_c(inst)
        Bx = get_arg_Bx(inst)
        sBx = get_arg_sBx(inst)

        aux = None
        if name in self.aux_opcodes and pc + 1 < len(self.code):
            aux = self.code[pc + 1]

        # --- Loads ---
        if name == "LOADNIL":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[NilLit()]
            )]

        elif name == "LOADB":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[BoolLit(value=bool(B))]
            )]

        elif name == "LOADN":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[NumberLit(value=sBx)]
            )]

        elif name == "LOADK":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[self._const(Bx)]
            )]

        elif name == "LOADKX":
            if aux is not None:
                return [LocalDecl(
                    names=[self._var(A, pc, is_def=True).name],
                    exprs=[self._const(aux)]
                )]
            return []

        elif name == "MOVE":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[self._var(B, pc)]
            )]

        # --- Globals ---
        elif name == "GETGLOBAL":
            gname = self._const_string(aux) if aux is not None else "?"
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[GlobalRef(name=gname)]
            )]

        elif name == "SETGLOBAL":
            gname = self._const_string(aux) if aux is not None else "?"
            return [Assign(
                targets=[GlobalRef(name=gname)],
                exprs=[self._var(A, pc)]
            )]

        # --- Upvalues ---
        elif name == "GETUPVAL":
            uname = self.names.get_upvalue_name(B)
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[UpvalueRef(name=uname, index=B)]
            )]

        elif name == "SETUPVAL":
            uname = self.names.get_upvalue_name(B)
            return [Assign(
                targets=[UpvalueRef(name=uname, index=B)],
                exprs=[self._var(A, pc)]
            )]

        elif name == "CLOSEUPVALS":
            return []  # No visible statement

        # --- Imports ---
        elif name == "GETIMPORT":
            if Bx < len(self.proto["kTable"]):
                import_id = self.proto["kTable"][Bx]["value"]
                path = _resolve_import(self.proto, self.string_table, import_id)
            else:
                path = f"import({Bx})"
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[GlobalRef(name=path)]
            )]

        # --- Table access ---
        elif name == "GETTABLE":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[IndexExpr(table=self._var(B, pc), key=self._var(C, pc))]
            )]

        elif name == "SETTABLE":
            return [Assign(
                targets=[IndexExpr(table=self._var(B, pc), key=self._var(C, pc))],
                exprs=[self._var(A, pc)]
            )]

        elif name == "GETTABLEKS":
            field_name = self._const_string(aux) if aux is not None else "?"
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[FieldExpr(table=self._var(B, pc), field=field_name)]
            )]

        elif name == "SETTABLEKS":
            field_name = self._const_string(aux) if aux is not None else "?"
            return [Assign(
                targets=[FieldExpr(table=self._var(B, pc), field=field_name)],
                exprs=[self._var(A, pc)]
            )]

        elif name == "GETTABLEN":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[IndexExpr(table=self._var(B, pc), key=NumberLit(value=C + 1))]
            )]

        elif name == "SETTABLEN":
            return [Assign(
                targets=[IndexExpr(table=self._var(B, pc), key=NumberLit(value=C + 1))],
                exprs=[self._var(A, pc)]
            )]

        # --- Arithmetic ---
        elif name in ("ADD", "SUB", "MUL", "DIV", "MOD", "POW", "IDIV"):
            op_map = {
                "ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/",
                "MOD": "%", "POW": "^", "IDIV": "//",
            }
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[BinOp(op=op_map[name], left=self._var(B, pc), right=self._var(C, pc))]
            )]

        elif name in ("ADDK", "SUBK", "MULK", "DIVK", "MODK", "POWK", "IDIVK"):
            op_map = {
                "ADDK": "+", "SUBK": "-", "MULK": "*", "DIVK": "/",
                "MODK": "%", "POWK": "^", "IDIVK": "//",
            }
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[BinOp(op=op_map[name], left=self._var(B, pc), right=self._const(C))]
            )]

        elif name in ("SUBRK", "DIVRK"):
            op_map = {"SUBRK": "-", "DIVRK": "/"}
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[BinOp(op=op_map[name], left=self._const(B), right=self._var(C, pc))]
            )]

        # --- Unary ---
        elif name == "NOT":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[UnOp(op="not ", operand=self._var(B, pc))]
            )]

        elif name == "MINUS":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[UnOp(op="-", operand=self._var(B, pc))]
            )]

        elif name == "LENGTH":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[UnOp(op="#", operand=self._var(B, pc))]
            )]

        # --- Logical ---
        elif name in ("AND", "OR"):
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[BinOp(op=name.lower(), left=self._var(B, pc), right=self._var(C, pc))]
            )]

        elif name in ("ANDK", "ORK"):
            op = "and" if name == "ANDK" else "or"
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[BinOp(op=op, left=self._var(B, pc), right=self._const(C))]
            )]

        # --- Concat ---
        elif name == "CONCAT":
            parts = [self._var(r, pc) for r in range(B, C + 1)]
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[ConcatExpr(parts=parts)]
            )]

        # --- Call ---
        elif name == "CALL":
            func_var = self._var(A, pc)
            args: List[Expr] = []
            if B == 0:
                args = [VarRef(name="...", register=-1)]  # vararg
            elif B > 1:
                args = [self._var(r, pc) for r in range(A + 1, A + B)]

            call_expr = FunctionCallExpr(
                func=func_var, args=args,
                is_vararg_return=(C == 0)
            )

            if C == 1:
                # No return values — standalone call
                return [FunctionCallStmt(call=call_expr)]
            elif C == 2:
                # Single return
                return [LocalDecl(
                    names=[self._var(A, pc, is_def=True).name],
                    exprs=[call_expr]
                )]
            elif C == 0:
                # Multi-return (variable)
                return [LocalDecl(
                    names=[self._var(A, pc, is_def=True).name],
                    exprs=[call_expr]
                )]
            else:
                # Multiple returns
                ret_names = [self._var(r, pc, is_def=True).name for r in range(A, A + C - 1)]
                return [LocalDecl(names=ret_names, exprs=[call_expr])]

        # --- Return ---
        elif name == "RETURN":
            if B == 1:
                return [ReturnStmt(values=[])]
            elif B == 0:
                return [ReturnStmt(values=[self._var(A, pc), VarargLit()])]
            elif B == 2:
                return [ReturnStmt(values=[self._var(A, pc)])]
            else:
                return [ReturnStmt(
                    values=[self._var(r, pc) for r in range(A, A + B - 1)]
                )]

        # --- Tables ---
        elif name == "NEWTABLE":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[TableConstructor(entries=[])]
            )]

        elif name == "DUPTABLE":
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[TableConstructor(entries=[])]
            )]

        elif name == "SETLIST":
            # SETLIST A B C aux: R[A][aux..aux+C-2] = R[B]..R[B+C-2]
            table_var = self._var(A, pc)
            stmts = []
            if aux is not None and C > 0:
                start_idx = aux
                count = C - 1
                for k in range(count):
                    stmts.append(Assign(
                        targets=[IndexExpr(table=VarRef(name=table_var.name, register=table_var.register, ssa_version=table_var.ssa_version), key=NumberLit(value=start_idx + k))],
                        exprs=[self._var(B + k, pc)]
                    ))
            return stmts

        # --- Closures ---
        elif name == "NEWCLOSURE" or name == "DUPCLOSURE":
            proto_idx = Bx
            return [LocalDecl(
                names=[self._var(A, pc, is_def=True).name],
                exprs=[ClosureExpr(proto_index=proto_idx)]
            )]

        # --- NAMECALL ---
        elif name == "NAMECALL":
            method_name = self._const_string(aux) if aux is not None else "?"
            # NAMECALL sets up R[A] = method, R[A+1] = self
            # The actual call happens at the next CALL instruction.
            # We emit a comment; the CALL handler will produce the method call.
            return [CommentStmt(text=f"namecall: {self._var(B, pc).name}:{method_name}")]

        # --- GETVARARGS ---
        elif name == "GETVARARGS":
            if B == 0:
                return [LocalDecl(
                    names=[self._var(A, pc, is_def=True).name],
                    exprs=[VarargLit()]
                )]
            else:
                names_list = [self._var(r, pc, is_def=True).name for r in range(A, A + B - 1)]
                return [LocalDecl(names=names_list, exprs=[VarargLit()])]

        # --- Vararg prep ---
        elif name == "PREPVARARGS":
            return []  # No visible statement

        # --- Jumps (handled by structure walker, not emitted as statements) ---
        elif name in ("JUMP", "JUMPBACK", "JUMPX",
                       "JUMPIF", "JUMPIFNOT",
                       "JUMPIFEQ", "JUMPIFLE", "JUMPIFLT",
                       "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT",
                       "JUMPXEQKNIL", "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS"):
            return []  # Handled by structure walker

        # --- For loops (handled by structure walker) ---
        elif name in ("FORNPREP", "FORNLOOP", "FORGPREP",
                       "FORGPREP_INEXT", "FORGPREP_NEXT", "FORGLOOP"):
            return []  # Handled by structure walker

        # --- FASTCALL (just hints, the actual CALL follows) ---
        elif name in ("FASTCALL", "FASTCALL1", "FASTCALL2",
                       "FASTCALL2K", "FASTCALL3"):
            return []  # The CALL instruction that follows handles the actual call

        # --- CAPTURE (part of closure creation, no visible statement) ---
        elif name == "CAPTURE":
            return []

        # --- COVERAGE (profiling hint) ---
        elif name == "COVERAGE":
            return []

        # --- NOP / BREAK ---
        elif name == "NOP":
            return []

        elif name == "BREAK":
            return [BreakStmt()]

        # --- Unknown ---
        else:
            return [CommentStmt(text=f"UNKNOWN opcode: {name}")]

    def lift_condition(self, pc: int) -> Expr:
        """Lift a conditional jump instruction into a condition expression.

        For if/while conditions. Returns the condition that, when true,
        takes the fall-through (true) branch.
        """
        inst = self.code[pc]
        opc = get_opcode(inst)
        name = self.opcode_to_name.get(opc, "UNKNOWN")
        A = get_arg_a(inst)
        B = get_arg_b(inst)

        aux = None
        if name in self.aux_opcodes and pc + 1 < len(self.code):
            aux = self.code[pc + 1]

        # JUMPIF R(A) — jumps if R(A) is truthy -> fall-through if falsy
        # So the "true branch" condition is: NOT R(A)
        if name == "JUMPIF":
            return UnOp(op="not ", operand=self._var(A, pc))

        # JUMPIFNOT R(A) — jumps if R(A) is falsy -> fall-through if truthy
        if name == "JUMPIFNOT":
            return self._var(A, pc)

        # Comparison jumps: JUMPIFEQ jumps when R(A)==aux -> fall-through when R(A)~=aux
        # So for "if" with fall-through as true branch, we invert
        cmp_ops = {
            "JUMPIFEQ": "~=", "JUMPIFLE": ">", "JUMPIFLT": ">=",
            "JUMPIFNOTEQ": "==", "JUMPIFNOTLE": "<=", "JUMPIFNOTLT": "<",
        }
        if name in cmp_ops:
            op = cmp_ops[name]
            if aux is not None:
                aux_reg = aux & 0xFF
                return BinOp(op=op, left=self._var(A, pc), right=self._var(aux_reg, pc))
            return self._var(A, pc)

        # JUMPXEQK variants
        if name == "JUMPXEQKNIL":
            not_flag = (aux >> 31) & 1 if aux is not None else 0
            op = "~=" if not not_flag else "=="
            return BinOp(op=op, left=self._var(A, pc), right=NilLit())

        if name == "JUMPXEQKB":
            not_flag = (aux >> 31) & 1 if aux is not None else 0
            val = bool(aux & 1) if aux is not None else False
            op = "~=" if not not_flag else "=="
            return BinOp(op=op, left=self._var(A, pc), right=BoolLit(value=val))

        if name == "JUMPXEQKN":
            not_flag = (aux >> 31) & 1 if aux is not None else 0
            k_idx = (aux & 0x00FFFFFF) if aux is not None else 0
            op = "~=" if not not_flag else "=="
            return BinOp(op=op, left=self._var(A, pc), right=self._const(k_idx))

        if name == "JUMPXEQKS":
            not_flag = (aux >> 31) & 1 if aux is not None else 0
            k_idx = (aux & 0x00FFFFFF) if aux is not None else 0
            op = "~=" if not not_flag else "=="
            return BinOp(op=op, left=self._var(A, pc), right=self._const(k_idx))

        # Fallback
        return VarRef(name=f"<cond@{pc}>", register=-1)


# ---------------------------------------------------------------------------
# Expression folder: inline single-use temporaries
# ---------------------------------------------------------------------------

def _count_uses(ssa: SSAForm) -> Dict[Tuple[int, int], int]:
    """Count how many times each SSA version is used."""
    counts: Dict[Tuple[int, int], int] = defaultdict(int)
    for use in ssa.uses:
        counts[(use.register, use.version)] += 1
    # Also count phi operand uses
    for block_id, phis in ssa.phi_nodes.items():
        for phi in phis:
            for _, ver in phi.operands.items():
                counts[(phi.register, ver)] += 1
    return dict(counts)


# ---------------------------------------------------------------------------
# Expression folder: inline single-use temporaries into compound expressions
# ---------------------------------------------------------------------------

def _collect_refs(expr: Expr) -> Set[str]:
    """Collect all VarRef names referenced in an expression."""
    refs: Set[str] = set()
    if isinstance(expr, VarRef):
        refs.add(expr.name)
    elif isinstance(expr, BinOp):
        refs |= _collect_refs(expr.left)
        refs |= _collect_refs(expr.right)
    elif isinstance(expr, UnOp):
        refs |= _collect_refs(expr.operand)
    elif isinstance(expr, ConcatExpr):
        for p in expr.parts:
            refs |= _collect_refs(p)
    elif isinstance(expr, FunctionCallExpr):
        refs |= _collect_refs(expr.func)
        for a in expr.args:
            refs |= _collect_refs(a)
    elif isinstance(expr, MethodCallExpr):
        refs |= _collect_refs(expr.obj)
        for a in expr.args:
            refs |= _collect_refs(a)
    elif isinstance(expr, IndexExpr):
        refs |= _collect_refs(expr.table)
        refs |= _collect_refs(expr.key)
    elif isinstance(expr, FieldExpr):
        refs |= _collect_refs(expr.table)
    elif isinstance(expr, TableConstructor):
        for key, val in expr.entries:
            if key is not None:
                refs |= _collect_refs(key)
            refs |= _collect_refs(val)
    return refs


def _substitute(expr: Expr, name: str, replacement: Expr) -> Expr:
    """Replace all VarRef(name=name) in expr with replacement.

    Returns a new expression tree (does not mutate the original).
    """
    if isinstance(expr, VarRef) and expr.name == name:
        return replacement
    elif isinstance(expr, BinOp):
        return BinOp(
            op=expr.op,
            left=_substitute(expr.left, name, replacement),
            right=_substitute(expr.right, name, replacement),
        )
    elif isinstance(expr, UnOp):
        return UnOp(op=expr.op, operand=_substitute(expr.operand, name, replacement))
    elif isinstance(expr, ConcatExpr):
        return ConcatExpr(parts=[_substitute(p, name, replacement) for p in expr.parts])
    elif isinstance(expr, FunctionCallExpr):
        return FunctionCallExpr(
            func=_substitute(expr.func, name, replacement),
            args=[_substitute(a, name, replacement) for a in expr.args],
            is_vararg_return=expr.is_vararg_return,
        )
    elif isinstance(expr, MethodCallExpr):
        return MethodCallExpr(
            obj=_substitute(expr.obj, name, replacement),
            method=expr.method,
            args=[_substitute(a, name, replacement) for a in expr.args],
            is_vararg_return=expr.is_vararg_return,
        )
    elif isinstance(expr, IndexExpr):
        return IndexExpr(
            table=_substitute(expr.table, name, replacement),
            key=_substitute(expr.key, name, replacement),
        )
    elif isinstance(expr, FieldExpr):
        return FieldExpr(
            table=_substitute(expr.table, name, replacement),
            field=expr.field,
        )
    elif isinstance(expr, TableConstructor):
        new_entries = []
        for key, val in expr.entries:
            new_key = _substitute(key, name, replacement) if key is not None else None
            new_val = _substitute(val, name, replacement)
            new_entries.append((new_key, new_val))
        return TableConstructor(entries=new_entries)
    return expr


def _stmt_refs(stmt: Stmt) -> Set[str]:
    """Collect all VarRef names used (read) by a statement."""
    refs: Set[str] = set()
    if isinstance(stmt, LocalDecl):
        for e in stmt.exprs:
            refs |= _collect_refs(e)
    elif isinstance(stmt, Assign):
        for t in stmt.targets:
            refs |= _collect_refs(t)
        for e in stmt.exprs:
            refs |= _collect_refs(e)
    elif isinstance(stmt, FunctionCallStmt):
        refs |= _collect_refs(stmt.call)
    elif isinstance(stmt, MethodCallStmt):
        refs |= _collect_refs(stmt.call)
    elif isinstance(stmt, ReturnStmt):
        for v in stmt.values:
            refs |= _collect_refs(v)
    return refs


def _substitute_in_stmt(stmt: Stmt, name: str, replacement: Expr) -> Stmt:
    """Replace all VarRef(name=name) in a statement with replacement."""
    if isinstance(stmt, LocalDecl):
        return LocalDecl(
            names=stmt.names,
            exprs=[_substitute(e, name, replacement) for e in stmt.exprs],
        )
    elif isinstance(stmt, Assign):
        return Assign(
            targets=[_substitute(t, name, replacement) for t in stmt.targets],
            exprs=[_substitute(e, name, replacement) for e in stmt.exprs],
        )
    elif isinstance(stmt, FunctionCallStmt):
        new_call = _substitute(stmt.call, name, replacement)
        if isinstance(new_call, FunctionCallExpr):
            return FunctionCallStmt(call=new_call)
        return stmt
    elif isinstance(stmt, MethodCallStmt):
        new_call = _substitute(stmt.call, name, replacement)
        if isinstance(new_call, MethodCallExpr):
            return MethodCallStmt(call=new_call)
        return stmt
    elif isinstance(stmt, ReturnStmt):
        return ReturnStmt(
            values=[_substitute(v, name, replacement) for v in stmt.values],
        )
    return stmt


def fold_expressions(stmts: List[Stmt], preserve: Optional[Set[str]] = None) -> List[Stmt]:
    """Inline single-use temporaries into their use sites.

    For each `local temp = expr` where `temp` is used exactly once in a
    subsequent statement, replace the use of `temp` with `expr` and remove
    the definition.

    This is safe because:
    - Bytecode instructions are emitted in evaluation order
    - Single-use means no aliasing
    - We only inline forward (def before use)
    """
    # Multi-pass: keep folding until no more changes
    changed = True
    while changed:
        changed = False

        # Count uses of each variable name across all statements
        use_counts: Dict[str, int] = defaultdict(int)
        for stmt in stmts:
            refs = _stmt_refs(stmt)
            for r in refs:
                use_counts[r] += 1

        # Build definition map: name -> (index, expr)
        # Only single-name LocalDecls with a single expression
        defs: Dict[str, Tuple[int, Expr]] = {}
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, LocalDecl) and len(stmt.names) == 1 and len(stmt.exprs) == 1:
                defs[stmt.names[0]] = (i, stmt.exprs[0])

        # Find candidates: definitions that are used exactly once
        to_remove: Set[int] = set()
        for vname, (def_idx, def_expr) in defs.items():
            if use_counts.get(vname, 0) != 1:
                continue

            if preserve and vname in preserve:
                continue

            # Find the statement that uses this variable
            for j in range(def_idx + 1, len(stmts)):
                use_stmt = stmts[j]
                if vname in _stmt_refs(use_stmt):
                    # Re-read the expr from the current statement since an
                    # earlier inline in this pass may have modified it.
                    current_def = stmts[def_idx]
                    if isinstance(current_def, LocalDecl) and len(current_def.exprs) == 1:
                        actual_expr = current_def.exprs[0]
                    else:
                        actual_expr = def_expr
                    stmts[j] = _substitute_in_stmt(use_stmt, vname, actual_expr)
                    to_remove.add(def_idx)
                    changed = True
                    break

        # Remove inlined definitions (in reverse order to preserve indices)
        if to_remove:
            stmts = [s for i, s in enumerate(stmts) if i not in to_remove]

    return stmts


def fold_reassignments(stmts: List[Stmt], debug_names: Set[str]) -> List[Stmt]:
    """Convert repeated LocalDecl for the same debug-named variable into Assign.

    SSA gives every write a new version, so the lifter emits LocalDecl for
    each one. When the variable has a debug name (meaning the source code
    declared it once), only the first occurrence should be `local x = ...`;
    subsequent writes become `x = ...`.
    """
    seen: Set[str] = set()
    result: List[Stmt] = []
    for stmt in stmts:
        if isinstance(stmt, LocalDecl) and len(stmt.names) == 1:
            vname = stmt.names[0]
            if vname in debug_names and vname in seen:
                result.append(Assign(
                    targets=[VarRef(name=vname, register=-1, ssa_version=-1)],
                    exprs=stmt.exprs,
                ))
                continue
            if vname in debug_names:
                seen.add(vname)
        result.append(stmt)
    return result


def negate_condition(cond: Expr) -> Expr:
    """Negate a condition expression, preferring operator flips over wrapping with `not`.

    For comparisons, flip the operator directly (e.g. `>` becomes `<=`).
    For `not x`, unwrap to `x`.
    For everything else, wrap with `not`.
    """
    _NEGATE_OP = {
        "<": ">=", "<=": ">", ">": "<=", ">=": "<",
        "==": "~=", "~=": "==",
    }
    if isinstance(cond, BinOp) and cond.op in _NEGATE_OP:
        return BinOp(op=_NEGATE_OP[cond.op], left=cond.left, right=cond.right)
    if isinstance(cond, UnOp) and cond.op == "not ":
        return cond.operand
    return UnOp(op="not ", operand=cond)


def fold_cond_expr(
    stmts: List[Stmt],
    cond: Expr,
    preserve: Optional[Set[str]] = None,
) -> Tuple[List[Stmt], Expr]:
    """Fold single-use temporaries from a condition block's body into the condition expression.

    Returns the pruned statement list and the updated condition.
    """
    cond_refs = _collect_refs(cond)

    # Count how many times each var is referenced across all stmts + the condition
    use_counts: Dict[str, int] = defaultdict(int)
    for r in cond_refs:
        use_counts[r] += 1
    for stmt in stmts:
        for r in _stmt_refs(stmt):
            use_counts[r] += 1

    to_remove: Set[int] = set()
    for i in range(len(stmts) - 1, -1, -1):
        stmt = stmts[i]
        if not isinstance(stmt, LocalDecl):
            continue
        if len(stmt.names) != 1 or len(stmt.exprs) != 1:
            continue
        vname = stmt.names[0]
        if preserve and vname in preserve:
            continue
        if use_counts.get(vname, 0) != 1:
            continue
        if vname not in cond_refs:
            continue
        cond = _substitute(cond, vname, stmt.exprs[0])
        cond_refs = _collect_refs(cond)
        to_remove.add(i)

    if to_remove:
        stmts = [s for i, s in enumerate(stmts) if i not in to_remove]

    # Normalize: if comparison has a literal on the left, flip it.
    # e.g. 2 < c  ->  c > 2
    _FLIP_OP = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}
    if isinstance(cond, BinOp) and cond.op in _FLIP_OP:
        if isinstance(cond.left, (NumberLit, StringLit, BoolLit, NilLit)):
            if not isinstance(cond.right, (NumberLit, StringLit, BoolLit, NilLit)):
                cond = BinOp(op=_FLIP_OP[cond.op], left=cond.right, right=cond.left)

    return stmts, cond


def _is_table_assign(stmt: Stmt, table_name: str) -> Optional[tuple]:
    """Check if stmt is an assignment to table_name[key] or table_name.field.

    Returns (key_expr_or_None, value_expr) if it matches, None otherwise.
    key_expr is None for sequential array entries.
    """
    if not isinstance(stmt, Assign):
        return None
    if len(stmt.targets) != 1 or len(stmt.exprs) != 1:
        return None

    target = stmt.targets[0]
    value = stmt.exprs[0]

    if isinstance(target, IndexExpr) and isinstance(target.table, VarRef):
        if target.table.name == table_name:
            return (target.key, value)

    if isinstance(target, FieldExpr) and isinstance(target.table, VarRef):
        if target.table.name == table_name:
            return (StringLit(value=target.field), value)

    return None


def fold_table_constructors(stmts: List[Stmt]) -> List[Stmt]:
    """Merge NEWTABLE/DUPTABLE + field assignments back into {} constructors.

    Scans for `local t = {}` followed by `t[k] = v` or `t.field = v`
    assignments and folds them into the table constructor literal.
    Sequential numeric keys starting from 1 become array entries.
    """
    result: List[Stmt] = []
    i = 0
    while i < len(stmts):
        stmt = stmts[i]

        if (isinstance(stmt, LocalDecl)
                and len(stmt.names) == 1
                and len(stmt.exprs) == 1
                and isinstance(stmt.exprs[0], TableConstructor)
                and not stmt.exprs[0].entries):

            table_name = stmt.names[0]
            tbl = stmt.exprs[0]
            entries: List[tuple] = []
            next_array_idx = 1
            j = i + 1

            while j < len(stmts):
                match = _is_table_assign(stmts[j], table_name)
                if match is None:
                    break
                key_expr, val_expr = match

                if isinstance(key_expr, NumberLit) and key_expr.value == next_array_idx:
                    entries.append((None, val_expr))
                    next_array_idx += 1
                else:
                    entries.append((key_expr, val_expr))
                j += 1

            if entries:
                tbl.entries = entries
            result.append(stmt)
            i = j
        else:
            result.append(stmt)
            i += 1

    return result


# ---------------------------------------------------------------------------
# Structure walker: emit structured Luau source
# ---------------------------------------------------------------------------

class SourceEmitter:
    """Walks the CFG in structured order and emits Luau source code."""

    def __init__(
        self,
        cfg: CFG,
        dtree: DominatorTree,
        structures: StructureInfo,
        ssa: SSAForm,
        lifter: InstructionLifter,
        proto: Dict[str, Any],
        luau_version: int,
        proto_table: Optional[List[Dict[str, Any]]] = None,
        string_table: Optional[List[str]] = None,
    ):
        self.cfg = cfg
        self.dtree = dtree
        self.structures = structures
        self.ssa = ssa
        self.lifter = lifter
        self.proto = proto
        self.luau_version = luau_version
        self.proto_table = proto_table or []
        self.string_table = string_table or []

        OP_TABLE = get_op_table(luau_version)
        self.opcode_to_name = {info.number: info.name for info in OP_TABLE}
        self.aux_opcodes = {info.name for info in OP_TABLE if info.get("aux", False)}
        self.code = proto["codeTable"]

        # Build lookup maps
        self._if_map: Dict[int, IfInfo] = {
            info.condition: info for info in structures.ifs
        }
        self._loop_map: Dict[int, LoopInfo] = {
            loop.header: loop for loop in structures.loops
        }

        # Pre-compute all blocks owned by a loop (non-header body blocks).
        # These must NOT be emitted as regular blocks in the region walker —
        # they're emitted only through their loop's handler.
        self._loop_body_blocks: Set[int] = set()
        for loop in structures.loops:
            for bid in loop.body:
                if bid != loop.header:
                    self._loop_body_blocks.add(bid)

        # Pre-compute FORNPREP/FORGPREP "setup" blocks for for-loops.
        # These are predecessor blocks that end with FORNPREP/FORGPREP and
        # should be absorbed into the for-loop emission, not emitted as
        # standalone blocks in the region walker.
        self._for_setup_blocks: Dict[int, int] = {}  # loop_header -> setup_block_id
        for loop in structures.loops:
            if loop.loop_type in (LoopType.FOR_NUMERIC, LoopType.FOR_GENERIC):
                header_block = cfg.get_block(loop.header)
                for pred_id in header_block.predecessors:
                    if pred_id in loop.body:
                        continue  # Skip back-edges from within the loop
                    pred_block = cfg.get_block(pred_id)
                    pred_inst = self.code[pred_block.end_pc]
                    pred_opc = get_opcode(pred_inst)
                    pred_name = self.opcode_to_name.get(pred_opc, "")
                    if pred_name in ("FORNPREP", "FORGPREP", "FORGPREP_INEXT", "FORGPREP_NEXT"):
                        self._for_setup_blocks[loop.header] = pred_id
                        self._loop_body_blocks.add(pred_id)  # Skip in region walker
                        break

        # Track which blocks have been emitted (avoid duplication)
        self._emitted: Set[int] = set()

    def emit(self) -> str:
        """Emit the complete decompiled source for this proto."""
        lines: List[str] = []

        # Function header
        params = self.lifter.names.get_param_names()
        if self.proto["isVarArg"]:
            params.append("...")
        lines.append(f"function({', '.join(params)})")

        # Emit body
        body_lines = self._emit_region(
            start_block=self.cfg.entry_id,
            end_block=None,
            exclude_blocks=set(),
            indent=1,
        )
        lines.extend(body_lines)

        if lines and lines[-1].strip() == "return":
            lines.pop()

        lines.append("end")
        return "\n".join(lines)

    def _indent(self, level: int) -> str:
        return "    " * level

    def _emit_region(
        self,
        start_block: int,
        end_block: Optional[int],
        exclude_blocks: Set[int],
        indent: int,
    ) -> List[str]:
        """Emit a region of blocks from start_block up to (not including) end_block."""
        lines: List[str] = []
        block_order = sorted(
            [b for b in self.cfg.blocks if b.id not in exclude_blocks],
            key=lambda b: b.start_pc
        )

        # Find the starting position
        start_idx = 0
        for i, b in enumerate(block_order):
            if b.id == start_block:
                start_idx = i
                break

        i = start_idx
        while i < len(block_order):
            block = block_order[i]

            if block.id in self._emitted:
                i += 1
                continue

            if end_block is not None and block.id == end_block:
                break

            if block.id in exclude_blocks:
                i += 1
                continue

            # Skip non-header loop body blocks — they're emitted by the loop handler
            if block.id in self._loop_body_blocks:
                i += 1
                continue

            # Check if this block is a loop header
            if block.id in self._loop_map:
                loop = self._loop_map[block.id]
                loop_lines = self._emit_loop(loop, indent)
                lines.extend(loop_lines)
                # Mark all blocks in the loop body as emitted
                self._emitted.update(loop.body)
                i += 1
                continue

            # Check if this block is an if condition
            if block.id in self._if_map:
                if_info = self._if_map[block.id]
                if_lines = self._emit_if(if_info, indent)
                lines.extend(if_lines)
                i += 1
                continue

            # Regular block — emit its instructions
            self._emitted.add(block.id)
            block_lines = self._emit_block_stmts(block, indent)
            lines.extend(block_lines)
            i += 1

        return lines

    def _collect_block_stmts(self, start_pc: int, end_pc: int) -> List[Stmt]:
        """Collect all lifted AST statements for a PC range (inclusive)."""
        stmts: List[Stmt] = []
        pc = start_pc
        while pc <= end_pc and pc < len(self.code):
            inst = self.code[pc]
            opc = get_opcode(inst)
            name = self.opcode_to_name.get(opc, "UNKNOWN")

            lifted = self.lifter.lift_instruction(pc)
            stmts.extend(lifted)

            if name in self.aux_opcodes and pc + 1 < len(self.code):
                pc += 2
            else:
                pc += 1
        return stmts

    def _emit_block_stmts(self, block: BasicBlock, indent: int) -> List[str]:
        """Emit all non-control-flow statements in a basic block."""
        stmts = self._collect_block_stmts(block.start_pc, block.end_pc)
        stmts = fold_expressions(stmts, self.lifter.names._debug_names)
        stmts = fold_table_constructors(stmts)
        stmts = fold_reassignments(stmts, self.lifter.names._debug_names)
        lines: List[str] = []
        for stmt in stmts:
            stmt_str = self._stmt_to_str(stmt, indent)
            if stmt_str:
                lines.append(stmt_str)
        return lines

    def _emit_loop(self, loop: LoopInfo, indent: int) -> List[str]:
        """Emit a loop structure."""
        ind = self._indent(indent)
        lines: List[str] = []

        if loop.loop_type == LoopType.WHILE:
            lines.extend(self._emit_while(loop, indent))
        elif loop.loop_type == LoopType.FOR_NUMERIC:
            lines.extend(self._emit_for_numeric(loop, indent))
        elif loop.loop_type == LoopType.FOR_GENERIC:
            lines.extend(self._emit_for_generic(loop, indent))
        elif loop.loop_type == LoopType.REPEAT_UNTIL:
            lines.extend(self._emit_repeat_until(loop, indent))

        return lines

    def _emit_while(self, loop: LoopInfo, indent: int) -> List[str]:
        """Emit a while loop."""
        ind = self._indent(indent)
        header = self.cfg.get_block(loop.header)

        # Get condition and fold temporaries into it
        cond_expr = self.lifter.lift_condition(header.end_pc)
        self._emitted.add(header.id)
        body_stmts = self._fold_block_body_stmts(header)
        body_stmts, cond_expr = fold_cond_expr(
            body_stmts, cond_expr, self.lifter.names._debug_names
        )
        cond_str = self._expr_to_str(cond_expr)

        lines = [f"{ind}while {cond_str} do"]

        # Emit remaining header body instructions
        for stmt in body_stmts:
            stmt_str = self._stmt_to_str(stmt, indent + 1)
            if stmt_str:
                lines.append(stmt_str)

        # Emit body blocks (excluding header and latch)
        body_blocks = sorted(loop.body - {loop.header})
        for bid in body_blocks:
            if bid in self._emitted:
                continue
            block = self.cfg.get_block(bid)
            self._emitted.add(bid)

            # Check for nested structures
            if bid in self._if_map:
                lines.extend(self._emit_if(self._if_map[bid], indent + 1))
            elif bid in self._loop_map:
                lines.extend(self._emit_loop(self._loop_map[bid], indent + 1))
            else:
                lines.extend(self._emit_block_stmts(block, indent + 1))

        lines.append(f"{ind}end")
        return lines

    def _emit_for_numeric(self, loop: LoopInfo, indent: int) -> List[str]:
        """Emit a numeric for loop.

        Luau numeric for layout:
          Setup block (FORNPREP):  R[A]=limit, R[A+1]=step, R[A+2]=init
          Header block (FORNLOOP): the self-loop that increments and checks

        We find the FORNPREP setup block (predecessor), extract A, and
        absorb the init/limit/step expressions into the for header.
        """
        ind = self._indent(indent)
        header = self.cfg.get_block(loop.header)
        lines: List[str] = []

        setup_bid = self._for_setup_blocks.get(loop.header)
        if setup_bid is not None:
            setup_block = self.cfg.get_block(setup_bid)
            setup_inst = self.code[setup_block.end_pc]
            A = get_arg_a(setup_inst)
            fornprep_pc = setup_block.end_pc
            self._emitted.add(setup_bid)
        else:
            inst = self.code[header.end_pc]
            A = get_arg_a(inst)
            fornprep_pc = header.end_pc

        # R[A] = limit, R[A+1] = step, R[A+2] = loop variable / init
        # Use the first body instruction PC for debug name lookup, since
        # the loop variable's debug range starts inside the body, not at
        # FORNPREP. Also bypass the name cache because the same register
        # can have different names across different for-loops.
        body_pc = header.start_pc
        var_name = self.lifter.names.debug_name_at(A + 2, body_pc)
        if var_name is None:
            var_name = self.lifter.names.get_name(A + 2, 0, fornprep_pc)
        limit_var = self.lifter._var(A, fornprep_pc).name
        step_var = self.lifter._var(A + 1, fornprep_pc).name
        init_var = self.lifter._var(A + 2, fornprep_pc).name

        # Default: use variable names (old behavior)
        init_str = init_var
        limit_str = limit_var
        step_str = step_var

        # Try to absorb the setup expressions into the for header
        if setup_bid is not None:
            setup_stmts = self._fold_block_body_stmts(setup_block)
            control_names = {limit_var, step_var, init_var}
            absorbed = set()

            # Map variable name -> its defining expression
            def_exprs: Dict[str, Expr] = {}
            for si, s in enumerate(setup_stmts):
                if isinstance(s, LocalDecl) and len(s.names) == 1 and s.names[0] in control_names:
                    if s.exprs:
                        def_exprs[s.names[0]] = s.exprs[0]
                        absorbed.add(si)

            if init_var in def_exprs:
                init_str = self._expr_to_str(def_exprs[init_var])
            if limit_var in def_exprs:
                limit_str = self._expr_to_str(def_exprs[limit_var])
            if step_var in def_exprs:
                step_str = self._expr_to_str(def_exprs[step_var])

            # Emit any remaining setup statements that weren't absorbed
            for si, s in enumerate(setup_stmts):
                if si not in absorbed:
                    stmt_str = self._stmt_to_str(s, indent)
                    if stmt_str:
                        lines.append(stmt_str)

        # Omit step if it's 1 (the default)
        if step_str == "1":
            lines.append(f"{ind}for {var_name} = {init_str}, {limit_str} do")
        else:
            lines.append(f"{ind}for {var_name} = {init_str}, {limit_str}, {step_str} do")

        self._emitted.add(header.id)

        header_body = self._emit_block_body_only(header, indent + 1)
        lines.extend(header_body)

        body_blocks = sorted(loop.body - {loop.header})
        for bid in body_blocks:
            if bid in self._emitted:
                continue
            block = self.cfg.get_block(bid)
            self._emitted.add(bid)

            if bid in self._if_map:
                lines.extend(self._emit_if(self._if_map[bid], indent + 1))
            elif bid in self._loop_map:
                lines.extend(self._emit_loop(self._loop_map[bid], indent + 1))
            else:
                lines.extend(self._emit_block_stmts(block, indent + 1))

        lines.append(f"{ind}end")
        return lines

    def _emit_for_generic(self, loop: LoopInfo, indent: int) -> List[str]:
        """Emit a generic for loop.

        Luau generic for layout:
          Setup block (FORGPREP):  R[A]=generator, R[A+1]=state, R[A+2]=control
          Header block (FORGLOOP): calls generator, assigns results to R[A+3..]
          Body blocks: the loop body using R[A+3..] as iteration variables

        We find the FORGPREP setup block and the FORGLOOP header to build
        the for header: `for <vars> in <iterator_call> do`
        """
        ind = self._indent(indent)
        lines: List[str] = []

        # Find FORGLOOP in the header to get A and aux (iteration var count)
        header = self.cfg.get_block(loop.header)
        header_inst = self.code[header.end_pc]
        header_opc = get_opcode(header_inst)
        header_name = self.opcode_to_name.get(header_opc, "")

        forgloop_pc = header.end_pc
        forgloop_A = get_arg_a(header_inst)
        forgloop_aux = self.code[forgloop_pc + 1] if forgloop_pc + 1 < len(self.code) else None

        # Build iteration variable names from R[A+3..A+3+nresults-1]
        # Use the first body block's start PC for debug name lookup. The
        # FORGLOOP PC sits at the endpc boundary of the debug range, so
        # the lookup would miss. The body start PC is inside the range.
        if forgloop_aux is not None:
            nresults = forgloop_aux & 0xFF
        else:
            nresults = 2  # Default: key, value

        body_blocks_sorted = sorted(loop.body - {loop.header})
        if body_blocks_sorted:
            body_pc = self.cfg.get_block(body_blocks_sorted[0]).start_pc
        else:
            body_pc = header.start_pc

        iter_vars = []
        for r in range(forgloop_A + 3, forgloop_A + 3 + nresults):
            dname = self.lifter.names.debug_name_at(r, body_pc)
            if dname is not None:
                iter_vars.append(dname)
            else:
                iter_vars.append(self.lifter.names.get_name(r, 0, forgloop_pc))

        # Find the FORGPREP setup block and absorb the iterator expression
        # into the for header instead of emitting it as separate statements.
        setup_bid = self._for_setup_blocks.get(loop.header)
        iter_expr_str = None

        if setup_bid is not None:
            setup_block = self.cfg.get_block(setup_bid)
            setup_stmts = self._fold_block_body_stmts(setup_block)
            self._emitted.add(setup_bid)

            # The iterator triple lives in R[A], R[A+1], R[A+2].
            # Get the variable name the lifter assigned to R[A].
            setup_pc = setup_block.end_pc
            gen_name = self.lifter._var(forgloop_A, setup_pc).name

            # Try to find the LocalDecl that defines the generator.
            # Case 1: multi-return call like `local gen, state, ctrl = pairs(t)`
            # Case 2: individual assignments like `local gen = next; local state = t; ...`
            absorbed = set()
            for si, s in enumerate(setup_stmts):
                if not isinstance(s, LocalDecl):
                    continue
                if gen_name in s.names:
                    if s.exprs and isinstance(s.exprs[0], FunctionCallExpr):
                        # Multi-return call (pairs, ipairs, etc.)
                        iter_expr_str = self._expr_to_str(s.exprs[0])
                        absorbed.add(si)
                    break

            if iter_expr_str is None:
                # Individual assignments: collect exprs for R[A], R[A+1], R[A+2]
                state_name = self.lifter._var(forgloop_A + 1, setup_pc).name
                ctrl_name = self.lifter._var(forgloop_A + 2, setup_pc).name
                triple_names = {gen_name, state_name, ctrl_name}
                iter_exprs = []
                for si, s in enumerate(setup_stmts):
                    if isinstance(s, LocalDecl) and len(s.names) == 1 and s.names[0] in triple_names:
                        if s.exprs:
                            iter_exprs.append(s.exprs[0])
                        absorbed.add(si)

                # Drop trailing nil literals
                while iter_exprs and isinstance(iter_exprs[-1], NilLit):
                    iter_exprs.pop()

                if iter_exprs:
                    iter_expr_str = ", ".join(self._expr_to_str(e) for e in iter_exprs)

            # Emit any remaining setup statements that weren't absorbed
            for si, s in enumerate(setup_stmts):
                if si not in absorbed:
                    stmt_str = self._stmt_to_str(s, indent)
                    if stmt_str:
                        lines.append(stmt_str)

        # Fallback: just use the generator variable name directly
        if iter_expr_str is None:
            setup_pc = self.cfg.get_block(setup_bid).end_pc if setup_bid is not None else forgloop_pc
            iter_expr_str = self.lifter._var(forgloop_A, setup_pc).name

        vars_str = ", ".join(iter_vars) if iter_vars else "k, v"
        lines.append(f"{ind}for {vars_str} in {iter_expr_str} do")

        # Mark header as emitted
        self._emitted.add(header.id)

        # Emit body blocks
        body_blocks = sorted(loop.body - {loop.header})
        for bid in body_blocks:
            if bid in self._emitted:
                continue
            block = self.cfg.get_block(bid)
            self._emitted.add(bid)

            if bid in self._if_map:
                lines.extend(self._emit_if(self._if_map[bid], indent + 1))
            elif bid in self._loop_map:
                lines.extend(self._emit_loop(self._loop_map[bid], indent + 1))
            else:
                lines.extend(self._emit_block_stmts(block, indent + 1))

        lines.append(f"{ind}end")
        return lines

    def _emit_repeat_until(self, loop: LoopInfo, indent: int) -> List[str]:
        """Emit a repeat-until loop."""
        ind = self._indent(indent)
        latch = self.cfg.get_block(loop.latch)
        header = self.cfg.get_block(loop.header)

        # lift_condition returns the fall-through (continue looping) condition.
        # For repeat-until we need the exit condition, so negate it.
        cond_expr = self.lifter.lift_condition(header.end_pc)
        cond_expr = negate_condition(cond_expr)
        self._emitted.add(header.id)
        body_stmts = self._fold_block_body_stmts(header)
        body_stmts, cond_expr = fold_cond_expr(
            body_stmts, cond_expr, self.lifter.names._debug_names
        )
        cond_str = self._expr_to_str(cond_expr)

        lines = [f"{ind}repeat"]

        # Emit header body (minus terminator)
        for stmt in body_stmts:
            stmt_str = self._stmt_to_str(stmt, indent + 1)
            if stmt_str:
                lines.append(stmt_str)

        # Emit other body blocks
        body_blocks = sorted(loop.body - {loop.header, loop.latch})
        for bid in body_blocks:
            if bid in self._emitted:
                continue
            block = self.cfg.get_block(bid)
            self._emitted.add(bid)
            lines.extend(self._emit_block_stmts(block, indent + 1))

        self._emitted.add(latch.id)

        lines.append(f"{ind}until {cond_str}")
        return lines

    def _emit_if(self, if_info: IfInfo, indent: int) -> List[str]:
        """Emit an if/elseif/else structure with full chain support.

        Handles arbitrary-depth elseif chains by walking the false_branch
        chain until we find a non-if block (the else) or no else at all.
        """
        ind = self._indent(indent)
        lines: List[str] = []

        # --- First 'if' ---
        cond_block = self.cfg.get_block(if_info.condition)
        cond_expr = self.lifter.lift_condition(cond_block.end_pc)

        # Get body stmts as AST, fold temporaries into the condition
        self._emitted.add(cond_block.id)
        body_stmts = self._fold_block_body_stmts(cond_block)
        body_stmts, cond_expr = fold_cond_expr(
            body_stmts, cond_expr, self.lifter.names._debug_names
        )
        cond_str = self._expr_to_str(cond_expr)

        for stmt in body_stmts:
            stmt_str = self._stmt_to_str(stmt, indent)
            if stmt_str:
                lines.append(stmt_str)

        lines.append(f"{ind}if {cond_str} then")

        # Emit true branch
        self._emit_if_branch(if_info.true_branch, lines, indent + 1)

        # --- Walk the elseif chain ---
        current = if_info
        while current.has_else() and current.false_branch is not None:
            fb = current.false_branch
            if fb in self._emitted:
                break

            # Is the false branch another if? -> elseif
            if fb in self._if_map:
                nested = self._if_map[fb]
                nested_cond_block = self.cfg.get_block(nested.condition)
                nested_cond = self.lifter.lift_condition(nested_cond_block.end_pc)

                self._emitted.add(nested.condition)
                nested_body = self._fold_block_body_stmts(nested_cond_block)
                nested_body, nested_cond = fold_cond_expr(
                    nested_body, nested_cond, self.lifter.names._debug_names
                )
                nested_cond_str = self._expr_to_str(nested_cond)

                for stmt in nested_body:
                    stmt_str = self._stmt_to_str(stmt, indent)
                    if stmt_str:
                        lines.append(stmt_str)

                lines.append(f"{ind}elseif {nested_cond_str} then")

                # Emit the elseif's true branch
                self._emit_if_branch(nested.true_branch, lines, indent + 1)

                # Continue the chain with the nested if's else
                current = nested
            else:
                # Plain else (not another if)
                lines.append(f"{ind}else")
                self._emitted.add(fb)
                fb_block = self.cfg.get_block(fb)
                lines.extend(self._emit_block_stmts(fb_block, indent + 1))
                break

        lines.append(f"{ind}end")
        return lines

    def _emit_if_branch(self, branch_id: Optional[int], lines: List[str], indent: int) -> None:
        """Emit a single branch (then/else) of an if statement."""
        if branch_id is None or branch_id in self._emitted:
            return
        self._emitted.add(branch_id)
        block = self.cfg.get_block(branch_id)

        if branch_id in self._if_map:
            lines.extend(self._emit_if(self._if_map[branch_id], indent))
        elif branch_id in self._loop_map:
            lines.extend(self._emit_loop(self._loop_map[branch_id], indent))
        else:
            lines.extend(self._emit_block_stmts(block, indent))

    def _fold_block_body_stmts(self, block: BasicBlock) -> List[Stmt]:
        """Get folded AST statements for a block body (minus terminator).

        Same logic as _emit_block_body_only but returns Stmt nodes
        instead of formatted strings.
        """
        last_inst = self.code[block.end_pc]
        last_opc = get_opcode(last_inst)
        last_name = self.opcode_to_name.get(last_opc, "")

        skip_terminator = last_name in CONDITIONAL_JUMPS or last_name in (
            "JUMP", "JUMPBACK", "JUMPX", "FORNPREP", "FORNLOOP",
            "FORGPREP", "FORGPREP_INEXT", "FORGPREP_NEXT", "FORGLOOP",
        )

        end_pc = block.end_pc
        if skip_terminator:
            end_pc = block.end_pc - 1

        stmts = self._collect_block_stmts(block.start_pc, end_pc)
        stmts = fold_expressions(stmts, self.lifter.names._debug_names)
        stmts = fold_table_constructors(stmts)
        stmts = fold_reassignments(stmts, self.lifter.names._debug_names)
        return stmts

    def _emit_block_body_only(self, block: BasicBlock, indent: int) -> List[str]:
        """Emit non-terminator instructions of a block.

        Skips the last instruction if it's a jump/branch (handled by structure).
        """
        stmts = self._fold_block_body_stmts(block)
        lines: List[str] = []
        for stmt in stmts:
            stmt_str = self._stmt_to_str(stmt, indent)
            if stmt_str:
                lines.append(stmt_str)
        return lines

    # --- AST to string conversion ---

    def _expr_to_str(self, expr: Expr) -> str:
        """Convert an expression to Luau source string."""
        if isinstance(expr, NumberLit):
            v = expr.value
            if v == int(v) and abs(v) < 2**53:
                return str(int(v))
            return str(v)

        elif isinstance(expr, StringLit):
            return repr(expr.value)

        elif isinstance(expr, BoolLit):
            return "true" if expr.value else "false"

        elif isinstance(expr, NilLit):
            return "nil"

        elif isinstance(expr, VarargLit):
            return "..."

        elif isinstance(expr, VarRef):
            return expr.name

        elif isinstance(expr, UpvalueRef):
            return expr.name

        elif isinstance(expr, GlobalRef):
            return expr.name

        elif isinstance(expr, IndexExpr):
            table_str = self._expr_to_str(expr.table)
            key_str = self._expr_to_str(expr.key)
            return f"{table_str}[{key_str}]"

        elif isinstance(expr, FieldExpr):
            table_str = self._expr_to_str(expr.table)
            return f"{table_str}.{expr.field}"

        elif isinstance(expr, BinOp):
            left_str = self._expr_to_str(expr.left)
            right_str = self._expr_to_str(expr.right)
            # Add parens for precedence clarity in nested expressions
            if isinstance(expr.left, BinOp):
                left_str = f"({left_str})"
            if isinstance(expr.right, BinOp):
                right_str = f"({right_str})"
            return f"{left_str} {expr.op} {right_str}"

        elif isinstance(expr, UnOp):
            operand_str = self._expr_to_str(expr.operand)
            if expr.op == "#" or expr.op == "-":
                return f"{expr.op}{operand_str}"
            return f"{expr.op}{operand_str}"

        elif isinstance(expr, ConcatExpr):
            parts = [self._expr_to_str(p) for p in expr.parts]
            return " .. ".join(parts)

        elif isinstance(expr, FunctionCallExpr):
            func_str = self._expr_to_str(expr.func)
            args_str = ", ".join(self._expr_to_str(a) for a in expr.args)
            return f"{func_str}({args_str})"

        elif isinstance(expr, MethodCallExpr):
            obj_str = self._expr_to_str(expr.obj)
            args_str = ", ".join(self._expr_to_str(a) for a in expr.args)
            return f"{obj_str}:{expr.method}({args_str})"

        elif isinstance(expr, TableConstructor):
            if not expr.entries:
                return "{}"
            parts = []
            for key, val in expr.entries:
                val_str = self._expr_to_str(val)
                if key is None:
                    parts.append(val_str)
                elif isinstance(key, StringLit):
                    parts.append(f"{key.value} = {val_str}")
                else:
                    parts.append(f"[{self._expr_to_str(key)}] = {val_str}")
            return "{ " + ", ".join(parts) + " }"

        elif isinstance(expr, ClosureExpr):
            if expr.source:
                return expr.source
            # Resolve child proto via pTable and recursively decompile
            p_table = self.proto.get("pTable", [])
            if self.proto_table and expr.proto_index < len(p_table):
                child_idx = p_table[expr.proto_index]
                if child_idx < len(self.proto_table):
                    child_proto = self.proto_table[child_idx]
                    child_src = decompile_proto(
                        child_proto,
                        self.luau_version,
                        self.string_table,
                        self.proto_table,
                        depth=1,
                    )
                    return child_src
            return f"function() --[[ proto {expr.proto_index} ]] end"

        elif isinstance(expr, FunctionExpr):
            params_str = ", ".join(expr.params)
            if expr.is_vararg:
                params_str += (", " if expr.params else "") + "..."
            return f"function({params_str}) --[[ body ]] end"

        return str(expr)

    def _reindent(self, text: str, indent: int) -> str:
        """Re-indent a multi-line string (from a child proto) to match parent context.

        The child source comes back indented from column 0, e.g.:
            function(a, b)
                return a + b
            end
        We prepend the parent indent to each line after the first, preserving
        the child's own relative indentation.
        """
        lines = text.split("\n")
        if len(lines) <= 1:
            return text
        ind = self._indent(indent)
        result = [lines[0]]
        for line in lines[1:]:
            if line.strip():
                result.append(f"{ind}{line}")
            else:
                result.append("")
        return "\n".join(result)

    def _stmt_to_str(self, stmt: Stmt, indent: int) -> str:
        """Convert a statement to an indented Luau source string."""
        ind = self._indent(indent)

        if isinstance(stmt, LocalDecl):
            names_str = ", ".join(stmt.names)
            if stmt.exprs:
                exprs_str = ", ".join(self._expr_to_str(e) for e in stmt.exprs)
                result = f"{ind}local {names_str} = {exprs_str}"
                if "\n" in result:
                    return self._reindent(result, indent)
                return result
            return f"{ind}local {names_str}"

        elif isinstance(stmt, Assign):
            targets_str = ", ".join(self._expr_to_str(t) for t in stmt.targets)
            exprs_str = ", ".join(self._expr_to_str(e) for e in stmt.exprs)
            result = f"{ind}{targets_str} = {exprs_str}"
            if "\n" in result:
                return self._reindent(result, indent)
            return result

        elif isinstance(stmt, FunctionCallStmt):
            return f"{ind}{self._expr_to_str(stmt.call)}"

        elif isinstance(stmt, MethodCallStmt):
            return f"{ind}{self._expr_to_str(stmt.call)}"

        elif isinstance(stmt, ReturnStmt):
            if stmt.values:
                vals_str = ", ".join(self._expr_to_str(v) for v in stmt.values)
                return f"{ind}return {vals_str}"
            return f"{ind}return"

        elif isinstance(stmt, BreakStmt):
            return f"{ind}break"

        elif isinstance(stmt, ContinueStmt):
            return f"{ind}continue"

        elif isinstance(stmt, CommentStmt):
            return f"{ind}-- {stmt.text}"

        elif isinstance(stmt, WhileStmt):
            cond_str = self._expr_to_str(stmt.condition)
            lines = [f"{ind}while {cond_str} do"]
            for s in stmt.body.stmts:
                lines.append(self._stmt_to_str(s, indent + 1))
            lines.append(f"{ind}end")
            return "\n".join(lines)

        return ""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def decompile_proto(
    proto: Dict[str, Any],
    luau_version: int,
    string_table: List[str],
    proto_table: List[Dict[str, Any]],
    depth: int = 0,
) -> str:
    """Decompile a single proto into Luau source code.

    This is the main decompilation entry point. It runs the full pipeline:
      CFG -> dominators -> structures -> SSA -> lift -> emit

    Args:
        proto: Deserialized proto dict.
        luau_version: Bytecode version (5 or 6).
        string_table: Global string table.
        proto_table: All protos (for child closure resolution).
        depth: Nesting depth (for child protos).

    Returns:
        Decompiled Luau source string.
    """
    from koralys.cfg import build_cfg
    from koralys.dominator import build_dominator_tree

    # Empty proto
    if not proto.get("codeTable"):
        return "function()\nend"

    # Build analysis
    cfg = build_cfg(proto, luau_version)
    dtree = build_dominator_tree(cfg)
    structures = identify_structures(cfg, dtree, proto, luau_version)
    ssa = build_ssa(cfg, dtree, proto, luau_version)

    # Build name resolver and instruction lifter
    names = NameResolver(proto, ssa)
    lifter = InstructionLifter(proto, luau_version, ssa, names, string_table)

    # Build source emitter
    emitter = SourceEmitter(
        cfg, dtree, structures, ssa, lifter, proto, luau_version,
        proto_table=proto_table, string_table=string_table,
    )

    return emitter.emit()


def decompile_all(
    main_proto: Dict[str, Any],
    proto_table: List[Dict[str, Any]],
    string_table: List[str],
    luau_version: int,
) -> str:
    """Decompile all protos into a complete Luau source file.

    The main proto is the top-level script. In Luau bytecode, child protos
    appear first in the proto table and the main proto is last.
    We decompile starting from main_proto; child protos are resolved on
    demand when NEWCLOSURE/DUPCLOSURE references them via pTable indices.
    """
    lines: List[str] = []
    lines.append(f"-- Decompiled by Koralys, a WIP Luau decompiler made by focat69 and jiface")
    lines.append(f"-- Luau bytecode version {luau_version}")
    lines.append("")

    # Decompile main proto (the top-level script)
    main_source = decompile_proto(
        main_proto, luau_version, string_table, proto_table, depth=0
    )
    lines.append(main_source)

    return "\n".join(lines)
