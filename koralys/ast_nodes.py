"""AST node definitions for decompiled Luau source.

These nodes represent the high-level Luau constructs that the lifter
produces from the CFG + structures + SSA analysis. The source emitter
walks this tree to produce readable Luau code.

Node hierarchy:
  Statement (base)
    LocalDecl        local x = expr
    Assign           x = expr
    FunctionCallStmt f(args)
    MethodCallStmt   obj:method(args)
    ReturnStmt       return exprs
    WhileStmt        while cond do ... end
    RepeatUntilStmt  repeat ... until cond
    NumericForStmt   for i = start, limit, step do ... end
    GenericForStmt   for k, v in iter do ... end
    IfStmt           if cond then ... elseif ... else ... end
    BreakStmt        break
    ContinueStmt     continue
    Block            sequence of statements

  Expression (base)
    NumberLit        42, 3.14
    StringLit        "hello"
    BoolLit          true, false
    NilLit           nil
    VarargLit        ...
    VarRef           local variable reference (register-based or named)
    UpvalueRef       upvalue reference
    GlobalRef        global variable reference
    IndexExpr        table[key]
    FieldExpr        table.field
    BinOp            a + b, a == b, etc.
    UnOp             -a, not a, #a
    ConcatExpr       a .. b .. c
    FunctionCallExpr f(args)
    MethodCallExpr   obj:method(args)
    TableConstructor { ... }
    FunctionExpr     function(...) ... end
    ClosureExpr      placeholder for child proto
"""

from dataclasses import dataclass, field
from typing import List, Optional, Any


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------

class Expr:
    """Base class for all expressions."""
    pass


@dataclass
class NumberLit(Expr):
    value: float

    def __repr__(self):
        if self.value == int(self.value) and not (self.value == 0 and str(self.value).startswith("-")):
            return str(int(self.value))
        return str(self.value)


@dataclass
class StringLit(Expr):
    value: str

    def __repr__(self):
        return repr(self.value)


@dataclass
class BoolLit(Expr):
    value: bool

    def __repr__(self):
        return "true" if self.value else "false"


@dataclass
class NilLit(Expr):
    def __repr__(self):
        return "nil"


@dataclass
class VarargLit(Expr):
    def __repr__(self):
        return "..."


@dataclass
class VarRef(Expr):
    """Reference to a local variable (register)."""
    name: str  # Either debug name or "v{N}"
    register: int = -1  # Original register number (-1 if not register-based)
    ssa_version: int = -1  # SSA version (-1 if not tracked)


@dataclass
class UpvalueRef(Expr):
    """Reference to an upvalue."""
    name: str
    index: int


@dataclass
class GlobalRef(Expr):
    """Reference to a global variable."""
    name: str


@dataclass
class IndexExpr(Expr):
    """table[key] — dynamic index."""
    table: Expr
    key: Expr


@dataclass
class FieldExpr(Expr):
    """table.field — string key known at compile time."""
    table: Expr
    field: str


@dataclass
class BinOp(Expr):
    """Binary operation: left op right."""
    op: str  # "+", "-", "*", "/", "//", "%", "^", "==", "~=", "<", "<=", ">", ">=", "and", "or", ".."
    left: Expr
    right: Expr


@dataclass
class UnOp(Expr):
    """Unary operation: op operand."""
    op: str  # "-", "not", "#"
    operand: Expr


@dataclass
class ConcatExpr(Expr):
    """String concatenation: a .. b .. c."""
    parts: List[Expr]


@dataclass
class FunctionCallExpr(Expr):
    """Function call expression: f(args)."""
    func: Expr
    args: List[Expr]
    is_vararg_return: bool = False  # True if this call returns multiple values


@dataclass
class MethodCallExpr(Expr):
    """Method call expression: obj:method(args)."""
    obj: Expr
    method: str
    args: List[Expr]
    is_vararg_return: bool = False


@dataclass
class TableConstructor(Expr):
    """Table constructor: { field1 = val1, val2, [expr] = val3 }."""
    # Each entry is (key_or_none, value) — None key means array part
    entries: List[tuple]  # List of (Optional[Expr], Expr)


@dataclass
class FunctionExpr(Expr):
    """Function expression (anonymous or named closure)."""
    params: List[str]
    is_vararg: bool
    body: Any  # Block (forward ref)
    name: Optional[str] = None  # Debug name if available


@dataclass
class ClosureExpr(Expr):
    """Placeholder for a child proto closure — resolved during emission."""
    proto_index: int
    source: Optional[str] = None  # Decompiled source of the child proto
    upvalue_names: Optional[List[str]] = None  # Inferred from parent CAPTURE instructions


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------

class Stmt:
    """Base class for all statements."""
    pass


@dataclass
class Block(Stmt):
    """A sequence of statements."""
    stmts: List[Stmt] = field(default_factory=list)


@dataclass
class LocalDecl(Stmt):
    """local name = expr (or local name1, name2 = expr1, expr2)."""
    names: List[str]
    exprs: List[Expr]  # May be empty (just declaration) or fewer than names


@dataclass
class Assign(Stmt):
    """Assignment: target = expr (or target1, target2 = expr1, expr2)."""
    targets: List[Expr]  # VarRef, IndexExpr, FieldExpr, GlobalRef, UpvalueRef
    exprs: List[Expr]


@dataclass
class FunctionCallStmt(Stmt):
    """Standalone function call statement."""
    call: FunctionCallExpr


@dataclass
class MethodCallStmt(Stmt):
    """Standalone method call statement."""
    call: MethodCallExpr


@dataclass
class ReturnStmt(Stmt):
    """return expr1, expr2, ..."""
    values: List[Expr]


@dataclass
class WhileStmt(Stmt):
    """while cond do body end."""
    condition: Expr
    body: Block


@dataclass
class RepeatUntilStmt(Stmt):
    """repeat body until cond."""
    body: Block
    condition: Expr


@dataclass
class NumericForStmt(Stmt):
    """for var = start, limit[, step] do body end."""
    var_name: str
    start: Expr
    limit: Expr
    step: Optional[Expr]  # None if default step of 1
    body: Block


@dataclass
class GenericForStmt(Stmt):
    """for var1, var2, ... in iter_func, state, control do body end."""
    var_names: List[str]
    iterators: List[Expr]  # The expressions after 'in'
    body: Block


@dataclass
class IfStmt(Stmt):
    """if cond then body [elseif cond then body]* [else body] end."""
    # List of (condition, body) pairs. First is the 'if', rest are 'elseif'.
    branches: List[tuple]  # List of (Expr, Block)
    else_body: Optional[Block] = None


@dataclass
class BreakStmt(Stmt):
    pass


@dataclass
class ContinueStmt(Stmt):
    pass


@dataclass
class CommentStmt(Stmt):
    """A comment in the output (for debugging/annotation)."""
    text: str
