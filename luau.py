"""
Useful utility functions, and constants (e.g. the operation table, getting opcodes, other stuff) for Luau.
"""

class BytecodeOp:
    name: str
    type: str
    number: int
    aux: bool

    def __init__(self, name: str, type: str, number: int, aux: bool = False):
        self.name = name
        self.type = type
        self.number = number
        self.aux = aux

    def __getitem__(self, key: str):
        print(key)
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def get(self, key, default = None):
        try:
            return getattr(self, key)
        except AttributeError:
            return default


def get_op_table(bytecode_version: int) -> list[BytecodeOp]:
    return OP_TABLE_VERSION_MAP[bytecode_version]


OP_TABLE_V5 = [
    BytecodeOp("NOP", "none", 0x00),
    BytecodeOp("BREAK", "none", 0xE3),
    BytecodeOp("LOADNIL", "iA", 0xC6),
    BytecodeOp("LOADB", "iABC", 0xA9),
    BytecodeOp("LOADN", "iABx", 0x8C),
    BytecodeOp("LOADK", "iABx", 0x6F),
    BytecodeOp("MOVE", "iAB", 0x52),
    BytecodeOp("GETGLOBAL", "iAC", 0x35, True),
    BytecodeOp("SETGLOBAL", "iAC", 0x18, True),
    BytecodeOp("GETUPVAL", "iAB", 0xFB),
    BytecodeOp("SETUPVAL", "iAB", 0xDE),
    BytecodeOp("CLOSEUPVALS", "iA", 0xC1),
    BytecodeOp("GETIMPORT", "iABx", 0xA4, True),
    BytecodeOp("GETTABLE", "iABC", 0x87),
    BytecodeOp("SETTABLE", "iABC", 0x6A),
    BytecodeOp("GETTABLEKS", "iABC", 0x4D, True),
    BytecodeOp("SETTABLEKS", "iABC", 0x30, True),
    BytecodeOp("GETTABLEN", "iABC", 0x13),
    BytecodeOp("SETTABLEN", "iABC", 0xF6),
    BytecodeOp("NEWCLOSURE", "iABx", 0xD9),
    BytecodeOp("NAMECALL", "iABC", 0xBC, True),
    BytecodeOp("CALL", "iABC", 0x9F),
    BytecodeOp("RETURN", "iAB", 0x82),
    BytecodeOp("JUMP", "isBx", 0x65),
    BytecodeOp("JUMPBACK", "isBx", 0x48),
    BytecodeOp("JUMPIF", "iAsBx", 0x2B),
    BytecodeOp("JUMPIFNOT", "iAsBx", 0x0E),
    BytecodeOp("JUMPIFEQ", "iAsBx", 0xF1, True),
    BytecodeOp("JUMPIFLE", "iAsBx", 0xD4, True),
    BytecodeOp("JUMPIFLT", "iAsBx", 0xB7, True),
    BytecodeOp("JUMPIFNOTEQ", "iAsBx", 0x9A, True),
    BytecodeOp("JUMPIFNOTLE", "iAsBx", 0x7D, True),
    BytecodeOp("JUMPIFNOTLT", "iAsBx", 0x60, True),
    BytecodeOp("ADD", "iABC", 0x43),
    BytecodeOp("SUB", "iABC", 0x26),
    BytecodeOp("MUL", "iABC", 0x09),
    BytecodeOp("DIV", "iABC", 0xEC),
    BytecodeOp("MOD", "iABC", 0xCF),
    BytecodeOp("POW", "iABC", 0xB2),
    BytecodeOp("ADDK", "iABC", 0x95),
    BytecodeOp("SUBK", "iABC", 0x78),
    BytecodeOp("MULK", "iABC", 0x5B),
    BytecodeOp("DIVK", "iABC", 0x3E),
    BytecodeOp("MODK", "iABC", 0x21),
    BytecodeOp("POWK", "iABC", 0x04),
    BytecodeOp("AND", "iABC", 0xE7),
    BytecodeOp("OR", "iABC", 0xCA),
    BytecodeOp("ANDK", "iABC", 0xAD),
    BytecodeOp("ORK", "iABC", 0x90),
    BytecodeOp("CONCAT", "iABC", 0x73),
    BytecodeOp("NOT", "iAB", 0x56),
    BytecodeOp("MINUS", "iAB", 0x39),
    BytecodeOp("LENGTH", "iAB", 0x1C),
    BytecodeOp("NEWTABLE", "iAB", 0xFF, True),
    BytecodeOp("DUPTABLE", "iABx", 0xE2),
    BytecodeOp("SETLIST", "iABC", 0xC5, True),
    BytecodeOp("FORNPREP", "iABx", 0xA8),
    BytecodeOp("FORNLOOP", "iABx", 0x8B),
    BytecodeOp("FORGLOOP", "iABx", 0x6E, True),
    BytecodeOp("FORGPREP_INEXT", "none", 0x51),
    BytecodeOp("DEP_FORGLOOP_INEXT", "none", 0x34),
    BytecodeOp("FORGPREP_NEXT", "none", 0x17),
    BytecodeOp("NATIVECALL", "none", 0xFA),
    BytecodeOp("GETVARARGS", "iAB", 0xDD),
    BytecodeOp("DUPCLOSURE", "iABx", 0xC0),
    BytecodeOp("PREPVARARGS", "iA", 0xA3),
    BytecodeOp("LOADKX", "iA", 0x86),
    BytecodeOp("JUMPX", "isAx", 0x69),
    BytecodeOp("FASTCALL", "iAC", 0x4C),
    BytecodeOp("COVERAGE", "isAx", 0x2F),
    BytecodeOp("CAPTURE", "iAB", 0x12),
    BytecodeOp("SUBRK", "iABx", 0xF5, True),
    BytecodeOp("DIVRK", "iABx", 0xD8, True),
    BytecodeOp("FASTCALL1", "iABC", 0xBB),
    BytecodeOp("FASTCALL2", "iABC", 0x9E, True),
    BytecodeOp("FASTCALL2K", "iABC", 0x81, True),
    BytecodeOp("FORGPREP", "iAB", 0x64),
    BytecodeOp("JUMPXEQKNIL", "iAsBx", 0x47, True),
    BytecodeOp("JUMPXEQKB", "iAsBx", 0x2A, True),
    BytecodeOp("JUMPXEQKN", "iAsBx", 0x0D, True),
    BytecodeOp("JUMPXEQKS", "iAsBx", 0xF0, True),
    BytecodeOp("IDIV", "iABC", 0xD3),
    BytecodeOp("IDIVK", "iABC", 0xB6),
    BytecodeOp("COUNT", "none", 0x99),
]

# notes:
# 1. v6 added FASTCALL3.
# 2. v6 removed DEP_FORGLOOP_INEXT
# also, this probably should be a different table.
OP_TABLE_V6 = OP_TABLE_V5 + [
    BytecodeOp("FASTCALL3", "iABC", 0x34, True),
]
index = next(
    i for i, op in enumerate(OP_TABLE_V6) if op["name"] == "DEP_FORGLOOP_INEXT"
)
OP_TABLE_V6.pop(index)


OP_TABLE_VERSION_MAP = {6: OP_TABLE_V6, 5: OP_TABLE_V5}


def get_opcode(i: int) -> int:
    return (i * 227) & 0xFF


def get_arg_a(i: int) -> int:
    return (i >> 8) & 0xFF


def get_arg_b(i: int) -> int:
    return (i >> 16) & 0xFF


def get_arg_c(i: int) -> int:
    return (i >> 24) & 0xFF


# def GETARG_D(i: int) -> int:
#     d = (i >> 16) & 0xFFFF  # Extract 16 bits for D
#     return d - 0x10000 if d & 0x8000 else d  # Convert to signed


def get_arg_Bx(i: int) -> int:
    return i >> 16


def get_arg_sBx(i: int) -> int:
    return (i >> 16) - 131071


def get_arg_sAx(i: int) -> int:
    return i >> 8
