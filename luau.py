"""
Useful utility functions, and constants (e.g. the operation table, getting opcodes, other stuff) for Luau.
"""

from typing import Optional

class BytecodeOpTable:
    name: str
    type: str
    case: int
    number: int
    aux: Optional[bool]

def get_op_table(bytecode_version: int) -> list[dict[str, BytecodeOpTable]]:
	return OP_TABLE_VERSION_MAP[bytecode_version]

OP_TABLE_V5 = [
    {"name": "NOP", "type": "none", "number": 0x00},
    {"name": "BREAK", "type": "none", "number": 0xE3},
    {"name": "LOADNIL", "type": "iA", "number": 0xC6},
    {"name": "LOADB", "type": "iABC", "number": 0xA9},
    {"name": "LOADN", "type": "iABx", "number": 0x8C},
    {"name": "LOADK", "type": "iABx", "number": 0x6F},
    {"name": "MOVE", "type": "iAB", "number": 0x52},
    {"name": "GETGLOBAL", "type": "iAC", "number": 0x35, "aux": True},
    {"name": "SETGLOBAL", "type": "iAC", "number": 0x18, "aux": True},
    {"name": "GETUPVAL", "type": "iAB", "number": 0xFB},
    {"name": "SETUPVAL", "type": "iAB", "number": 0xDE},
    {"name": "CLOSEUPVALS", "type": "iA", "number": 0xC1},
    {"name": "GETIMPORT", "type": "iABx", "number": 0xA4, "aux": True},
    {"name": "GETTABLE", "type": "iABC", "number": 0x87},
    {"name": "SETTABLE", "type": "iABC", "number": 0x6A},
    {"name": "GETTABLEKS", "type": "iABC", "number": 0x4D, "aux": True},
    {"name": "SETTABLEKS", "type": "iABC", "number": 0x30, "aux": True},
    {"name": "GETTABLEN", "type": "iABC", "number": 0x13},
    {"name": "SETTABLEN", "type": "iABC", "number": 0xF6},
    {"name": "NEWCLOSURE", "type": "iABx", "number": 0xD9},
    {"name": "NAMECALL", "type": "iABC", "number": 0xBC, "aux": True},
    {"name": "CALL", "type": "iABC", "number": 0x9F},
    {"name": "RETURN", "type": "iAB", "number": 0x82},
    {"name": "JUMP", "type": "isBx", "number": 0x65},
    {"name": "JUMPBACK", "type": "isBx", "number": 0x48},
    {"name": "JUMPIF", "type": "iAsBx", "number": 0x2B},
    {"name": "JUMPIFNOT", "type": "iAsBx", "number": 0x0E},
    {"name": "JUMPIFEQ", "type": "iAsBx", "number": 0xF1, "aux": True},
    {"name": "JUMPIFLE", "type": "iAsBx", "number": 0xD4, "aux": True},
    {"name": "JUMPIFLT", "type": "iAsBx", "number": 0xB7, "aux": True},
    {
        "name": "JUMPIFNOTEQ",
        "type": "iAsBx",
        "number": 0x9A,
        "aux": True,
    },
    {
        "name": "JUMPIFNOTLE",
        "type": "iAsBx",
        "number": 0x7D,
        "aux": True,
    },
    {
        "name": "JUMPIFNOTLT",
        "type": "iAsBx",
        "number": 0x60,
        "aux": True,
    },
    {"name": "ADD", "type": "iABC", "number": 0x43},
    {"name": "SUB", "type": "iABC", "number": 0x26},
    {"name": "MUL", "type": "iABC", "number": 0x09},
    {"name": "DIV", "type": "iABC", "number": 0xEC},
    {"name": "MOD", "type": "iABC", "number": 0xCF},
    {"name": "POW", "type": "iABC", "number": 0xB2},
    {"name": "ADDK", "type": "iABC", "number": 0x95},
    {"name": "SUBK", "type": "iABC", "number": 0x78},
    {"name": "MULK", "type": "iABC", "number": 0x5B},
    {"name": "DIVK", "type": "iABC", "number": 0x3E},
    {"name": "MODK", "type": "iABC", "number": 0x21},
    {"name": "POWK", "type": "iABC", "number": 0x04},
    {"name": "AND", "type": "iABC", "number": 0xE7},
    {"name": "OR", "type": "iABC", "number": 0xCA},
    {"name": "ANDK", "type": "iABC", "number": 0xAD},
    {"name": "ORK", "type": "iABC", "number": 0x90},
    {"name": "CONCAT", "type": "iABC", "number": 0x73},
    {"name": "NOT", "type": "iAB", "number": 0x56},
    {"name": "MINUS", "type": "iAB", "number": 0x39},
    {"name": "LENGTH", "type": "iAB", "number": 0x1C},
    {"name": "NEWTABLE", "type": "iAB", "number": 0xFF, "aux": True},
    {"name": "DUPTABLE", "type": "iABx", "number": 0xE2},
    {"name": "SETLIST", "type": "iABC", "number": 0xC5, "aux": True},
    {"name": "FORNPREP", "type": "iABx", "number": 0xA8},
    {"name": "FORNLOOP", "type": "iABx", "number": 0x8B},
    {"name": "FORGLOOP", "type": "iABx", "number": 0x6E, "aux": True},
    {"name": "FORGPREP_INEXT", "type": "none", "number": 0x51},
    {"name": "DEP_FORGLOOP_INEXT", "type": "none", "number": 0x34},
    {"name": "FORGPREP_NEXT", "type": "none", "number": 0x17},
    {"name": "NATIVECALL", "type": "none", "number": 0xFA},
    {"name": "GETVARARGS", "type": "iAB", "number": 0xDD},
    {"name": "DUPCLOSURE", "type": "iABx", "number": 0xC0},
    {"name": "PREPVARARGS", "type": "iA", "number": 0xA3},
    {"name": "LOADKX", "type": "iA", "number": 0x86},
    {"name": "JUMPX", "type": "isAx", "number": 0x69},
    {"name": "FASTCALL", "type": "iAC", "number": 0x4C},
    {"name": "COVERAGE", "type": "isAx", "number": 0x2F},
    {"name": "CAPTURE", "type": "iAB", "number": 0x12},
    {"name": "SUBRK", "type": "iABx", "number": 0xF5, "aux": True},
    {"name": "DIVRK", "type": "iABx", "number": 0xD8, "aux": True},
    {"name": "FASTCALL1", "type": "iABC", "number": 0xBB},
    {"name": "FASTCALL2", "type": "iABC", "number": 0x9E, "aux": True},
    {"name": "FASTCALL2K", "type": "iABC", "number": 0x81, "aux": True},
    {"name": "FORGPREP", "type": "iAB", "number": 0x64},
    {
        "name": "JUMPXEQKNIL",
        "type": "iAsBx",
        "number": 0x47,
        "aux": True,
    },
    {"name": "JUMPXEQKB", "type": "iAsBx", "number": 0x2A, "aux": True},
    {"name": "JUMPXEQKN", "type": "iAsBx", "number": 0x0D, "aux": True},
    {"name": "JUMPXEQKS", "type": "iAsBx", "number": 0xF0, "aux": True},
    {"name": "IDIV", "type": "iABC", "number": 0xD3},
    {"name": "IDIVK", "type": "iABC", "number": 0xB6},
    {"name": "COUNT", "type": "none", "number": 0x99},
]

# notes:
# 1. v6 added FASTCALL3.
# 2. v6 removed DEP_FORGLOOP_INEXT
# also, this probably should be a different table.
OP_TABLE_V6 = OP_TABLE_V5 + [{
    "name": "FASTCALL3", "type": "iABC", "number": 0xe3, "aux": True,
}]
index = next(i for i, op in enumerate(OP_TABLE_V6) if op["name"] == "DEP_FORGLOOP_INEXT")
OP_TABLE_V6.pop(index)


OP_TABLE_VERSION_MAP = {
    6: OP_TABLE_V6,
    5: OP_TABLE_V5
}

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
