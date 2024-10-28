"""
Useful utility functions, and constants (e.g. the operation table, getting opcodes, other stuff) for Luau.
"""

OP_TABLE = [
    {"name": "NOP", "type": "none", "case": 0, "number": 0x00},
    {"name": "BREAK", "type": "none", "case": 1, "number": 0xE3},
    {"name": "LOADNIL", "type": "iA", "case": 2, "number": 0xC6},
    {"name": "LOADB", "type": "iABC", "case": 3, "number": 0xA9},
    {"name": "LOADN", "type": "iABx", "case": 4, "number": 0x8C},
    {"name": "LOADK", "type": "iABx", "case": 5, "number": 0x6F},
    {"name": "MOVE", "type": "iAB", "case": 6, "number": 0x52},
    {"name": "GETGLOBAL", "type": "iAC", "case": 7, "number": 0x35, "aux": True},
    {"name": "SETGLOBAL", "type": "iAC", "case": 8, "number": 0x18, "aux": True},
    {"name": "GETUPVAL", "type": "iAB", "case": 9, "number": 0xFB},
    {"name": "SETUPVAL", "type": "iAB", "case": 10, "number": 0xDE},
    {"name": "CLOSEUPVALS", "type": "iA", "case": 11, "number": 0xC1},
    {"name": "GETIMPORT", "type": "iABx", "case": 12, "number": 0xA4, "aux": True},
    {"name": "GETTABLE", "type": "iABC", "case": 13, "number": 0x87},
    {"name": "SETTABLE", "type": "iABC", "case": 14, "number": 0x6A},
    {"name": "GETTABLEKS", "type": "iABC", "case": 15, "number": 0x4D, "aux": True},
    {"name": "SETTABLEKS", "type": "iABC", "case": 16, "number": 0x30, "aux": True},
    {"name": "GETTABLEN", "type": "iABC", "case": 17, "number": 0x13},
    {"name": "SETTABLEN", "type": "iABC", "case": 18, "number": 0xF6},
    {"name": "NEWCLOSURE", "type": "iABx", "case": 19, "number": 0xD9},
    {"name": "NAMECALL", "type": "iABC", "case": 20, "number": 0xBC, "aux": True},
    {"name": "CALL", "type": "iABC", "case": 21, "number": 0x9F},
    {"name": "RETURN", "type": "iAB", "case": 22, "number": 0x82},
    {"name": "JUMP", "type": "isBx", "case": 23, "number": 0x65},
    {"name": "JUMPBACK", "type": "isBx", "case": 24, "number": 0x48},
    {"name": "JUMPIF", "type": "iAsBx", "case": 25, "number": 0x2B},
    {"name": "JUMPIFNOT", "type": "iAsBx", "case": 26, "number": 0x0E},
    {"name": "JUMPIFEQ", "type": "iAsBx", "case": 27, "number": 0xF1, "aux": True},
    {"name": "JUMPIFLE", "type": "iAsBx", "case": 28, "number": 0xD4, "aux": True},
    {"name": "JUMPIFLT", "type": "iAsBx", "case": 29, "number": 0xB7, "aux": True},
    {
        "name": "JUMPIFNOTEQ",
        "type": "iAsBx",
        "case": 30,
        "number": 0x9A,
        "aux": True,
    },
    {
        "name": "JUMPIFNOTLE",
        "type": "iAsBx",
        "case": 31,
        "number": 0x7D,
        "aux": True,
    },
    {
        "name": "JUMPIFNOTLT",
        "type": "iAsBx",
        "case": 32,
        "number": 0x60,
        "aux": True,
    },
    {"name": "ADD", "type": "iABC", "case": 33, "number": 0x43},
    {"name": "SUB", "type": "iABC", "case": 34, "number": 0x26},
    {"name": "MUL", "type": "iABC", "case": 35, "number": 0x09},
    {"name": "DIV", "type": "iABC", "case": 36, "number": 0xEC},
    {"name": "MOD", "type": "iABC", "case": 37, "number": 0xCF},
    {"name": "POW", "type": "iABC", "case": 38, "number": 0xB2},
    {"name": "ADDK", "type": "iABC", "case": 39, "number": 0x95},
    {"name": "SUBK", "type": "iABC", "case": 40, "number": 0x78},
    {"name": "MULK", "type": "iABC", "case": 41, "number": 0x5B},
    {"name": "DIVK", "type": "iABC", "case": 42, "number": 0x3E},
    {"name": "MODK", "type": "iABC", "case": 43, "number": 0x21},
    {"name": "POWK", "type": "iABC", "case": 44, "number": 0x04},
    {"name": "AND", "type": "iABC", "case": 45, "number": 0xE7},
    {"name": "OR", "type": "iABC", "case": 46, "number": 0xCA},
    {"name": "ANDK", "type": "iABC", "case": 47, "number": 0xAD},
    {"name": "ORK", "type": "iABC", "case": 48, "number": 0x90},
    {"name": "CONCAT", "type": "iABC", "case": 49, "number": 0x73},
    {"name": "NOT", "type": "iAB", "case": 50, "number": 0x56},
    {"name": "MINUS", "type": "iAB", "case": 51, "number": 0x39},
    {"name": "LENGTH", "type": "iAB", "case": 52, "number": 0x1C},
    {"name": "NEWTABLE", "type": "iAB", "case": 53, "number": 0xFF, "aux": True},
    {"name": "DUPTABLE", "type": "iABx", "case": 54, "number": 0xE2},
    {"name": "SETLIST", "type": "iABC", "case": 55, "number": 0xC5, "aux": True},
    {"name": "FORNPREP", "type": "iABx", "case": 56, "number": 0xA8},
    {"name": "FORNLOOP", "type": "iABx", "case": 57, "number": 0x8B},
    {"name": "FORGLOOP", "type": "iABx", "case": 58, "number": 0x6E, "aux": True},
    {"name": "FORGPREP_INEXT", "type": "none", "case": 59, "number": 0x51},
    {"name": "DEP_FORGLOOP_INEXT", "type": "none", "case": 60, "number": 0x34},
    {"name": "FORGPREP_NEXT", "type": "none", "case": 61, "number": 0x17},
    {"name": "NATIVECALL", "type": "none", "case": 62, "number": 0xFA},
    {"name": "GETVARARGS", "type": "iAB", "case": 63, "number": 0xDD},
    {"name": "DUPCLOSURE", "type": "iABx", "case": 64, "number": 0xC0},
    {"name": "PREPVARARGS", "type": "iA", "case": 65, "number": 0xA3},
    {"name": "LOADKX", "type": "iA", "case": 66, "number": 0x86},
    {"name": "JUMPX", "type": "isAx", "case": 67, "number": 0x69},
    {"name": "FASTCALL", "type": "iAC", "case": 68, "number": 0x4C},
    {"name": "COVERAGE", "type": "isAx", "case": 69, "number": 0x2F},
    {"name": "CAPTURE", "type": "iAB", "case": 70, "number": 0x12},
    {"name": "SUBRK", "type": "iABx", "case": 71, "number": 0xF5, "aux": True},
    {"name": "DIVRK", "type": "iABx", "case": 72, "number": 0xD8, "aux": True},
    {"name": "FASTCALL1", "type": "iABC", "case": 73, "number": 0xBB},
    {"name": "FASTCALL2", "type": "iABC", "case": 74, "number": 0x9E, "aux": True},
    {"name": "FASTCALL2K", "type": "iABC", "case": 75, "number": 0x81, "aux": True},
    {"name": "FORGPREP", "type": "iAB", "case": 76, "number": 0x64},
    {
        "name": "JUMPXEQKNIL",
        "type": "iAsBx",
        "case": 77,
        "number": 0x47,
        "aux": True,
    },
    {"name": "JUMPXEQKB", "type": "iAsBx", "case": 78, "number": 0x2A, "aux": True},
    {"name": "JUMPXEQKN", "type": "iAsBx", "case": 79, "number": 0x0D, "aux": True},
    {"name": "JUMPXEQKS", "type": "iAsBx", "case": 80, "number": 0xF0, "aux": True},
    {"name": "IDIV", "type": "iABC", "case": 81, "number": 0xD3},
    {"name": "IDIVK", "type": "iABC", "case": 82, "number": 0xB6},
    {"name": "COUNT", "type": "none", "case": 83, "number": 0x99},
]


def get_opcode(i: int) -> int:
    return (i * 227) & 0xFF


def GETARG_A(i: int) -> int:
    return (i >> 8) & 0xFF


def GETARG_B(i: int) -> int:
    return (i >> 16) & 0xFF


def GETARG_C(i: int) -> int:
    return (i >> 24) & 0xFF


# def GETARG_D(i: int) -> int:
#     d = (i >> 16) & 0xFFFF  # Extract 16 bits for D
#     return d - 0x10000 if d & 0x8000 else d  # Convert to signed


def GETARG_Bx(i: int) -> int:
    return i >> 16


def GETARG_sBx(i: int) -> int:
    return (i >> 16) - 131071


def GETARG_sAx(i: int) -> int:
    return i >> 8
