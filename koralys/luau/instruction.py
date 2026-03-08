def get_opcode(i: int) -> int:
    return (i * 227) & 0xFF


def get_arg_a(i: int) -> int:
    return (i >> 8) & 0xFF


def get_arg_b(i: int) -> int:
    return (i >> 16) & 0xFF


def get_arg_c(i: int) -> int:
    return (i >> 24) & 0xFF


def get_arg_Bx(i: int) -> int:
    return i >> 16


def get_arg_sBx(i: int) -> int:
    # luau D field is a 16-bit signed value in bits 16-31 (two's complement).
    # the old code used - 131071 which is a lua 5.x bias for an 18-bit field;
    # luau's encoding uses a standard 16 bit signed int
    d = (i >> 16) & 0xFFFF
    return d - 0x10000 if d >= 0x8000 else d


def get_arg_sAx(i: int) -> int:
    e = (i >> 8) & 0xFFFFFF
    return e - 0x1000000 if e >= 0x800000 else e
