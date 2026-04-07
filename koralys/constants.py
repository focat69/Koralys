LBC_CONSTANT_NIL = 0
LBC_CONSTANT_BOOLEAN = 1
LBC_CONSTANT_NUMBER = 2
LBC_CONSTANT_STRING = 3
LBC_CONSTANT_IMPORT = 4
LBC_CONSTANT_TABLE = 5
LBC_CONSTANT_CLOSURE = 6
LBC_CONSTANT_VECTOR = 7

DEBUG = False  #! Will slow down the decompilation process significantly


def debug(*args, **kwargs):
    return print(*args, **kwargs) if DEBUG else None

# https://github.com/luau-lang/luau/blob/master/Common/include/Luau/Bytecode.h
# enum LuauBuiltinFunction
LBF_NAMES = {
    0: "none",
    1: "assert",
    2: "math.abs",
    3: "math.acos",
    4: "math.asin",
    5: "math.atan2",
    6: "math.atan",
    7: "math.ceil",
    8: "math.cosh",
    9: "math.cos",
    10: "math.deg",
    11: "math.exp",
    12: "math.floor",
    13: "math.fmod",
    14: "math.frexp",
    15: "math.ldexp",
    16: "math.log10",
    17: "math.log",
    18: "math.max",
    19: "math.min",
    20: "math.modf",
    21: "math.pow",
    22: "math.rad",
    23: "math.sinh",
    24: "math.sin",
    25: "math.sqrt",
    26: "math.tanh",
    27: "math.tan",
    28: "bit32.arshift",
    29: "bit32.band",
    30: "bit32.bnot",
    31: "bit32.bor",
    32: "bit32.bxor",
    33: "bit32.btest",
    34: "bit32.extract",
    35: "bit32.lrotate",
    36: "bit32.lshift",
    37: "bit32.replace",
    38: "bit32.rrotate",
    39: "bit32.rshift",
    40: "type",
    41: "string.byte",
    42: "string.char",
    43: "string.len",
    44: "typeof",
    45: "string.sub",
    46: "math.clamp",
    47: "math.sign",
    48: "math.round",
    49: "rawset",
    50: "rawget",
    51: "rawequal",
    52: "table.insert",
    53: "table.unpack",
    54: "vector",
    55: "bit32.countlz",
    56: "bit32.countrz",
    57: "select",
    58: "rawlen",
    59: "bit32.extractk",
    60: "getmetatable",
    61: "setmetatable",
    62: "tonumber",
    63: "tostring",
    64: "bit32.byteswap",
    65: "buffer.readi8",
    66: "buffer.readu8",
    67: "buffer.writeu8",
    68: "buffer.readi16",
    69: "buffer.readu16",
    70: "buffer.writeu16",
    71: "buffer.readi32",
    72: "buffer.readu32",
    73: "buffer.writeu32",
    74: "buffer.readf32",
    75: "buffer.writef32",
    76: "buffer.readf64",
    77: "buffer.writef64",
    78: "vector.magnitude",
    79: "vector.normalize",
    80: "vector.cross",
    81: "vector.dot",
    82: "vector.floor",
    83: "vector.ceil",
    84: "vector.abs",
    85: "vector.sign",
    86: "vector.clamp",
    87: "vector.min",
    88: "vector.max",
    89: "math.lerp",
    90: "vector.lerp",
    91: "math.isnan",
    92: "math.isinf",
    93: "math.isfinite",
}


def builtin_name(id: int) -> str:
    return LBF_NAMES.get(id, f"builtin[{id}]")