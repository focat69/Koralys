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
