"""
Koralys Disassembler & Decompiler
>> This project is a result of countless hours of hard work and development.
>> We ask that you do not claim this project as your own, and give credit where it is due.
>>>> This project is licensed under the GNU General Public License v3.0.

Written by:
    - focat ({
        "Discord": @focat, (676960182621962271)
        "Github": focat69
    })
    - Jiface ({
        "Discord": @_jifacepellyfreckles, (1233718214714724385)
        "Github": ssynical
    })

Turning on the `DEBUG` flag will slow down the decompilation process significantly.
0.000406s -> 0.002075s, around 5x slower
The `DEBUG` flag is meant for development purposes only. Turn off before using in production.

>> There is no V6 support in this version!
>> To get access, become a beta tester.

Issues:
    Makes everything a proto even if it isnt
    Does not show jump targets (eg. if code has goto [5] but only has 3 instructions, it doesnt show "::5::" and it's dism)
    Decompile is broken/really bad/unfinished
    No type checking
    Does not handle variables kindly
    No v6 support (not an issue just not added to this version lol)

Please contribute and fix these bugs and more that you may find.
(except v6 support we got dat)
"""

import sys
import time
import struct
from typing import List, Dict, Tuple, Any

DEBUG = False #! Will slow down the decompilation process significantly
def debug(*args, **kwargs):
    return print(*args, **kwargs) if DEBUG else None

# < CONSTANT TYPES > #
LBC_CONSTANT_NIL = 0
LBC_CONSTANT_BOOLEAN = 1
LBC_CONSTANT_NUMBER = 2
LBC_CONSTANT_STRING = 3
LBC_CONSTANT_IMPORT = 4
LBC_CONSTANT_TABLE = 5
LBC_CONSTANT_CLOSURE = 6
LBC_CONSTANT_VECTOR = 7

# < BYTECODE READER > #
class Reader:
    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.pos = 0

    def canRead(self, n: int) -> bool:
        return self.pos + n <= len(self.bytecode)

    def nextByte(self) -> int:
        if not self.canRead(1):
            raise IndexError(f"Attempted to read byte at position {self.pos}, but bytecode length is {len(self.bytecode)}")
        v = self.bytecode[self.pos]
        self.pos += 1
        return v

    def nextChar(self) -> str:
        return chr(self.nextByte())

    def nextUint32(self) -> int:
        return self.unpackStruct(
            4, 'Attempted to read 4 bytes at position ', '<I'
        )

    def nextInt(self) -> int:
        b = [self.nextByte() for _ in range(4)]
        return (b[3] << 24) | (b[2] << 16) | (b[1] << 8) | b[0]

    def nextVarInt(self) -> int:
        result = 0
        shift = 0
        while True:
            if not self.canRead(1):
                raise IndexError(f"Unexpected end of bytecode while reading VarInt at position {self.pos}")
            b = self.nextByte()
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result

    def nextString(self) -> str:
        length = self.nextVarInt()
        if not self.canRead(length):
            raise IndexError(f"Attempted to read string of length {length} at position {self.pos}, but bytecode length is {len(self.bytecode)}")
        result = self.bytecode[self.pos:self.pos+length].decode('utf-8')
        self.pos += length
        return result

    def nextFloat(self) -> float:
        return self.unpackStruct(
            4, 'Attempted to read float at position ', '<f'
        )

    def nextDouble(self) -> float:
        return self.unpackStruct(
            8, 'Attempted to read double at position ', '<d'
        )

    # TODO Rename this here and in `nextUint32`, `nextFloat` and `nextDouble`
    def unpackStruct(self, n, arg1, format):
        if not self.canRead(n):
            raise IndexError(
                f"{arg1}{self.pos}, but bytecode length is {len(self.bytecode)}"
            )
        value = struct.unpack(format, self.bytecode[self.pos:self.pos + n])[0]
        self.pos += n
        return value

    def skip(self, n: int) -> None:
        if not self.canRead(n):
            raise IndexError(f"Attempted to skip {n} bytes at position {self.pos}, but bytecode length is {len(self.bytecode)}")
        self.pos += n

    def read(self, n: int) -> bytes:
        if not self.canRead(n):
            raise IndexError(f"Attempted to read {n} bytes at position {self.pos}, but bytecode length is {len(self.bytecode)}")
        data = self.bytecode[self.pos:self.pos+n]
        self.pos += n
        return data

# TODO: fix sourcery code quality issues (currently 12%)
def deserialize_v5(reader: Reader) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    types_version = reader.nextByte()
    if types_version not in [1, 2, 3]:
        raise ValueError(f"Invalid types version (types version: {types_version})")

    luau_version = f"Luau Version 5, Types Version {types_version}"

    proto_table: List[Dict[str, Any]] = []
    string_table: List[str] = []

    size_strings = reader.nextVarInt()
    string_table.extend(reader.nextString() for _ in range(size_strings))
    size_protos = reader.nextVarInt()
    proto_table.extend(
        {
            'codeTable': [],
            'kTable': [],
            'pTable': [],
            'smallLineInfo': [],
            'largeLineInfo': [],
        }
        for _ in range(size_protos)
    )
    for i in range(size_protos):
        proto = proto_table[i]
        proto['maxStackSize'] = reader.nextByte()
        proto['numParams'] = reader.nextByte()
        proto['numUpValues'] = reader.nextByte()
        proto['isVarArg'] = reader.nextByte()

        proto['flags'] = reader.nextByte()
        typesize = reader.nextVarInt()
        proto['typeInfo'] = [reader.nextByte() for _ in range(typesize)]

        proto['sizeCode'] = reader.nextVarInt()
        for _ in range(proto['sizeCode']):
            proto['codeTable'].append(reader.nextInt())

        proto['sizeConsts'] = reader.nextVarInt()
        for _ in range(proto['sizeConsts']):
            k = {'type': reader.nextByte()}
            if k['type'] == LBC_CONSTANT_BOOLEAN:
                k['value'] = reader.nextByte() == 1
            elif k['type'] == LBC_CONSTANT_NUMBER:
                k['value'] = reader.nextDouble()
            elif k['type'] == LBC_CONSTANT_STRING:
                index = reader.nextVarInt()
                adjusted_index = index - 1
                if 0 <= adjusted_index < len(string_table):
                    k['value'] = string_table[adjusted_index]
                else:
                    k['value'] = "Invalid string index"
            elif k['type'] == LBC_CONSTANT_IMPORT:
                k['value'] = reader.nextInt()
            elif k['type'] == LBC_CONSTANT_TABLE:
                k['value'] = {'size': reader.nextVarInt(), 'ids': []}
                for _ in range(k['value']['size']):
                    k['value']['ids'].append(reader.nextVarInt() + 1)
            elif k['type'] == LBC_CONSTANT_CLOSURE:
                k['value'] = reader.nextVarInt() + 1
            elif k['type'] == LBC_CONSTANT_VECTOR:
                k['value'] = [reader.nextFloat() for _ in range(4)]
            elif k['type'] != 0:
                raise ValueError(f"Unrecognized constant type: {k['type']}")
            proto['kTable'].append(k)

        proto['sizeProtos'] = reader.nextVarInt()
        for _ in range(proto['sizeProtos']):
            proto['pTable'].append(proto_table[reader.nextVarInt()])

        proto['lineDefined'] = reader.nextVarInt()

        protoSourceId = reader.nextVarInt()
        if protoSourceId >= len(string_table):
            raise IndexError(f"Index {protoSourceId} out of range for stringTable with length {len(string_table)}")
        proto['source'] = string_table[protoSourceId]

        if reader.nextByte() == 1:  # has line info?
            compKey = reader.nextByte()
            for _ in range(proto['sizeCode']):
                proto['smallLineInfo'].append(reader.nextByte())

            _ = (proto['sizeCode'] + 3) & -4
            intervals = ((proto['sizeCode'] - 1) >> compKey) + 1

            for _ in range(intervals):
                proto['largeLineInfo'].append(reader.nextInt())

        if reader.nextByte() == 1:  # has debug info?
            raise ValueError("only ROBLOX scripts can be disassembled")

    mainProtoId = reader.nextVarInt()
    if mainProtoId >= len(proto_table):
        raise IndexError(f"Index {mainProtoId} out of range for protoTable with length {len(proto_table)}")
    return proto_table[mainProtoId], proto_table, string_table, luau_version

def parse_proto(reader: Reader, string_table: List[str], types_version: int) -> Dict[str, Any]:
    proto: Dict[str, Any] = {
        'maxStackSize': reader.nextByte(),
        'numParams': reader.nextByte(),
        'numUpValues': reader.nextByte(),
        'isVarArg': reader.nextByte(),
        'flags': reader.nextByte(),
        'typeInfo': [],
        'codeTable': [],
        'kTable': [],
        'pTable': [],
        'lineInfo': None,
        'debugInfo': None,
        'source': "",
    }

    type_size = reader.nextVarInt()
    proto['typeInfo'] = [reader.nextByte() for _ in range(type_size)]

    size_code = reader.nextVarInt()
    debug(f"  Code size: {size_code}")
    proto['codeTable'] = [reader.nextUint32() for _ in range(size_code)]
    proto['sizeCode'] = size_code

    size_consts = reader.nextVarInt()
    debug(f"  Number of constants: {size_consts}")
    proto['kTable'] = [parse_constant(reader, string_table) for _ in range(size_consts)]

    size_protos = reader.nextVarInt()
    debug(f"  Number of child protos: {size_protos}")
    proto['pTable'] = [reader.nextVarInt() for _ in range(size_protos)]
    proto['numChildren'] = size_protos

    proto['lineDefined'] = reader.nextVarInt()

    proto_source_id = reader.nextVarInt()
    if 0 <= proto_source_id - 1 < len(string_table):
        proto['source'] = string_table[proto_source_id - 1]
    else:
        proto['source'] = f"Invalid source index: {proto_source_id}"

    if reader.nextByte() == 1:  # has line info?
        debug("  Proto has line info")
        proto['lineInfo'] = parse_line_info(reader, size_code)

    if reader.nextByte() == 1:  # has debug info?
        debug("  Proto has debug info")
        proto['debugInfo'] = parse_debug_info(reader, string_table)

    return proto

def parse_constant(reader: Reader, string_table: List[str]) -> Dict[str, Any]:
    try:
        k = {'type': reader.nextByte()}
        if k['type'] == LBC_CONSTANT_NIL:
            k['value'] = None
        elif k['type'] == LBC_CONSTANT_BOOLEAN:
            k['value'] = reader.nextByte() == 1
        elif k['type'] == LBC_CONSTANT_NUMBER:
            k['value'] = reader.nextDouble()
        elif k['type'] == LBC_CONSTANT_STRING:
            index = reader.nextVarInt()
            adjusted_index = index - 1
            if 0 <= adjusted_index < len(string_table):
                k['value'] = string_table[adjusted_index]
            else:
                k['value'] = f"Invalid string index: {index}"
        elif k['type'] == LBC_CONSTANT_IMPORT:
            k['value'] = reader.nextUint32()
        elif k['type'] == LBC_CONSTANT_TABLE:
            size = reader.nextVarInt()
            k['value'] = {'size': size, 'ids': [reader.nextVarInt() for _ in range(size)]}
        elif k['type'] == LBC_CONSTANT_CLOSURE:
            k['value'] = reader.nextVarInt()
        elif k['type'] == LBC_CONSTANT_VECTOR:
            k['value'] = [reader.nextFloat() for _ in range(4)]
        elif k['type'] == 70:
            k['value'] = reader.nextVarInt()
        else:
            k['value'] = f"Unknown type: {k['type']}, Value: {reader.nextVarInt()}"
    except IndexError as e:
        k['value'] = f"Error reading constant: {str(e)}"
    return k

def parse_line_info(reader: Reader, size_code: int) -> Dict[str, Any]:
    lineInfo = {'compKey': reader.nextByte(), 'intervals': []}
    lineInfo['intervals'] = [reader.nextByte() for _ in range(size_code)]

    _ = (size_code + 3) & -4
    largeIntervals = ((size_code - 1) >> lineInfo['compKey']) + 1

    lineInfo['intervals'].extend([reader.nextUint32() for _ in range(largeIntervals)])
    return lineInfo

def parse_debug_info(reader: Reader, string_table: List[str]) -> Dict[str, Any]:
    debug_info = {
        'varInfo': [],
        'upvalueInfo': [],
    }
    sizeVars = reader.nextVarInt()
    for _ in range(sizeVars):
        debug_info['varInfo'].append({
            'name': string_table[reader.nextVarInt() - 1],
            'startpc': reader.nextVarInt(),
            'endpc': reader.nextVarInt(),
            'reg': reader.nextByte(),
        })
    sizeUpvalues = reader.nextVarInt()
    debug_info['upvalueInfo'] = [string_table[reader.nextVarInt() - 1] for _ in range(sizeUpvalues)]
    return debug_info

def deserialize(bytecode: bytes) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str], str]:
    reader = Reader(bytecode)
    version = reader.nextByte()
    debug(f"Bytecode version: {version}")
    if version == 5:
        return deserialize_v5(reader)
    else:
        raise ValueError(f"Unsupported bytecode version: {version}")

def getluauoptable():
    return [
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
        {"name": "JUMPIFNOTEQ", "type": "iAsBx", "case": 30, "number": 0x9A, "aux": True},
        {"name": "JUMPIFNOTLE", "type": "iAsBx", "case": 31, "number": 0x7D, "aux": True},
        {"name": "JUMPIFNOTLT", "type": "iAsBx", "case": 32, "number": 0x60, "aux": True},
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
        {"name": "JUMPXEQKNIL", "type": "iAsBx", "case": 77, "number": 0x47, "aux": True},
        {"name": "JUMPXEQKB", "type": "iAsBx", "case": 78, "number": 0x2A, "aux": True},
        {"name": "JUMPXEQKN", "type": "iAsBx", "case": 79, "number": 0x0D, "aux": True},
        {"name": "JUMPXEQKS", "type": "iAsBx", "case": 80, "number": 0xF0, "aux": True},
        {"name": "IDIV", "type": "iABC", "case": 81, "number": 0xD3},
        {"name": "IDIVK", "type": "iABC", "case": 82, "number": 0xB6},
        {"name": "COUNT", "type": "none", "case": 83, "number": 0x99}
    ]

def GET_OPCODE(i: int) -> int:
    return (i * 227) & 0xFF

def GETARG_A(i: int) -> int:
    return (i >> 8) & 0xFF

def GETARG_B(i: int) -> int:
    return (i >> 16) & 0xFF

def GETARG_C(i: int) -> int:
    return (i >> 24) & 0xFF

def GETARG_Bx(i: int) -> int:
    return i >> 16

def GETARG_sBx(i: int) -> int:
    return (i >> 16) - 131071

def GETARG_sAx(i: int) -> int:
    return i >> 8

def read_proto(proto: Dict[str, Any], depth: int, proto_table: List[Dict[str, Any]], string_table: List[str], luau_version: str) -> str:
    output = ""
    tab_space = "    " * (depth - 1)

    output += f"{tab_space}function({', '.join(['...' if proto['isVarArg'] else ''] + [f'R{i}' for i in range(proto['numParams'])])})\n"

    luauOpTable = getluauoptable()
    opnameToOpcode = {info['name']: info['number'] for info in luauOpTable}
    opcodeToOpname = {info['number']: info['name'] for info in luauOpTable}
    max_opname_length = max(len(info['name']) for info in luauOpTable)

    def get_opcode(opname: str) -> int:
        opcode = opnameToOpcode.get(opname)
        if opcode is None:
            raise ValueError(f"Unknown opname {opname}")
        return opcode

    codeIndex = 0
    while codeIndex < len(proto['codeTable']):
        i = proto['codeTable'][codeIndex]
        opc = GET_OPCODE(i)
        A = GETARG_A(i)
        B = GETARG_B(i)
        Bx = GETARG_Bx(i)
        C = GETARG_C(i)
        sBx = GETARG_sBx(i)
        sAx = GETARG_sAx(i)

        opname = opcodeToOpname.get(opc, "UNKNOWN")
        output += f"{'    ' * depth}[{codeIndex:03}] {opname:<{max_opname_length}} "

        aux = None
        if any(info['name'] == opname and info.get('aux', False) for info in luauOpTable) and codeIndex + 1 < len(proto['codeTable']):
            aux = proto['codeTable'][codeIndex + 1]
            codeIndex += 1
        def __CALL_handler():
            args = f"R{A+1}" + (f" ... R{A+C-1}" if C > 1 else "")
            returns = f"R{A}" + (f" ... R{A+B-2}" if B > 1 else "")
            return f"{returns} = R{A}({args})"

        def jump_if_gen(
             op: str | None = None,
             invert: bool = False
        ):
            pre_op = invert and "not " or " "
            jump = opcode_handlers["JUMP"]()
            after_cond = op and f"{op} {aux}" or ""
            return f"if {pre_op}R{A} {after_cond} then {jump}"

        opcode_handlers = {
            "LOADNIL": lambda: f"R{A} = nil",
            "LOADB": lambda: f"R{A} = {bool(B)}; " + (f"goto [{codeIndex + C + 1}]" if C != 0 else ""),
            "LOADN": lambda: f"R{A} = {Bx}",
            "MOVE": lambda: f"R{A} = R{B}",
            "GETGLOBAL":
                    lambda:
                         f"R{A} = _G[{repr(string_table[aux])}]"
                          if aux is not None and aux < len(string_table)
                        else f"R{A} = _G[Invalid string index]",
            "SETGLOBAL":
                lambda:
                     f"_G[{repr(string_table[aux])}"
                       if aux is not None and aux < len(string_table)
                     else f"_G[Invalid string index] = R{A}",
            "GETUPVAL":
                lambda:
                     f"R{A} = U{B}",
            "SETUPVAL":
                lambda:
                     f"U{B} = R{A}",
            "CLOSEUPVALS":
                lambda:
                     f"close upvalues R{A}+",
            "GETIMPORT":
                lambda:
                     f"R{A} = {proto['kTable'][Bx]['value']}",
            "GETTABLE":
                lambda:
                     f"R{A} = R{B}[R{C}]",
            "SETTABLE":
                lambda:
                     f"R{A} = R{B}[R{C}]",
            "GETTABLEKS":
                lambda:
                     f"R{A} = R{B}[{repr(string_table[aux])}"
                       if aux is not None and aux < len(string_table)
                     else f"R{A} = R{B}[Invalid string index]",
            "SETTABLEKS":
                lambda:
                     f"R{B}[{repr(string_table[aux])} = R{A}"
                       if aux is not None and aux < len(string_table)
                     else f"R{B}[Invalid string index] = R{A}",
            "GETTABLEN":
                lambda:
                     f"R{A} = R{B}[{C + 1}]",
            "SETTABLEN":
                lambda:
                     f"R{B}[{C + 1}] = R{A}",
            "NEWCLOSURE":
                lambda:
                     f"R{A} = closure(proto[{Bx}])",
            "NAMECALL":
                lambda:
                     f"R{A} = R{B}[{repr(string_table[aux])}; R{A+1} = R{B}"
                       if aux is not None and aux < len(string_table)
                     else f"R{A} = R{B}[Invalid String Index]; R{A+1} = R{B}",
            "CALL": __CALL_handler,
            "RETURN":
                lambda:
                     f"return R{A} ..."
                       if B == 0
                     else "return"
                          if B == 1
                        else f"return R{A} ... R{A+B-2}",
            "JUMP":
                lambda:
                     f"goto [{(codeIndex + 1 + sBx) & 0xFF}]",
            "JUMPBACK":
                lambda:
                     f"goto [{(codeIndex + 1 - sBx) & 0xFF}]",
            "JUMPIF":
                lambda:
                     jump_if_gen(),
            "JUMPIFNOT":
                lambda:
                     jump_if_gen(None, True),
            "JUMPIFEQ":
                lambda:
                     jump_if_gen("=="),
            "JUMPIFLE":
                lambda:
                     jump_if_gen("<=")
        }
        if opname in opcode_handlers:
            output += opcode_handlers[opname]()
        else:
            output += f"Unknown opcode: {opc}"

        output += "\n"
        codeIndex += 1

    output += "end\n"

    if len(proto['kTable']) > 0:
        output += "--< Constants >--\n"
        constant_types = {
            LBC_CONSTANT_NIL: "nil",
            LBC_CONSTANT_BOOLEAN: lambda k: str(k['value']).lower(),
            LBC_CONSTANT_STRING: lambda k: repr(k['value']),
            LBC_CONSTANT_NUMBER: lambda k: k['value'],
            LBC_CONSTANT_TABLE: lambda k: k['value'],
            LBC_CONSTANT_CLOSURE: lambda k: k['value'],
            LBC_CONSTANT_VECTOR: lambda k: k['value'],
        }
        for i, k in enumerate(proto['kTable']):
            value = constant_types.get(k['type'], lambda k: f"Unknown constant type: {k['type']}")(k)
            output += f"{'    ' * depth}[{i}] = {value}\n"

    if 'sizeProtos' in proto and proto['sizeProtos'] > 0:
        output += "--< Protos >--\n"
        for i, p in enumerate(proto['pTable']):
            output += f"{'    ' * depth}[{i}] = {read_proto(p, depth + 1, proto_table, string_table, luau_version)}\n"

    if proto['numUpValues'] > 0:
        output += "--< Upvalues >--\n"
        for i in range(proto['numUpValues']):
            output += f"{'    ' * depth}[{i}] = Upvalue {i}\n"

    return output


def disassemble(bytecode: bytes) -> Tuple[List[str], List[str], int, str]:
    output = []
    decompiled_output = []

    if bytecode[0] == 0:
        return [bytecode[1:].decode('utf-8')], [], 0, "Luau Version Unknown"

    try:
        mainProto, protoTable, stringTable, LUAUVERSION = deserialize(bytecode)
    except Exception as e:
        return [f"Error: {e}"], [], 0, "Luau Version Unknown"

    protos = 0
    for i, proto in enumerate(protoTable):
        output.extend(
            (
                f"--< Proto->{i:03} | Line {proto.get('lineDefined', 0)} >--",
                read_proto(proto, 1, protoTable, stringTable, LUAUVERSION),
            )
        )
        decompiled_output.extend(
            (
                f"-- Decompiled Proto->{i:03} --",
                decompile(proto, 1, stringTable),
            )
        )
        protos += 1

    return output, decompiled_output, protos, LUAUVERSION

def decompile(proto: Dict[str, Any], depth: int, stringTable: List[str]) -> str:
    # Removed redundant variables, fixed jumps and cleaned up the output - focat
    # its still shit btw LMAO but some what better
    output = []

    def add_tab_space(depth):
        return "    " * depth

    output.append(f"local function func{depth}()")

    luau_op_table = getluauoptable()
    # opname_to_opcode = {info['name']: info['number'] for info in luau_op_table}
    opcode_to_opname = {info['number']: info['name'] for info in luau_op_table}

    # def get_opcode(opname: str) -> int:
    #     return opname_to_opcode.get(opname, -1)

    def format_constant(k):
        if isinstance(k, dict):
            if k['type'] == 3:  # String
                return repr(k['value'])
            elif k['type'] in [1, 2]:  # Number
                return str(k['value'])
            else:
                return str(k['value'])
        return str(k)

    for code_index, i in enumerate(proto['codeTable']):
        try:
            opc = GET_OPCODE(i)
            A = GETARG_A(i)
            B = GETARG_B(i)
            Bx = GETARG_Bx(i)
            C = GETARG_C(i)
            sBx = GETARG_sBx(i)
            sAx = GETARG_sAx(i)
            aux = proto['codeTable'][code_index + 1] if code_index + 1 < len(proto['codeTable']) else None

            opname = opcode_to_opname.get(opc, "UNKNOWN")

            if opname == "LOADNIL":
                output.append(f"{add_tab_space(depth + 1)}R{A} = nil")
            elif opname == "LOADB":
                output.append(f"{add_tab_space(depth + 1)}R{A} = {bool(B)}")
                if C != 0:
                    output.append(f"{add_tab_space(depth + 1)}goto [{code_index + 1 + C}]")
            elif opname == "LOADN":
                output.append(f"{add_tab_space(depth + 1)}R{A} = {sBx}")
            elif opname == "LOADK":
                if Bx < len(proto['kTable']):
                    k = proto['kTable'][Bx]
                    output.append(f"{add_tab_space(depth + 1)}R{A} = {format_constant(k)}")
                else:
                    output.append(f"{add_tab_space(depth + 1)}R{A} = <invalid index {Bx}>")
            elif opname == "MOVE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B}")
            elif opname == "GETGLOBAL":
                if aux is not None and aux < len(stringTable):
                    output.append(f"{add_tab_space(depth + 1)}R{A} = _G[{repr(stringTable[aux])}]")
                else:
                    output.append(f"{add_tab_space(depth + 1)}R{A} = _G[Invalid string index]")
            elif opname == "SETGLOBAL":
                if aux is not None and aux < len(stringTable):
                    output.append(f"{add_tab_space(depth + 1)}_G[{repr(stringTable[aux])}] = R{A}")
                else:
                    output.append(f"{add_tab_space(depth + 1)}_G[Invalid string index] = R{A}")
            elif opname == "GETUPVAL":
                output.append(f"{add_tab_space(depth + 1)}R{A} = U{B}")
            elif opname == "SETUPVAL":
                output.append(f"{add_tab_space(depth + 1)}U{B} = R{A}")
            elif opname == "CLOSEUPVALS":
                output.append(f"{add_tab_space(depth + 1)}close upvalues R{A}+")
            elif opname == "GETIMPORT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = {proto['kTable'][Bx]['value']}")
            elif opname == "GETTABLE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B}[R{C}]")
            elif opname == "SETTABLE":
                output.append(f"{add_tab_space(depth + 1)}R{B}[R{C}] = R{A}")
            elif opname == "GETTABLEKS":
                if aux is not None and aux < len(stringTable):
                    output.append(f"{add_tab_space(depth + 1)}R{A} = R{B}[{repr(stringTable[aux])}]")
                else:
                    output.append(f"{add_tab_space(depth + 1)}R{A} = R{B}[Invalid string index]")
            elif opname == "SETTABLEKS":
                if aux is not None and aux < len(stringTable):
                    output.append(f"{add_tab_space(depth + 1)}R{B}[{repr(stringTable[aux])}] = R{A}")
                else:
                    output.append(f"{add_tab_space(depth + 1)}R{B}[Invalid string index] = R{A}")
            elif opname == "GETTABLEN":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B}[{C + 1}]")
            elif opname == "SETTABLEN":
                output.append(f"{add_tab_space(depth + 1)}R{B}[{C + 1}] = R{A}")
            elif opname == "NEWCLOSURE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = closure(proto[{Bx}])")
            elif opname == "NAMECALL":
                if aux is not None and aux < len(stringTable):
                    output.append(f"{add_tab_space(depth + 1)}R{A} = R{B}[{repr(stringTable[aux])}]; R{A+1} = R{B}")
                else:
                    output.append(f"{add_tab_space(depth + 1)}R{A} = R{B}[Invalid string index]; R{A+1} = R{B}")
            elif opname == "CALL":
                args = f"R{A+1}" + (f" ... R{A+C-1}" if C > 1 else "")
                returns = f"R{A}" + (f" ... R{A+B-2}" if B > 1 else "")
                output.append(f"{add_tab_space(depth + 1)}{returns} = R{A}({args})")
            elif opname == "RETURN":
                if B == 0:
                    output.append(f"{add_tab_space(depth + 1)}return R{A} ...")
                elif B == 1:
                    output.append(f"{add_tab_space(depth + 1)}return")
                else:
                    output.append(f"{add_tab_space(depth + 1)}return R{A} ... R{A+B-2}")
            elif opname in ["JUMP", "JUMPBACK"]:
                target = code_index + 1 + sBx if opname == "JUMP" else code_index + 1 - sBx
                target &= 0xFF
                output.append(f"{add_tab_space(depth + 1)}goto [{target}]")
            elif opname in ["JUMPIF", "JUMPIFNOT"]:
                condition = "" if opname == "JUMPIF" else "not "
                output.append(f"{add_tab_space(depth + 1)}if {condition}R{A} then goto [{(code_index + 1 + sBx) & 0xFF}]")
            elif opname in ["JUMPIFEQ", "JUMPIFLE", "JUMPIFLT", "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT"]:
                op = {
                    "JUMPIFEQ": "==", "JUMPIFLE": "<=", "JUMPIFLT": "<",
                    "JUMPIFNOTEQ": "~=", "JUMPIFNOTLE": ">", "JUMPIFNOTLT": ">="
                }[opname]
                output.append(f"{add_tab_space(depth + 1)}if R{A} {op} {aux} then goto [{(code_index + 2 + sBx) & 0xFF}]")
            elif opname in ["ADD", "SUB", "MUL", "DIV", "MOD", "POW", "ADDK", "SUBK", "MULK", "DIVK", "MODK", "POWK"]:
                op = {
                    "ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "MOD": "%", "POW": "^",
                    "ADDK": "+", "SUBK": "-", "MULK": "*", "DIVK": "/", "MODK": "%", "POWK": "^"
                }[opname]
                if opname.endswith("K"):
                    k = proto['kTable'][C] if C < len(proto['kTable']) else {'type': "nil", 'value': "nil"}
                    output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} {op} {format_constant(k)}")
                else:
                    output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} {op} R{C}")
            elif opname in ["AND", "OR", "ANDK", "ORK"]:
                op = "and" if opname.startswith("AND") else "or"
                if opname.endswith("K"):
                    k = proto['kTable'][C] if C < len(proto['kTable']) else {'type': "nil", 'value': "nil"}
                    output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} {op} {format_constant(k)}")
                else:
                    output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} {op} R{C}")
            elif opname == "NOT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = not R{B}")
            elif opname == "NOP":
                output.append(f"{add_tab_space(depth + 1)}nop")
            elif opname == "BREAK":
                output.append(f"{add_tab_space(depth + 1)}break")
            elif opname == "FORNPREP":
                output.append(f"{add_tab_space(depth + 1)}R{A} = fornprep(R{A}, {sBx})")
            elif opname == "FORNLOOP":
                output.append(f"{add_tab_space(depth + 1)}R{A} = fornloop(R{A}, {sBx})")
            elif opname == "MINUS":
                output.append(f"{add_tab_space(depth + 1)}R{A} = -R{B}")
            elif opname == "LEN":
                output.append(f"{add_tab_space(depth + 1)}R{A} = #R{B}")
            elif opname == "CONCAT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} .. R{C}")
            elif opname == "FASTCALL":
                output.append(f"{add_tab_space(depth + 1)}R{A} = fastcall({B}, {C})")
            elif opname == "FASTCALL1":
                output.append(f"{add_tab_space(depth + 1)}R{A} = fastcall1({B}, R{C})")
            elif opname == "FASTCALL2":
                output.append(f"{add_tab_space(depth + 1)}R{A} = fastcall2({B}, R{C}, {aux})")
            elif opname == "FASTCALL2K":
                k = proto['kTable'][aux] if aux < len(proto['kTable']) else {'type': "nil", 'value': "nil"}
                output.append(f"{add_tab_space(depth + 1)}R{A} = fastcall2k({B}, R{C}, {format_constant(k)})")
            elif opname == "FORGLOOP":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgloop(R{A}, {sBx})")
            elif opname == "FORGLOOP_INEXT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgloop_inext(R{A}, {sBx})")
            elif opname == "FORGLOOP_NEXT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgloop_next(R{A}, {sBx})")
            elif opname == "FORGPREP":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgprep(R{A}, {sBx})")
            elif opname == "FORGPREP_INEXT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgprep_inext(R{A}, {sBx})")
            elif opname == "FORGPREP_NEXT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgprep_next(R{A}, {sBx})")
            elif opname == "GETVARARGS":
                output.append(f"{add_tab_space(depth + 1)}R{A}, ... = ..., ({B - 1} args)")
            elif opname == "DUPCLOSURE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = dupclosure(K{Bx})")
            elif opname == "PREPVARARGS":
                output.append(f"{add_tab_space(depth + 1)}prepare_varargs({A})")
            elif opname == "LOADKX":
                if aux is not None:
                    k = proto['kTable'][aux] if aux < len(proto['kTable']) else {'type': "nil", 'value': "nil"}
                    output.append(f"{add_tab_space(depth + 1)}R{A} = {format_constant(k)}")
                else:
                    output.append(f"{add_tab_space(depth + 1)}R{A} = <invalid constant>")
            elif opname == "JUMPX":
                output.append(f"{add_tab_space(depth + 1)}goto [{(code_index + 1 + sAx) & 0xFF}]")
            elif opname == "FASTCALL1":
                output.append(f"{add_tab_space(depth + 1)}R{A} = fastcall1({B}, R{C})")
            elif opname == "FASTCALL2":
                if aux is not None:
                    output.append(f"{add_tab_space(depth + 1)}R{A} = fastcall2({B}, R{C}, R{aux})")
                else:
                    output.append(f"{add_tab_space(depth + 1)}R{A} = fastcall2({B}, R{C}, <invalid register>)")
            elif opname == "FASTCALL2K":
                if aux is not None:
                    k = proto['kTable'][aux] if aux < len(proto['kTable']) else {'type': "nil", 'value': "nil"}
                    output.append(f"{add_tab_space(depth + 1)}R{A} = fastcall2k({B}, R{C}, {format_constant(k)})")
                else:
                    output.append(f"{add_tab_space(depth + 1)}R{A} = fastcall2k({B}, R{C}, <invalid constant>)")
            elif opname == "NEWTABLE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = {{}}")
            elif opname == "DUPTABLE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = {{}}")
            elif opname == "SETLIST":
                output.append(f"{add_tab_space(depth + 1)}R{A}[{B}] = R{A+1} ... R{A+C}")
            elif opname == "CAPTURE":
                if A == 0:
                    output.append(f"{add_tab_space(depth + 1)}capture(upvalue, R{B})")
                else:
                    output.append(f"{add_tab_space(depth + 1)}capture(R{B})")
            elif opname == "NEWCLOSURE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = closure(proto[{Bx}])")
            elif opname == "DUPCLOSURE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = dupclosure(K{Bx})")
            elif opname == "PREPVARARGS":
                output.append(f"{add_tab_space(depth + 1)}prepare_varargs({A})")
            elif opname == "FORGPREP":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgprep(R{A}, {sBx})")
            elif opname == "FORGLOOP":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgloop(R{A}, {sBx})")
            elif opname == "FORGPREP_NEXT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgprep_next(R{A}, {sBx})")
            elif opname == "FORGPREP_INEXT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgprep_inext(R{A}, {sBx})")
            elif opname == "FORGLOOP_NEXT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgloop_next(R{A}, {sBx})")
            elif opname == "FORGLOOP_INEXT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgloop_inext(R{A}, {sBx})")
            elif opname == "GETVARARGS":
                output.append(f"{add_tab_space(depth + 1)}R{A}, ... = ..., ({B - 1} args)")
            elif opname == "JUMPX":
                output.append(f"{add_tab_space(depth + 1)}goto [{(code_index + 1 + sAx) & 0xFF}]")
            elif opname == "JUMPXEQKNIL":
                output.append(f"{add_tab_space(depth + 1)}if R{A} == nil then goto [{(code_index + 1 + sAx) & 0xFF}]")
            elif opname == "JUMPXEQKB":
                output.append(f"{add_tab_space(depth + 1)}if R{A} == {bool(Bx)} then goto [({code_index + 1 + sAx & 0xFF})]")
            elif opname == "JUMPXEQKN":
                output.append(f"{add_tab_space(depth + 1)}if R{A} == {aux} then goto [{(code_index + 2 + sAx) & 0xFF}]")
            elif opname == "JUMPXEQKS":
                if aux is not None and aux < len(stringTable):
                    output.append(f"{add_tab_space(depth + 1)}if R{A} == {repr(stringTable[aux])} then goto [{(code_index + 2 + sAx) & 0xFF}]")
                else:
                    output.append(f"{add_tab_space(depth + 1)}if R{A} == <invalid string> then goto [{(code_index + 2 + sAx) & 0xFF}]")
            elif opname == "IDIV":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} // R{C}")
            elif opname == "IDIVK":
                k = proto['kTable'][C] if C < len(proto['kTable']) else {'type': "nil", 'value': "nil"}
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} // {format_constant(k)}")
            elif opname == "BAND":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} & R{C}")
            elif opname == "BOR":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} | R{C}")
            elif opname == "BXOR":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} ~ R{C}")
            elif opname == "BNOT":
                output.append(f"{add_tab_space(depth + 1)}R{A} = ~R{B}")
            elif opname == "SHL":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} << R{C}")
            elif opname == "SHR":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} >> R{C}")
            elif opname == "BANDK":
                k = proto['kTable'][C] if C < len(proto['kTable']) else {'type': "nil", 'value': "nil"}
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} & {format_constant(k)}")
            elif opname == "BORK":
                k = proto['kTable'][C] if C < len(proto['kTable']) else {'type': "nil", 'value': "nil"}
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} | {format_constant(k)}")
            elif opname == "BXORK":
                k = proto['kTable'][C] if C < len(proto['kTable']) else {'type': "nil", 'value': "nil"}
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} ~ {format_constant(k)}")
            elif opname == "SHLI":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} << {C}")
            elif opname == "SHRI":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} >> {C}")
            elif opname == "GETUPVAL":
                output.append(f"{add_tab_space(depth + 1)}R{A} = U{B}")
            elif opname == "SETUPVAL":
                output.append(f"{add_tab_space(depth + 1)}U{B} = R{A}")
            elif opname == "CLOSEUPVALS":
                output.append(f"{add_tab_space(depth + 1)}close upvalues R{A}+")
            elif opname == "FASTCALL":
                output.append(f"{add_tab_space(depth + 1)}R{A} = fastcall({B}, {C})")
            elif opname == "COVERAGE":
                output.append(f"{add_tab_space(depth + 1)}coverage({aux})")
            elif opname == "BOOST":
                output.append(f"{add_tab_space(depth + 1)}boost({A})")
            elif opname == "CAPTURE":
                if A == 0:
                    output.append(f"{add_tab_space(depth + 1)}capture(upvalue, R{B})")
                else:
                    output.append(f"{add_tab_space(depth + 1)}capture(R{B})")
            else:
                output.append(f"{add_tab_space(depth + 1)}UNKNOWN OPCODE: {opname}")
        except Exception as e:
            output.append(f"{add_tab_space(depth + 1)}Error processing opcode: {str(e)}")

    output.append("end")
    return "\n".join(output)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python disassembler.py <bytecode_file>")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        bytecode = f.read()

    start = time.perf_counter()
    disassembled, decompiled, protos, LUAUVERSION = disassemble(bytecode)
    end = time.perf_counter()

    if DEBUG:
        print("\n".join(disassembled))
    disassembled_extra = "--<@ Disassembled with Koralys' BETA disassembler @>--\n"
    disassembled_extra += f"--<@ Protos: {protos} | {LUAUVERSION} @>--\n"
    disassembled_extra += f"--<@ Time taken: {end - start:.6f}s @>--\n"
    disassembled_str = "\n".join(disassembled)
    full_output = disassembled_extra + disassembled_str
    with open('output.txt', 'w', encoding='utf-8') as f:
        f.write(full_output)
    print(f"Disassembled bytecode in {end - start:.6f}s")
    flattened_decompiled = []
    for item in decompiled:
        if isinstance(item, list):
            flattened_decompiled.extend(item)
        else:
            flattened_decompiled.append(item)
    decompiled_str = "\n".join(flattened_decompiled)
    with open('decompiled.luau', 'w', encoding='utf-8') as f:
        f.write(decompiled_str)
    print("Decompiled disassembly")
