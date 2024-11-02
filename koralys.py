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

Issues:
    Makes everything a proto even if it isnt
    Does not show jump targets (eg. if code has goto [5] but only has 3 instructions, it doesnt show "::5::" and it's dism)
    Decompile is broken/really bad/unfinished
    No type checking
    Does not handle variables kindly

Please contribute and fix these bugs and more that you may find.
"""

import sys
import time
from typing import List, Dict, Tuple, Any
from reader import Reader
from luau import (
    get_opcode,
    get_arg_a,
    get_arg_b,
    get_arg_c,
    get_arg_Bx,
    get_arg_sBx,
    get_arg_sAx,
    get_op_table,
)

DEBUG = False  #! Will slow down the decompilation process significantly


def debug(*args, **kwargs):
    return print(*args, **kwargs) if DEBUG else None


# < CONSTANT TYPES > #
# https://github.com/luau-lang/luau/blob/db809395bf5739c895a24dc73960b9e9ab6468c5/Compiler/include/Luau/BytecodeBuilder.h#L151-L161
LBC_CONSTANT_NIL = 0
LBC_CONSTANT_BOOLEAN = 1
LBC_CONSTANT_NUMBER = 2
LBC_CONSTANT_STRING = 3
LBC_CONSTANT_IMPORT = 4
LBC_CONSTANT_TABLE = 5
LBC_CONSTANT_CLOSURE = 6
LBC_CONSTANT_VECTOR = 7


def deserialize_v5(
    reader: Reader,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str], int, int]:
    types_version = reader.nextByte()
    if types_version not in [1, 2, 3]:
        raise ValueError(f"Invalid types version (types version: {types_version})")

    proto_table: List[Dict[str, Any]] = []
    string_table: List[str] = []

    size_strings = reader.nextVarInt()
    string_table.extend(reader.nextString() for _ in range(size_strings))
    size_protos = reader.nextVarInt()
    proto_table.extend(create_empty_proto() for _ in range(size_protos))

    for i in range(size_protos):
        proto = proto_table[i]
        read_proto_data(reader, proto, string_table)

    mainProtoId = reader.nextVarInt()
    if mainProtoId >= len(proto_table):
        raise IndexError(
            f"Index {mainProtoId} out of range for protoTable with length {len(proto_table)}"
        )
    return proto_table[mainProtoId], proto_table, string_table, 5, types_version


def create_empty_proto() -> Dict[str, Any]:
    return {
        "codeTable": [],
        "kTable": [],
        "pTable": [],
        "smallLineInfo": [],
        "largeLineInfo": [],
    }


def read_proto_data(reader: Reader, proto: Dict[str, Any], string_table: List[str]):
    proto["maxStackSize"] = reader.nextByte()
    proto["numParams"] = reader.nextByte()
    proto["numUpValues"] = reader.nextByte()
    proto["isVarArg"] = reader.nextByte()
    proto["flags"] = reader.nextByte()
    typesize = reader.nextVarInt()
    type_info = [reader.nextByte() for _ in range(typesize)]
    proto["typeInfo"] = type_info

    proto["sizeCode"] = reader.nextVarInt()
    proto["codeTable"].extend(reader.nextInt() for _ in range(proto["sizeCode"]))

    proto["sizeConsts"] = reader.nextVarInt()
    proto["kTable"] = [
        read_constant(reader, string_table) for _ in range(proto["sizeConsts"])
    ]

    proto["sizeProtos"] = reader.nextVarInt()
    proto["pTable"] = proto["sizeProtos"] > 1 and [
        proto["pTable"][reader.nextVarInt() - 1] for _ in range(proto["sizeProtos"])
    ] or []

    proto["lineDefined"] = reader.nextVarInt()
    proto["source"] = read_proto_source(reader, string_table)

    if reader.nextByte() == 1:  # has line info?
        read_line_info(reader, proto)

    if reader.nextByte() == 1:  # has debug info?
        raise ValueError("only ROBLOX scripts can be disassembled")


def read_constant(reader: Reader, string_table: List[str]) -> Dict[str, Any]:
    k = {"type": reader.nextByte()}
    if k["type"] == LBC_CONSTANT_BOOLEAN:
        k["value"] = reader.nextByte() == 1
    elif k["type"] == LBC_CONSTANT_NUMBER:
        k["value"] = reader.nextDouble()
    elif k["type"] == LBC_CONSTANT_STRING:
        index = reader.nextVarInt() - 1
        k["value"] = (
            string_table[index]
            if 0 <= index < len(string_table)
            else "Invalid string index"
        )
    elif k["type"] == LBC_CONSTANT_IMPORT:
        k["value"] = reader.nextInt()
    elif k["type"] == LBC_CONSTANT_TABLE:
        k["value"] = {
            "size": reader.nextVarInt(),
            "ids": [reader.nextVarInt() + 1 for _ in range(reader.nextVarInt())],
        }
    elif k["type"] == LBC_CONSTANT_CLOSURE:
        k["value"] = reader.nextVarInt() + 1
    elif k["type"] == LBC_CONSTANT_VECTOR:
        k["value"] = [reader.nextFloat() for _ in range(4)]
    elif k["type"] != 0:
        raise ValueError(f"Unrecognized constant type: {k['type']}")
    return k


def read_proto_source(reader: Reader, string_table: List[str]) -> str:
    protoSourceId = reader.nextVarInt()
    return (
        string_table[protoSourceId]
        if protoSourceId < len(string_table)
        else "Invalid source index"
    )


def read_line_info(reader: Reader, proto: Dict[str, Any]):
    compKey = reader.nextByte()
    proto["smallLineInfo"] = [reader.nextByte() for _ in range(proto["sizeCode"])]
    intervals = ((proto["sizeCode"] - 1) >> compKey) + 1
    proto["largeLineInfo"] = [reader.nextInt() for _ in range(intervals)]


def parse_proto(
    reader: Reader, string_table: List[str], types_version: int
) -> Dict[str, Any]:
    proto: Dict[str, Any] = {
        "maxStackSize": reader.nextByte(),
        "numParams": reader.nextByte(),
        "numUpValues": reader.nextByte(),
        "isVarArg": reader.nextByte(),
        "flags": reader.nextByte(),
        "typeInfo": [],
        "codeTable": [],
        "kTable": [],
        "pTable": [],
        "lineInfo": None,
        "debugInfo": None,
        "source": "",
    }

    type_size = reader.nextVarInt()
    proto["typeInfo"] = [reader.nextByte() for _ in range(type_size)]

    size_code = reader.nextVarInt()
    debug(f"  Code size: {size_code}")
    proto["codeTable"] = [reader.nextUint32() for _ in range(size_code)]
    proto["sizeCode"] = size_code

    size_consts = reader.nextVarInt()
    debug(f"  Number of constants: {size_consts}")
    proto["kTable"] = [parse_constant(reader) for _ in range(size_consts)]

    size_protos = reader.nextVarInt()
    debug(f"  Number of child protos: {size_protos}")
    proto["pTable"] = [reader.nextVarInt() for _ in range(size_protos)]
    proto["numChildren"] = size_protos

    proto["lineDefined"] = reader.nextVarInt()

    proto_source_id = reader.nextVarInt()
    if 0 <= proto_source_id - 1 < len(string_table):
        proto["source"] = string_table[proto_source_id - 1]
    else:
        proto["source"] = f"Invalid source index: {proto_source_id}"

    if reader.nextByte() == 1:  # has line info?
        debug("  Proto has line info")
        proto["lineInfo"] = parse_line_info(reader, size_code)

    if reader.nextByte() == 1:  # has debug info?
        debug("  Proto has debug info")
        proto["debugInfo"] = parse_debug_info(reader, string_table)

    return proto


def parse_constant(reader: Reader) -> Dict[str, Any]:
    try:
        k = {"type": reader.nextByte()}
        constant_handlers = {
            LBC_CONSTANT_NIL: lambda: None,
            LBC_CONSTANT_BOOLEAN: lambda: reader.nextByte() == 1,
            LBC_CONSTANT_NUMBER: lambda: reader.nextDouble(),
            LBC_CONSTANT_STRING: lambda: reader.nextVarInt() - 1,
            LBC_CONSTANT_IMPORT: lambda: reader.nextUint32(),
            LBC_CONSTANT_TABLE: lambda: {
                "size": reader.nextVarInt(),
                "ids": [reader.nextVarInt() for _ in range(reader.nextVarInt())],
            },
            LBC_CONSTANT_CLOSURE: lambda: reader.nextVarInt(),
            LBC_CONSTANT_VECTOR: lambda: {
                "size": reader.nextVarInt(),
                "ids": [reader.nextVarInt() for _ in range(reader.nextVarInt())],
            },
        }
        if handler := constant_handlers[k["type"]]:
            k["value"] = handler()
        else:
            raise ValueError(f"Unknown constant type: {k['type']}")
    except IndexError as e:
        k["value"] = f"Error reading constant: {str(e)}"
    return k


def parse_line_info(reader: Reader, size_code: int) -> Dict[str, Any]:
    lineInfo = {"compKey": reader.nextByte(), "intervals": []}
    lineInfo["intervals"] = [reader.nextByte() for _ in range(size_code)]

    _ = (size_code + 3) & -4
    largeIntervals = ((size_code - 1) >> lineInfo["compKey"]) + 1

    lineInfo["intervals"].extend([reader.nextUint32() for _ in range(largeIntervals)])
    return lineInfo


def parse_debug_info(reader: Reader, string_table: List[str]) -> Dict[str, Any]:
    debug_info = {
        "varInfo": [],
        "upvalueInfo": [],
    }
    sizeVars = reader.nextVarInt()
    for _ in range(sizeVars):
        debug_info["varInfo"].append(
            {
                "name": string_table[reader.nextVarInt() - 1],
                "startpc": reader.nextVarInt(),
                "endpc": reader.nextVarInt(),
                "reg": reader.nextByte(),
            }
        )
    sizeUpvalues = reader.nextVarInt()
    debug_info["upvalueInfo"] = [
        string_table[reader.nextVarInt() - 1] for _ in range(sizeUpvalues)
    ]
    return debug_info


def deserialize(
    bytecode: bytes,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str], str]:
    reader = Reader(bytecode)
    version = reader.nextByte()
    debug(f"Bytecode version: {version}")
    if version == 5:
        return deserialize_v5(reader)
    elif version == 6:
        return deserialize_v6(reader)
    else:
        raise ValueError(f"Unsupported bytecode version: {version}")


def deserialize_v6(
    reader: Reader,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str], int, int]:
    types_version = reader.nextByte()
    if types_version not in [1, 2, 3]:
        raise ValueError(f"Invalid types version (types version: {types_version})")
    debug("Types version:", types_version)

    proto_table: List[Dict[str, Any]] = []
    string_table: List[str] = []
    size_strings = reader.nextVarInt()
    debug("# of strings:", size_strings)
    string_table.extend(reader.nextString() for _ in range(size_strings))
    reader.skip(1)
    size_protos = reader.nextVarInt()
    debug("# of protos:", size_protos)
    proto_table.extend(create_empty_proto() for _ in range(size_protos))

    for i in range(size_protos):
        proto = proto_table[i]
        read_proto_data(reader, proto, string_table)

    mainProtoId = reader.nextVarInt()
    if mainProtoId >= len(proto_table):
        raise IndexError(
            f"Index {mainProtoId} out of range for protoTable with length {len(proto_table)}"
        )
    return proto_table[mainProtoId], proto_table, string_table, 6, types_version


def read_proto(
    proto: Dict[str, Any],
    depth: int,
    proto_table: List[Dict[str, Any]],
    string_table: List[str],
    luau_version: int,
) -> str:
    OP_TABLE = get_op_table(luau_version)
    output = ""
    tab_space = "    " * (depth - 1)

    output += f"{tab_space}function({', '.join(['...' if proto['isVarArg'] else ''] + [f'R{i}' for i in range(proto['numParams'])])})\n"

    # opnameToOpcode = {info.name: info["number"] for info in OP_TABLE}
    opcodeToOpname = {
        info.number: info.name for info in OP_TABLE
    }
    max_opname_length = max(len(info.name) for info in OP_TABLE)

    # def get_opcode_from_name(opname: str) -> int:
    #     opcode = opnameToOpcode.get(opname)
    #     if opcode is None:
    #         raise ValueError(f"Unknown opname {opname}")
    #     return opcode

    codeIndex = 0
    while codeIndex < len(proto["codeTable"]):
        i = proto["codeTable"][codeIndex]
        opc = get_opcode(i)
        A = get_arg_a(i)
        B = get_arg_b(i)
        Bx = get_arg_Bx(i)
        C = get_arg_c(i)
        sBx = get_arg_sBx(i)
        sAx = get_arg_sAx(i)

        op_name = opcodeToOpname.get(opc, "UNKNOWN")
        output += f"{'    ' * depth}[{codeIndex:03}] {op_name:<{max_opname_length}} "

        aux = None
        if any(
            info.name == op_name and info.get("aux", False) for info in OP_TABLE
        ) and codeIndex + 1 < len(proto["codeTable"]):
            aux = proto["codeTable"][codeIndex + 1]
            codeIndex += 1

        def __CALL_handler(_):
            args = f"R{A+1}" + (f" ... R{A+B-1}" if B > 2 else "")
            returns = f"R{A}" + (f" ... R{A+C}" if C > 1 else "")
            return f"{returns} = R{A}({args})"

        def __CAPTURE_handler(_):
            capture_types = ["VAL", "REF", "UPVAL"]
            capture_type = (
                capture_types[A] if A < len(capture_types) else f"Unknown({A})"
            )
            return f"capture {capture_type} R{B}"

        def __GETIMPORT_handler(_):
            # https://github.com/luau-lang/luau/blob/0.631/Compiler/src/BytecodeBuilder.cpp#L913-L920
            # 100% not just ported to python
            def decompose_import_id(ids: int) -> tuple[int, List[int]]:
                count = ids >> 30
                id1 = (ids >> 20) & 1023 if count > 0 else None
                id2 = (ids >> 10) & 1023 if count > 1 else None
                id3 = ids & 1023 if count > 2 else None

                return count, [x for x in [id1, id2, id3] if x is not None]

            def import_id_to_name(ids: int) -> str:
                imported_path = ""
                _, ids = decompose_import_id(ids)

                for i, id_constant in enumerate(ids):
                    id_constant = proto["kTable"][id_constant]
                    assert (
                        id_constant["type"] == LBC_CONSTANT_STRING
                    ), f"ID Constant {i} ({id_constant}) isn't a string."
                    to_append = (
                        i > 0 and f".{id_constant['value']}" or id_constant["value"]
                    )
                    # kinda ew but it works
                    # also slow but I don't care lol
                    # this is Python, what do you expect?
                    imported_path += to_append

                return imported_path

            import_id = proto["kTable"][Bx]["value"]
            imported_path = import_id_to_name(import_id)
            return f"R{A} = {imported_path} -- Import ID: {import_id}"

        def jump_if_gen(
            op: str | None = None, invert: bool = False, k_mode: bool = False
        ):
            """Generates a conditional jump statement based on the provided operation.

            This function constructs a string representing a conditional jump in a specific format,
            allowing for optional inversion of the condition and handling of auxiliary values.
            The generated statement can be used in bytecode or intermediate representations.

            Args:
                op (str | None): The operator to include in the condition, or None for no operator.
                invert (bool): If True, inverts the condition in the generated statement.
                k_mode (bool): If True, appends `K` before the index,
                               use this with operations like `JUMPIFEQK`,
                               usually where the operation ends in `K`.

            Returns:
                str: A formatted string representing the conditional jump statement.
            """
            pre_op = " not " if invert else " "
            jump = opcode_handlers["JUMP"]("JUMP")
            after_cond = op and f" {op} {k_mode and f'K{aux}' or aux} " or " "
            return f"if{pre_op}R{A}{after_cond}then {jump}"

        def __LOADKX_handler(_):
            k = proto["kTable"][aux] if aux < len(proto["kTable"]) else {"type": "nil", "value": "nil"}
            return f"R{A} = {repr(k['value']) if isinstance(k['value'], str) else k['value']}"

        opcode_handlers = {
            "NOP": lambda _: "-- do nothing (no-op / NOP)",
            "BREAK": lambda _: "break",
            "PREPVARARGS": lambda _: f"(adjust vararg params, {A} fixed params)",
            "LOADNIL": lambda _: f"R{A} = nil",
            "LOADB": lambda _: f"R{A} = {bool(B)}; "
            + (f"goto [{codeIndex + C + 1}]" if C != 0 else ""),
            "LOADN": lambda _: f"R{A} = {Bx}",
            "LOADK": lambda _: f"R{A} = {Bx}",
            "MOVE": lambda _: f"R{A} = R{B}",
            "GETGLOBAL": lambda _: f"R{A} = _G[{repr(string_table[aux])}]"
            if aux is not None and aux < len(string_table)
            else f"R{A} = _G[Invalid string index]",
            "SETGLOBAL": lambda _: f"_G[{repr(string_table[aux])}]"
            if aux is not None and aux < len(string_table)
            else f"_G[Invalid string index] = R{A}",
            "GETUPVAL": lambda _: f"R{A} = U{B}",
            "SETUPVAL": lambda _: f"U{B} = R{A}",
            "CLOSEUPVALS": lambda _: f"close upvalues R{A}+",
            "GETIMPORT": __GETIMPORT_handler,
            "GETTABLE": lambda _: f"R{A} = R{B}[R{C}]",
            "SETTABLE": lambda _: f"R{A} = R{B}[R{C}]",
            "GETTABLEKS": lambda _: f"R{A} = R{B}[{repr(string_table[aux])}"
            if aux is not None and aux < len(string_table)
            else f"R{A} = R{B}[Invalid string index]",
            "SETTABLEKS": lambda _: f"R{B}[{repr(string_table[aux - 1])}] = R{A}"
            if aux is not None and aux - 1 < len(string_table)
            else f"R{B}[Invalid string index] = R{A}",
            "GETTABLEN": lambda _: f"R{A} = R{B}[{C + 1}]",
            "SETTABLEN": lambda _: f"R{B}[{C + 1}] = R{A}",
            "NEWCLOSURE": lambda _: f"R{A} = closure(proto[{Bx}])",
            "NAMECALL": lambda _: f"R{A} = R{B}[{repr(string_table[aux])}; R{A+1} = R{B}"
            if aux is not None and aux < len(string_table)
            else f"R{A} = R{B}[Invalid String Index]; R{A+1} = R{B}",
            "CALL": __CALL_handler,
            "RETURN": lambda _: f"return R{A} ..."
            if B == 0
            else "return"
            if B == 1
            else f"return R{A} ... R{A+B-2}",
            "JUMP": lambda _: f"goto [{(codeIndex + 1 + sBx) & 0xFF}]",
            "JUMPBACK": lambda _: f"goto [{(codeIndex + 1 - sBx) & 0xFF}]",
            "JUMPX": lambda _: f"goto [{(codeIndex + 1 + sAx) & 0xFF}]",
            "FASTCALL": lambda _: f"R{A} = builtin[{C}]",
            "FASTCALL3": lambda _: f"R{A} = builtin[{C}]",
            "COVERAGE": lambda _: "(coverage)",
            "CAPTURE": __CAPTURE_handler,
            "JUMPIFEQK": lambda _: jump_if_gen("==", k_mode=True),
            "FORNPREP": lambda _: f"R{A} -= R{A+2}; goto [{(codeIndex + 1 + Bx) & 0xFF}]",
            "FORNLOOP": lambda _: f"R{A} += R{A+2}; if R{A} <= R{A+1} then goto [{(codeIndex + 1 - Bx) & 0xFF}]; R{A+3} = R{A}",
            "MINUS": lambda _: f"R{A} = -R{B}",
            "LENGTH": lambda _: f"R{A} = #R{B}",
            # https://github.com/luau-lang/luau/blob/a251bc68a2b70212e53941fd541d16ce523a1e01/Compiler/src/BytecodeBuilder.cpp#L2134-L2136
            "NEWTABLE": lambda _: f"R{A} = table with {(B == 0 and 0 or 1 << max(0, B - 1)) + 1} entries",
            "DUPTABLE": lambda _: f"R{A} = R{B} -- duplicate",
            "SETLIST": lambda _: f"R{A}[{C}] = R{A+1} ... R{A+B}",
            "CONCAT": lambda _: f"R{A} = R{B} .. R{C}",
            "NOT": lambda _: f"R{A} = not R{B}",
            "FORGPREP": lambda _: f"R{A} = R{A+1}; R{A+1} = R{A+2}; R{A+2} = R{A+3}; R{A+3} = nil; goto [{(codeIndex + 1 + Bx) & 0xFF}]",
            "FORGLOOP": lambda _: f"R{A+3}, ..., R{A+2+C} = R{A}(R{A+1}, R{A+2}); if R{A+3} ~= nil then R{A+2} = R{A+3}; goto [{(codeIndex + 1 - Bx) & 0xFF}]",
            "FORGPREP_INEXT": lambda _: f"R{A} = next; goto [{(codeIndex + 1 + B) & 0xFF}]",
            "NATIVECALL": lambda _: "Unimplemented",
            # (yes, `B - 1` can return -1, but the Luau disassembler does this so hopefully it's fine)
            # https://github.com/luau-lang/luau/blob/a251bc68a2b70212e53941fd541d16ce523a1e01/Compiler/src/BytecodeBuilder.cpp#L2171-L2173
            "GETVARARGS": lambda _: f"R{A} = {B - 1}",
            "DUPCLOSURE": lambda _: f"R{A} = K{Bx} -- duplicate",
            "LOADKX": __LOADKX_handler,
            "FORGPREP_NEXT": lambda _: f"R{A} = next; goto [{(codeIndex + 1 + B) & 0xFF}]",
        }

        for condition in ["EQ", "LE", "LT", None]:
            opcode_handlers[f"JUMPIF{condition or ''}"] = lambda _: jump_if_gen(condition)
            opcode_handlers[f"JUMPIFNOT{condition or ''}"] = lambda _: jump_if_gen(condition, True)

        for gen_op_name in ["AND", "OR"]:
            def __gen_op_handler(gen_op_name: str):
                op = "and" if gen_op_name.startswith("AND") else "or"
                if gen_op_name.endswith("K"):
                    k = (
                        proto["kTable"][C]
                        if C < len(proto["kTable"])
                        else {"type": "nil", "value": "nil"}
                    )
                    return f"R{A} = R{B} {op} "\
                        f"{repr(k['value']) if isinstance(k['value'], str) else k['value']}"
                else:
                    return f"R{A} = R{B} {op} R{C} "\
                        f"{repr(k['value']) if isinstance(k['value'], str) else k['value']}"
            opcode_handlers[gen_op_name] = __gen_op_handler
            opcode_handlers[f"{gen_op_name}K"] = __gen_op_handler

        math_ops = {
            "ADD": "+",
            "SUB": "-",
            "MUL": "*",
            "DIV": "/",
            "MOD": "%",
            "POW": "^",
        }

        for gen_op_name in ["SUBRK", "DIVRK"]:
            opcode_handlers[gen_op_name] = lambda op: f"R{A} = R{A} {math_ops[op[:-2]]} R{C}"


        for gen_op_name in ["ADD", "SUB", "MUL", "DIV", "MOD", "POW"]:
            opcode_handlers[gen_op_name] = (
                lambda opcode: f"R{A} = R{B} {math_ops[opcode]} R{C}"
            )

            def __gen_op_handler(opcode):
                op = math_ops[opcode[:-1]]
                k = (
                    proto["kTable"][C]
                    if C < len(proto["kTable"])
                    else {"type": "nil", "value": "nil"}
                )
                return f"R{A} = R{B} {op} {repr(k['value']) if isinstance(k['value'], str) else k['value']}"

            opcode_handlers[f"{gen_op_name}K"] = __gen_op_handler

        if op_name in opcode_handlers:
            output += opcode_handlers[op_name](op_name)
        else:
            output += f"Unknown opcode: {opc}"

        output += "\n"
        codeIndex += 1

    output += "end\n"

    if len(proto["kTable"]) > 0:
        output += "--< Constants >--\n"
        constant_types = {
            LBC_CONSTANT_NIL: "nil",
            LBC_CONSTANT_BOOLEAN: lambda k: str(k["value"]).lower(),
            LBC_CONSTANT_NUMBER: lambda k: k["value"],
            LBC_CONSTANT_STRING: lambda k: repr(k["value"]),
            LBC_CONSTANT_IMPORT: lambda k: k["value"],
            LBC_CONSTANT_TABLE: lambda k: k["value"],
            LBC_CONSTANT_CLOSURE: lambda k: k["value"],
            LBC_CONSTANT_VECTOR: lambda k: k["value"],
        }
        for i, k in enumerate(proto["kTable"]):
            value = constant_types.get(
                k["type"], lambda k: f"Unknown constant type: {k['type']}"
            )(k)
            output += f"{'    ' * depth}[{i}] = {value}\n"

    if "sizeProtos" in proto and proto["sizeProtos"] > 1:
        output += "--< Protos >--\n"
        for i, p in enumerate(proto["pTable"]):
            output += f"{'    ' * depth}[{i}] = {read_proto(p, depth + 1, proto_table, string_table, luau_version)}\n"

    if proto["numUpValues"] > 0:
        output += "--< Upvalues >--\n"
        for i in range(proto["numUpValues"]):
            output += f"{'    ' * depth}[{i}] = Upvalue {i}\n"

    return output


def disassemble(bytecode: bytes) -> Tuple[List[str], List[str], int, str]:
    output = []
    decompiled_output = []

    if bytecode[0] == 0:
        return [bytecode[1:].decode("utf-8")], [], 0, -1, -1

    mainProto, protoTable, stringTable, luau_version, types_version = deserialize(
        bytecode
    )

    protos = 0
    for i, proto in enumerate(protoTable):
        output.extend(
            (
                f"--< Proto->{i:03} | Line {proto.get('lineDefined', 0)} >--",
                read_proto(proto, 1, protoTable, stringTable, luau_version),
            )
        )
        decompiled_output.extend(
            (
                f"-- Decompiled Proto->{i:03} --",
                decompile(proto, 1, stringTable, luau_version),
            )
        )
        protos += 1

    return output, decompiled_output, protos, luau_version, types_version


def decompile(
    proto: Dict[str, Any], depth: int, stringTable: List[str], luau_version: int
) -> str:
    # Removed redundant variables, fixed jumps and cleaned up the output - focat
    # its still shit btw LMAO but some what better
    output = []

    def add_tab_space(depth):
        return "    " * depth

    output.append(f"local function func{depth}({proto['isVarArg'] and '...' or ''})")

    # opname_to_opcode = {info['name']: info['number'] for info in luau_op_table}
    opcode_to_opname = {
        info["number"]: info.name for info in get_op_table(luau_version)
    }

    # def get_opcode(opname: str) -> int:
    #     return opname_to_opcode.get(opname, -1)

    def format_constant(k):
        if isinstance(k, dict):
            if k["type"] == 3:  # String
                return repr(k["value"])
            elif k["type"] in [1, 2]:  # Number
                return str(k["value"])
            else:
                return str(k["value"])
        return str(k)

    for code_index, i in enumerate(proto["codeTable"]):
        try:
            opc = get_opcode(i)
            A = get_arg_a(i)
            B = get_arg_b(i)
            Bx = get_arg_Bx(i)
            C = get_arg_c(i)
            sBx = get_arg_sBx(i)
            sAx = get_arg_sAx(i)
            aux = (
                proto["codeTable"][code_index + 1]
                if code_index + 1 < len(proto["codeTable"])
                else None
            )

            opname = opcode_to_opname.get(opc, "UNKNOWN")

            if opname == "LOADNIL":
                output.append(f"{add_tab_space(depth + 1)}R{A} = nil")
            elif opname == "LOADB":
                output.append(f"{add_tab_space(depth + 1)}R{A} = {bool(B)}")
                if C != 0:
                    output.append(
                        f"{add_tab_space(depth + 1)}goto [{code_index + 1 + C}]"
                    )
            elif opname == "LOADN":
                output.append(f"{add_tab_space(depth + 1)}R{A} = {sBx}")
            elif opname == "LOADK":
                if Bx < len(proto["kTable"]):
                    k = proto["kTable"][Bx]
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = {format_constant(k)}"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = <invalid index {Bx}>"
                    )
            elif opname == "MOVE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B}")
            elif opname == "GETGLOBAL":
                if aux is not None and aux < len(stringTable):
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = _G[{repr(stringTable[aux])}]"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = _G[Invalid string index]"
                    )
            elif opname == "SETGLOBAL":
                if aux is not None and aux < len(stringTable):
                    output.append(
                        f"{add_tab_space(depth + 1)}_G[{repr(stringTable[aux])}] = R{A}"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}_G[Invalid string index] = R{A}"
                    )
            elif opname == "GETUPVAL":
                output.append(f"{add_tab_space(depth + 1)}R{A} = U{B}")
            elif opname == "SETUPVAL":
                output.append(f"{add_tab_space(depth + 1)}U{B} = R{A}")
            elif opname == "CLOSEUPVALS":
                output.append(f"{add_tab_space(depth + 1)}close upvalues R{A}+")
            elif opname == "GETIMPORT":
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = {proto['kTable'][Bx]['value']}"
                )
            elif opname == "GETTABLE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B}[R{C}]")
            elif opname == "SETTABLE":
                output.append(f"{add_tab_space(depth + 1)}R{B}[R{C}] = R{A}")
            elif opname == "GETTABLEKS":
                if aux is not None and aux < len(stringTable):
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = R{B}[{repr(stringTable[aux])}]"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = R{B}[Invalid string index]"
                    )
            elif opname == "SETTABLEKS":
                if aux is not None and aux < len(stringTable):
                    output.append(
                        f"{add_tab_space(depth + 1)}R{B}[{repr(stringTable[aux])}] = R{A}"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{B}[Invalid string index] = R{A}"
                    )
            elif opname == "GETTABLEN":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B}[{C + 1}]")
            elif opname == "SETTABLEN":
                output.append(f"{add_tab_space(depth + 1)}R{B}[{C + 1}] = R{A}")
            elif opname == "NEWCLOSURE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = closure(proto[{Bx}])")
            elif opname == "NAMECALL":
                if aux is not None and aux < len(stringTable):
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = R{B}[{repr(stringTable[aux])}]; R{A+1} = R{B}"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = R{B}[Invalid string index]; R{A+1} = R{B}"
                    )
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
                target = (
                    code_index + 1 + sBx if opname == "JUMP" else code_index + 1 - sBx
                )
                target &= 0xFF
                output.append(f"{add_tab_space(depth + 1)}goto [{target}]")
            elif opname in ["JUMPIF", "JUMPIFNOT"]:
                condition = "" if opname == "JUMPIF" else "not "
                output.append(
                    f"{add_tab_space(depth + 1)}if {condition}R{A} then goto [{(code_index + 1 + sBx) & 0xFF}]"
                )
            elif opname in [
                "JUMPIFEQ",
                "JUMPIFLE",
                "JUMPIFLT",
                "JUMPIFNOTEQ",
                "JUMPIFNOTLE",
                "JUMPIFNOTLT",
            ]:
                op = {
                    "JUMPIFEQ": "==",
                    "JUMPIFLE": "<=",
                    "JUMPIFLT": "<",
                    "JUMPIFNOTEQ": "~=",
                    "JUMPIFNOTLE": ">",
                    "JUMPIFNOTLT": ">=",
                }[opname]
                output.append(
                    f"{add_tab_space(depth + 1)}if R{A} {op} {aux} then goto [{(code_index + 2 + sBx) & 0xFF}]"
                )
            elif opname in [
                "ADD",
                "SUB",
                "MUL",
                "DIV",
                "MOD",
                "POW",
                "ADDK",
                "SUBK",
                "MULK",
                "DIVK",
                "MODK",
                "POWK",
            ]:
                op = {
                    "ADD": "+",
                    "SUB": "-",
                    "MUL": "*",
                    "DIV": "/",
                    "MOD": "%",
                    "POW": "^",
                    "ADDK": "+",
                    "SUBK": "-",
                    "MULK": "*",
                    "DIVK": "/",
                    "MODK": "%",
                    "POWK": "^",
                }[opname]
                if opname.endswith("K"):
                    k = (
                        proto["kTable"][C]
                        if C < len(proto["kTable"])
                        else {"type": "nil", "value": "nil"}
                    )
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = R{B} {op} {format_constant(k)}"
                    )
                else:
                    output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} {op} R{C}")
            elif opname in ["AND", "OR", "ANDK", "ORK"]:
                op = "and" if opname.startswith("AND") else "or"
                if opname.endswith("K"):
                    k = (
                        proto["kTable"][C]
                        if C < len(proto["kTable"])
                        else {"type": "nil", "value": "nil"}
                    )
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = R{B} {op} {format_constant(k)}"
                    )
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
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = fastcall2({B}, R{C}, {aux})"
                )
            elif opname == "FASTCALL2K":
                k = (
                    proto["kTable"][aux]
                    if aux < len(proto["kTable"])
                    else {"type": "nil", "value": "nil"}
                )
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = fastcall2k({B}, R{C}, {format_constant(k)})"
                )
            elif opname == "FORGLOOP":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgloop(R{A}, {sBx})")
            elif opname == "FORGLOOP_INEXT":
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = forgloop_inext(R{A}, {sBx})"
                )
            elif opname == "FORGLOOP_NEXT":
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = forgloop_next(R{A}, {sBx})"
                )
            elif opname == "FORGPREP":
                output.append(f"{add_tab_space(depth + 1)}R{A} = forgprep(R{A}, {sBx})")
            elif opname == "FORGPREP_INEXT":
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = forgprep_inext(R{A}, {sBx})"
                )
            elif opname == "FORGPREP_NEXT":
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = forgprep_next(R{A}, {sBx})"
                )
            elif opname == "GETVARARGS":
                output.append(
                    f"{add_tab_space(depth + 1)}R{A}, ... = ..., ({B - 1} args)"
                )
            elif opname == "DUPCLOSURE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = dupclosure(K{Bx})")
            elif opname == "PREPVARARGS":
                pass
            elif opname == "LOADKX":
                if aux is not None:
                    k = (
                        proto["kTable"][aux]
                        if aux < len(proto["kTable"])
                        else {"type": "nil", "value": "nil"}
                    )
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = {format_constant(k)}"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = <invalid constant>"
                    )
            elif opname == "JUMPX":
                output.append(
                    f"{add_tab_space(depth + 1)}goto [{(code_index + 1 + sAx) & 0xFF}]"
                )
            elif opname == "FASTCALL1":
                output.append(f"{add_tab_space(depth + 1)}R{A} = fastcall1({B}, R{C})")
            elif opname == "FASTCALL2":
                if aux is not None:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = fastcall2({B}, R{C}, R{aux})"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = fastcall2({B}, R{C}, <invalid register>)"
                    )
            elif opname == "FASTCALL2K":
                if aux is not None:
                    k = (
                        proto["kTable"][aux]
                        if aux < len(proto["kTable"])
                        else {"type": "nil", "value": "nil"}
                    )
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = fastcall2k({B}, R{C}, {format_constant(k)})"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = fastcall2k({B}, R{C}, <invalid constant>)"
                    )
            elif opname == "NEWTABLE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = {{}}")
            elif opname == "DUPTABLE":
                output.append(f"{add_tab_space(depth + 1)}R{A} = {{}}")
            elif opname == "SETLIST":
                output.append(
                    f"{add_tab_space(depth + 1)}R{A}[{B}] = R{A+1} ... R{A+C}"
                )
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
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = forgprep_next(R{A}, {sBx})"
                )
            elif opname == "FORGPREP_INEXT":
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = forgprep_inext(R{A}, {sBx})"
                )
            elif opname == "FORGLOOP_NEXT":
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = forgloop_next(R{A}, {sBx})"
                )
            elif opname == "FORGLOOP_INEXT":
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = forgloop_inext(R{A}, {sBx})"
                )
            elif opname == "GETVARARGS":
                output.append(
                    f"{add_tab_space(depth + 1)}R{A}, ... = ..., ({B - 1} args)"
                )
            elif opname == "JUMPX":
                output.append(
                    f"{add_tab_space(depth + 1)}goto [{(code_index + 1 + sAx) & 0xFF}]"
                )
            elif opname == "JUMPXEQKNIL":
                output.append(
                    f"{add_tab_space(depth + 1)}if R{A} == nil then goto [{(code_index + 1 + sAx) & 0xFF}]"
                )
            elif opname == "JUMPXEQKB":
                output.append(
                    f"{add_tab_space(depth + 1)}if R{A} == {bool(Bx)} then goto [({code_index + 1 + sAx & 0xFF})]"
                )
            elif opname == "JUMPXEQKN":
                output.append(
                    f"{add_tab_space(depth + 1)}if R{A} == {aux} then goto [{(code_index + 2 + sAx) & 0xFF}]"
                )
            elif opname == "JUMPXEQKS":
                if aux is not None and aux < len(stringTable):
                    output.append(
                        f"{add_tab_space(depth + 1)}if R{A} == {repr(stringTable[aux])} then goto [{(code_index + 2 + sAx) & 0xFF}]"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}if R{A} == <invalid string> then goto [{(code_index + 2 + sAx) & 0xFF}]"
                    )
            elif opname == "IDIV":
                output.append(f"{add_tab_space(depth + 1)}R{A} = R{B} // R{C}")
            elif opname == "IDIVK":
                k = (
                    proto["kTable"][C]
                    if C < len(proto["kTable"])
                    else {"type": "nil", "value": "nil"}
                )
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = R{B} // {format_constant(k)}"
                )
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
                k = (
                    proto["kTable"][C]
                    if C < len(proto["kTable"])
                    else {"type": "nil", "value": "nil"}
                )
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = R{B} & {format_constant(k)}"
                )
            elif opname == "BORK":
                k = (
                    proto["kTable"][C]
                    if C < len(proto["kTable"])
                    else {"type": "nil", "value": "nil"}
                )
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = R{B} | {format_constant(k)}"
                )
            elif opname == "BXORK":
                k = (
                    proto["kTable"][C]
                    if C < len(proto["kTable"])
                    else {"type": "nil", "value": "nil"}
                )
                output.append(
                    f"{add_tab_space(depth + 1)}R{A} = R{B} ~ {format_constant(k)}"
                )
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
            output.append(
                f"{add_tab_space(depth + 1)}Error processing opcode: {str(e)}"
            )

    output.append("end")
    return "\n".join(output)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python disassembler.py <bytecode_file>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        bytecode = f.read()

    start = time.perf_counter()
    disassembled, decompiled, protos, luau_version, types_version = disassemble(
        bytecode
    )
    end = time.perf_counter()

    if DEBUG:
        print("\n".join(disassembled))
    disassembled_extra = "--<@ Disassembled with Koralys' BETA disassembler @>--\n"
    versions = (
        f"Luau version {luau_version}, types version {types_version}"
        if luau_version != -1
        else f"Luau version unknown, types version {types_version}"
        if types_version != -1
        else "Types version unknown, luau version unknown"
    )
    disassembled_extra += f"--<@ Protos: {protos} | {versions} @>--\n"
    disassembled_extra += f"--<@ Time taken: {end - start:.6f}s @>--\n"
    disassembled_str = "\n".join(disassembled)
    full_output = disassembled_extra + disassembled_str
    with open("output.txt", "w", encoding="utf-8") as f:
        f.write(full_output)
    print(f"Disassembled bytecode in {end - start:.6f}s")
    flattened_decompiled = []
    for item in decompiled:
        if isinstance(item, list):
            flattened_decompiled.extend(item)
        else:
            flattened_decompiled.append(item)
    decompiled_str = "\n".join(flattened_decompiled)
    with open("decompiled.luau", "w", encoding="utf-8") as f:
        f.write(decompiled_str)
    print("Decompiled disassembly")
