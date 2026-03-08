from typing import List, Dict, Any

from koralys.reader import Reader
from koralys.constants import (
    LBC_CONSTANT_NIL,
    LBC_CONSTANT_BOOLEAN,
    LBC_CONSTANT_NUMBER,
    LBC_CONSTANT_STRING,
    LBC_CONSTANT_IMPORT,
    LBC_CONSTANT_TABLE,
    LBC_CONSTANT_CLOSURE,
    LBC_CONSTANT_VECTOR,
    debug,
)


def create_empty_proto() -> Dict[str, Any]:
    return {
        "codeTable": [],
        "kTable": [],
        "pTable": [],
        "smallLineInfo": [],
        "largeLineInfo": [],
        "debugInfo": None,
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
    debug(f"v5: kTable for proto has {len(proto['kTable'])} constants:")
    for idx, const in enumerate(proto["kTable"]):
        debug(f"  [{idx}] type={const.get('type', '?')}, value={const.get('value', 'MISSING')}")
 
    proto["sizeProtos"] = reader.nextVarInt()
    proto["pTable"] = [reader.nextVarInt() for _ in range(proto["sizeProtos"])]
 
    proto["lineDefined"] = reader.nextVarInt()
    proto["source"] = read_proto_source(reader, string_table)
 
    if reader.nextByte() == 1:  # has line info?
        read_line_info(reader, proto)
 
    if reader.nextByte() == 1:  # has debug info?
        proto["debugInfo"] = read_debug_info(reader, string_table)


def read_debug_info(reader: Reader, string_table: List[str]) -> Dict[str, Any]:
    """Parse debug info (local variable names + upvalue names) from bytecode
    The format is the same for v5 and v6: varInfo entries then upvalue name entries"""
    debug_info = {
        "varInfo": [],
        "upvalueInfo": [],
    }
    sizeVars = reader.nextVarInt()
    for _ in range(sizeVars):
        name_idx = reader.nextVarInt()
        name = string_table[name_idx - 1] if 0 < name_idx <= len(string_table) else f"<var_{name_idx}>"
        debug_info["varInfo"].append({
            "name": name,
            "startpc": reader.nextVarInt(),
            "endpc": reader.nextVarInt(),
            "reg": reader.nextByte(),
        })
    sizeUpvalues = reader.nextVarInt()
    for _ in range(sizeUpvalues):
        uv_idx = reader.nextVarInt()
        uv_name = string_table[uv_idx - 1] if 0 < uv_idx <= len(string_table) else f"<uv_{uv_idx}>"
        debug_info["upvalueInfo"].append(uv_name)
    return debug_info


def read_constant(reader: Reader, string_table: List[str]) -> Dict[str, Any]:
    pos_before = reader.pos
    k = {"type": reader.nextByte()}
    if k["type"] == LBC_CONSTANT_NIL:
        k["value"] = None
    elif k["type"] == LBC_CONSTANT_BOOLEAN:
        k["value"] = reader.nextByte() == 1
    elif k["type"] == LBC_CONSTANT_NUMBER:
        k["value"] = reader.nextDouble()
    elif k["type"] == LBC_CONSTANT_STRING:
        raw_index = reader.nextVarInt()
        index = raw_index - 1
        k["value"] = (
            string_table[index]
            if 0 <= index < len(string_table)
            else "Invalid string index"
        )
    elif k["type"] == LBC_CONSTANT_IMPORT:
        k["value"] = reader.nextInt()
    elif k["type"] == LBC_CONSTANT_TABLE:
        size = reader.nextVarInt()
        k["value"] = {
            "size": size,
            "ids": [reader.nextVarInt() for _ in range(size)],
        }
    elif k["type"] == LBC_CONSTANT_CLOSURE:
        k["value"] = reader.nextVarInt()
    elif k["type"] == LBC_CONSTANT_VECTOR:
        k["value"] = [reader.nextFloat() for _ in range(4)]
    elif k["type"] != 0:
        raise ValueError(f"Unrecognized constant type: {k['type']}")
    pos_after = reader.pos
    return k


def read_proto_source(reader: Reader, string_table: List[str]) -> str:
    """Read the proto's debugname (1-based string table index, 0 = no name)"""
    protoSourceId = reader.nextVarInt()
    # protoSourceId is 1-based (0 means no debug name); subtract 1 to get 0-based index
    index = protoSourceId - 1
    if index < 0:
        return ""  # no debug name (top-level chunk or anonymous function)
    return (
        string_table[index]
        if index < len(string_table)
        else f"Invalid source index: {protoSourceId}"
    )


def read_line_info(reader: Reader, proto: Dict[str, Any]):
    compKey = reader.nextByte()
    proto["lineGapLog2"] = compKey
    proto["smallLineInfo"] = [reader.nextByte() for _ in range(proto["sizeCode"])]
    intervals = ((proto["sizeCode"] - 1) >> compKey) + 1
    proto["largeLineInfo"] = [reader.nextInt() for _ in range(intervals)]
