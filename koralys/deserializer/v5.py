from typing import List, Dict, Any, Tuple

from koralys.reader import Reader
from koralys.constants import debug
from koralys.deserializer.common import create_empty_proto, read_proto_data


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
    if types_version >= 3: # this is only in types version 3
        # if you don't know what this is, I didn't too.
        # look here:
        # https://github.com/MaximumADHD/RCT-Source/blob/6aa8566bb7d91d3b22b89e74ff2ff89e911daad2/src/Luau/LuauDisassembly.cs#L75-L81
        # an index??? ok...
        # basically pasted from there anyways
        index = reader.nextByte()

        while index != 0:
            index = reader.nextByte()
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
