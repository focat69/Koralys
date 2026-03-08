from typing import Dict, Any, List, Tuple

from koralys.reader import Reader
from koralys.constants import debug
from koralys.deserializer.v5 import deserialize_v5
from koralys.deserializer.v6 import deserialize_v6


def deserialize(
    bytecode: bytes,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str], int, int]:
    reader = Reader(bytecode)
    version = reader.nextByte()
    debug(f"Bytecode version: {version}")
    if version == 5:
        return deserialize_v5(reader)
    elif version == 6:
        return deserialize_v6(reader)
    else:
        raise ValueError(f"Unsupported bytecode version: {version}")
