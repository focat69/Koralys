from struct import unpack
from typing import Optional, List, Tuple


class Reader:
    def __init__(self, bytecode: bytes):
        self.bytecode: bytes = bytecode
        self.pos: int = 0

    def canRead(self, n: int) -> bool:
        return self.pos + n <= len(self.bytecode)

    def nextByte(self) -> int:
        if not self.canRead(1):
            raise IndexError(
                f"Attempted to read byte at position {self.pos}, but bytecode length is {len(self.bytecode)}"
            )
        value = self.bytecode[self.pos]
        self.pos += 1
        return value

    def nextChar(self) -> str:
        return chr(self.nextByte())

    def nextUint32(self) -> int:
        return self.unpackStruct(4, "Attempted to read 4 bytes at position ", "<I")

    def nextInt(self) -> int:
        b = [self.nextByte() for _ in range(4)]
        return (b[3] << 24) | (b[2] << 16) | (b[1] << 8) | b[0]

    def nextVarInt(self) -> int:
        result = 0
        shift = 0
        while True:
            if not self.canRead(1):
                raise IndexError(
                    f"Unexpected end of bytecode while reading VarInt at position {self.pos}"
                )
            b = self.nextByte()
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result

    def nextString(self) -> str:
        length = self.nextVarInt()
        if length < 0:
            raise ValueError(f"Invalid string length {length} at position {self.pos}")
        if not self.canRead(length):
            raise IndexError(
                f"Attempted to read string of length {length} at position {self.pos}, but bytecode length is {len(self.bytecode)}"
            )
        result = self.bytecode[self.pos : self.pos + length].decode("utf-8", errors="replace")
        self.pos += length
        return result

    def nextFloat(self) -> float:
        return self.unpackStruct(4, "Attempted to read float at position ", "<f")

    def nextDouble(self) -> float:
        return self.unpackStruct(8, "Attempted to read double at position ", "<d")

    def unpackStruct(self, n: int, error_message: str, fmt: str) -> Optional[int | float]:
        if not self.canRead(n):
            raise IndexError(
                f"{error_message}{self.pos}, but bytecode length is {len(self.bytecode)}"
            )
        value = unpack(fmt, self.bytecode[self.pos : self.pos + n])[0]
        self.pos += n
        return value

    def skip(self, n: int) -> None:
        if n < 0:
            raise ValueError("Cannot skip a negative number of bytes.")
        if not self.canRead(n):
            raise IndexError(
                f"Attempted to skip {n} bytes at position {self.pos}, but bytecode length is {len(self.bytecode)}"
            )
        self.pos += n

    def read(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("Cannot read a negative number of bytes.")
        if not self.canRead(n):
            raise IndexError(
                f"Attempted to read {n} bytes at position {self.pos}, but bytecode length is {len(self.bytecode)}"
            )
        data = self.bytecode[self.pos : self.pos + n]
        self.pos += n
        return data

    def validateJumpTarget(self, target: int, max_instructions: int) -> None:
        """
        Validate a jump target to ensure it's within valid bounds.
        """
        if target < 0 or target >= max_instructions:
            raise ValueError(
                f"Invalid jump target {target}. Must be between 0 and {max_instructions - 1}."
            )

    def parseJumpTargets(self, instructions: List[Tuple[str, int]]) -> List[Tuple[str, int, Optional[str]]]:
        """
        Parses jump targets and associates labels with them.
        """
        max_instructions = len(instructions)
        labeled_instructions = []
        for idx, (opcode, operand) in enumerate(instructions):
            if opcode.startswith("JUMP"):
                label = f"::{operand}::" if 0 <= operand < max_instructions else None
                self.validateJumpTarget(operand, max_instructions)
                labeled_instructions.append((opcode, operand, label))
            else:
                labeled_instructions.append((opcode, operand, None))
        return labeled_instructions
