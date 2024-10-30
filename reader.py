from struct import unpack

class Reader:
    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.pos = 0

    def canRead(self, n: int) -> bool:
        return self.pos + n <= len(self.bytecode)

    def nextByte(self) -> int:
        if not self.canRead(1):
            raise IndexError(
                f"Attempted to read byte at position {self.pos}, but bytecode length is {len(self.bytecode)}"
            )
        v = self.bytecode[self.pos]
        self.pos += 1
        return v

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
        if not self.canRead(length):
            raise IndexError(
                f"Attempted to read string of length {length} at position {self.pos}, but bytecode length is {len(self.bytecode)}"
            )
        result = self.bytecode[self.pos : self.pos + length].decode("utf-8")
        self.pos += length
        return result

    def nextFloat(self) -> float:
        return self.unpackStruct(4, "Attempted to read float at position ", "<f")

    def nextDouble(self) -> float:
        return self.unpackStruct(8, "Attempted to read double at position ", "<d")

    # TODO Rename this here and in `nextUint32`, `nextFloat` and `nextDouble`
    def unpackStruct(self, n, arg1, format):
        if not self.canRead(n):
            raise IndexError(
                f"{arg1}{self.pos}, but bytecode length is {len(self.bytecode)}"
            )
        value = unpack(format, self.bytecode[self.pos : self.pos + n])[0]
        self.pos += n
        return value

    def skip(self, n: int) -> None:
        if not self.canRead(n):
            raise IndexError(
                f"Attempted to skip {n} bytes at position {self.pos}, but bytecode length is {len(self.bytecode)}"
            )
        self.pos += n

    def read(self, n: int) -> bytes:
        if not self.canRead(n):
            raise IndexError(
                f"Attempted to read {n} bytes at position {self.pos}, but bytecode length is {len(self.bytecode)}"
            )
        data = self.bytecode[self.pos : self.pos + n]
        self.pos += n
        return data