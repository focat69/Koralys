#!/usr/bin/env python3
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
        "Discord": @cephalocone, (1460413830394937477)
        "Github": ssynical
    })
    - DataModell ({
        "Discord": @datamodel (773207810120089600)
        "GitHub": DataM0del
    })

Turning on the `DEBUG` flag will slow down the decompilation process significantly.
0.000406s -> 0.002075s, around 5x slower
The `DEBUG` flag is meant for development purposes only. Turn off before using in production.

Issues:
    Decompiler is unfinished

Please contribute and fix these bugs and more that you may find.
"""

import sys
import time

from koralys import disassemble


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <bytecode_file>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        bytecode = f.read()

    start = time.perf_counter()
    disassembled, decompiled, protos, luau_version, types_version = disassemble(
        bytecode
    )
    end = time.perf_counter()

    from koralys.constants import DEBUG
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


if __name__ == "__main__":
    main()
