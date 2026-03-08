from typing import List, Dict, Any

from koralys.luau import (
    get_opcode,
    get_arg_a,
    get_arg_b,
    get_arg_c,
    get_arg_Bx,
    get_arg_sBx,
    get_arg_sAx,
    get_op_table,
)


def decompile(
    proto: Dict[str, Any], depth: int, stringTable: List[str], luau_version: int
) -> str:
    # Removed redundant variables, fixed jumps and cleaned up the output - focat
    # its still shit btw LMAO but some what better
    output = []
    OP_TABLE = get_op_table(luau_version)

    def add_tab_space(depth):
        return "    " * depth

    output.append(f"local function func{depth}({proto['isVarArg'] and '...' or ''})")

    # opname_to_opcode = {info['name']: info['number'] for info in luau_op_table}
    opcode_to_opname = {
        info["number"]: info.name for info in OP_TABLE
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

    code_index = 0
    while code_index < len(proto["codeTable"]):
        try:
            i = proto["codeTable"][code_index]
            opc = get_opcode(i)
            opname = opcode_to_opname.get(opc, "UNKNOWN")
            A = get_arg_a(i)
            B = get_arg_b(i)
            Bx = get_arg_Bx(i)
            C = get_arg_c(i)
            sBx = get_arg_sBx(i)
            sAx = get_arg_sAx(i)
            aux = (
                proto["codeTable"][code_index + 1]
                if any(info.name == opname and \
                        info.get("aux", False) for info in OP_TABLE) \
                and code_index + 1 < len(proto["codeTable"])
                else None
            )
            if aux is not None:
                code_index += 1

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
                if aux is not None and aux < len(proto['kTable']):
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = _G[{repr(proto['kTable'][aux]['value'])}]"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = _G[Invalid constant index]"
                    )
            elif opname == "SETGLOBAL":
                if aux is not None and aux < len(proto['kTable']):
                    output.append(
                        f"{add_tab_space(depth + 1)}_G[{repr(proto['kTable'][aux]['value'])}] = R{A}"
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
                if aux is not None and aux < len(proto['kTable']):
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = R{B}[{repr(proto['kTable'][aux]['value'])}]"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = R{B}[Invalid string index]"
                    )
            elif opname == "SETTABLEKS":
                if aux is not None and aux < len(proto['kTable']):
                    output.append(
                        f"{add_tab_space(depth + 1)}R{B}[{repr(proto['kTable'][aux]['value'])}] = R{A}"
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
                if aux is not None and aux < len(proto['kTable']):
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = R{B}[{repr(proto['kTable'][aux]['value'])}]; R{A+1} = R{B}"
                    )
                else:
                    output.append(
                        f"{add_tab_space(depth + 1)}R{A} = R{B}[Invalid string index]; R{A+1} = R{B}"
                    )
            elif opname == "CALL":
                if B == 1:
                    args = ""
                elif B == 0:
                    args = f"R{A+1} ..."
                else:
                    args = f"R{A+1}" + (f" ... R{A+B-1}" if B > 2 else "")
                
                if C == 0:
                    returns = f"R{A} ..."
                elif C == 1:
                    returns = ""
                else:
                    returns = f"R{A}" + (f" ... R{A+C-2}" if C > 2 else "")
                
                call_str = f"R{A}({args})"
                if returns:
                    output.append(f"{add_tab_space(depth + 1)}{returns} = {call_str}")
                else:
                    output.append(f"{add_tab_space(depth + 1)}{call_str}")
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
                if aux is not None and aux < len(proto['kTable']):
                    output.append(
                        f"{add_tab_space(depth + 1)}if R{A} == {repr(proto['kTable'][aux]['value'])} then goto [{(code_index + 2 + sAx) & 0xFF}]"
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
        code_index += 1

    output.append("end")
    return "\n".join(output)

