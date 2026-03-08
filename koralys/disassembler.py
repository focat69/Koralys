from typing import List, Dict, Any, Tuple

from koralys.constants import (
    LBC_CONSTANT_NIL,
    LBC_CONSTANT_BOOLEAN,
    LBC_CONSTANT_NUMBER,
    LBC_CONSTANT_STRING,
    LBC_CONSTANT_IMPORT,
    LBC_CONSTANT_TABLE,
    LBC_CONSTANT_CLOSURE,
    LBC_CONSTANT_VECTOR,
    builtin_name,
)
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
from koralys.deserializer import deserialize
from koralys.decompiler import decompile


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
 
    # Build debug info helpers if available
    debug_info = proto.get("debugInfo")
    # reg_name: look up variable name for a register at a given pc
    def reg_name(reg: int, pc: int) -> str:
        """Return 'varname' if debug info maps register `reg` at instruction `pc`, else None.
        Also matches at startpc - 1 to annotate the defining instruction itself,
        since the compiler sets startpc to the instruction AFTER the assignment."""
        if debug_info is None:
            return None
        for var in debug_info["varInfo"]:
            if var["reg"] == reg and (var["startpc"] - 1) <= pc < var["endpc"]:
                return var["name"]
        return None
 
    def upvalue_name(idx: int) -> str:
        """Return upvalue name from debug info, or None."""
        if debug_info and idx < len(debug_info["upvalueInfo"]):
            return debug_info["upvalueInfo"][idx]
        return None
 
    # smallLineInfo = per-instruction signed byte deltas of offset-from-interval
    # largeLineInfo = absolute line numbers at intervals of (1 << lineGapLog2)
    # Formula: accumulate the signed deltas, then line = largeLineInfo[pc >> gap] + accumulated_offset
    line_map = None
    if proto.get("smallLineInfo") and proto.get("largeLineInfo"):
        gap = proto.get("lineGapLog2", 0)
        small = proto["smallLineInfo"]
        large = proto["largeLineInfo"]
        line_map = []
        last_offset = 0
        for pc in range(len(small)):
            delta = small[pc]
            if delta >= 128:
                delta -= 256
            last_offset += delta
            interval_idx = pc >> gap
            if interval_idx < len(large):
                line_map.append(large[interval_idx] + last_offset)
            else:
                line_map.append(0)
                
    # Build function signature with parameter names from debug info
    params = []
    if proto["isVarArg"]:
        params.append("...")
    for i in range(proto["numParams"]):
        name = reg_name(i, 0)
        params.append(name if name else f"R{i}")
    output += f"{tab_space}function({', '.join(params)})\n"
 
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
    
    # Pre-scan: here we collect all jump target instruction indices so we can emit the labels
    jump_targets = set()
    op_aux_set = {info.name for info in OP_TABLE if info.get("aux", False)}
    _scan_idx = 0
    while _scan_idx < len(proto["codeTable"]):
        _inst = proto["codeTable"][_scan_idx]
        _opc = get_opcode(_inst)
        _name = opcodeToOpname.get(_opc, "")
        _curr_idx = _scan_idx
        if _name in op_aux_set and _scan_idx + 1 < len(proto["codeTable"]):
            _scan_idx += 1
        _sBx = get_arg_sBx(_inst)
        _sAx = get_arg_sAx(_inst)
        _C = get_arg_c(_inst)
        if _name in ("JUMP", "JUMPBACK", "JUMPIF", "JUMPIFNOT",
                     "JUMPIFEQ", "JUMPIFLE", "JUMPIFLT",
                     "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT",
                     "JUMPIFEQK", "FORNPREP", "FORNLOOP",
                     "FORGPREP", "FORGPREP_INEXT", "FORGPREP_NEXT",
                     "FORGLOOP", "JUMPXEQKNIL", "JUMPXEQKB",
                     "JUMPXEQKN", "JUMPXEQKS"):
            jump_targets.add(_curr_idx + 1 + _sBx)
        elif _name == "JUMPX":
            jump_targets.add(_curr_idx + 1 + _sAx)
        elif _name == "LOADB" and _C != 0:
            jump_targets.add(_curr_idx + _C + 1)
        _scan_idx += 1
 
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
        if codeIndex in jump_targets:
            output += f"{'    ' * depth}.L{codeIndex}:\n"
        output += f"{'    ' * depth}[{codeIndex:03}] {op_name:<{max_opname_length}} "
        inst_index = codeIndex
 
        aux = None
        if any(
            info.name == op_name and info.get("aux", False) for info in OP_TABLE
        ) and codeIndex + 1 < len(proto["codeTable"]):
            aux = proto["codeTable"][codeIndex + 1]
            codeIndex += 1
 
        def __CALL_handler(_):
            # B = nargs + 1 (0 = varargs to top), C = nresults + 1 (0 = multi-return)
            if B == 0:
                args = f"R{A+1} ... top"
            elif B == 1:
                args = ""
            elif B == 2:
                args = f"R{A+1}"
            else:
                args = f"R{A+1} ... R{A+B-1}"
 
            if C == 0:
                returns = f"R{A} ... top"
            elif C == 1:
                returns = ""
            elif C == 2:
                returns = f"R{A}"
            else:
                returns = f"R{A} ... R{A+C-2}"
 
            if returns:
                return f"{returns} = R{A}({args})"
            else:
                return f"R{A}({args})"
 
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
 
            For JUMPIFNOT{EQ,LE,LT}, invert=True flips the operator (== -> ~=, <= -> >, < -> >=)
            instead of prepending "not", which would be ambiguous (e.g. "if not R0 == R1"
            reads as "(not R0) == R1" in Lua operator precedence).
 
            Args:
                op (str | None): The operator to include in the condition, or None for no operator.
                invert (bool): If True, inverts the condition in the generated statement.
                k_mode (bool): If True, appends `K` before the index,
                               use this with operations like `JUMPIFEQK`,
                               usually where the operation ends in `K`.
 
            Returns:
                str: A formatted string representing the conditional jump statement.
            """
            op_map = {"EQ": "==", "LE": "<=", "LT": "<"}
            inv_op_map = {"EQ": "~=", "LE": ">", "LT": ">="}
            current_A = A
            current_aux = aux
            jump = opcode_handlers["JUMP"]("JUMP")
 
            if op is None:
                pre_op = " not " if invert else " "
                return f"if{pre_op}R{current_A} then {jump}"
            else:
                # JUMPIFEQ / JUMPIFNOTEQ etc. comparison with second operand
                operator = (inv_op_map if invert else op_map).get(op, op)
                rhs = f"K{current_aux}" if k_mode else f"R{current_aux}"
                return f"if R{current_A} {operator} {rhs} then {jump}"
 
        def jumpx_if_gen(value: str, curr_aux=None):
            not_flag = (curr_aux >> 31) & 1 if curr_aux is not None else 0
            op = "~=" if not_flag else "=="
            jump = f"goto .L{inst_index + 1 + sBx}"
            return f"if R{A} {op} {value} then {jump}"
 
        def __LOADKX_handler(_):
            k = proto["kTable"][aux] if aux < len(proto["kTable"]) else {"type": "nil", "value": "nil"}
            return f"R{A} = {repr(k['value']) if isinstance(k['value'], str) else k['value']}"
 
        opcode_handlers = {
            "NOP": lambda _: "-- do nothing (no-op / NOP)",
            "BREAK": lambda _: "break",
            "PREPVARARGS": lambda _: f"(adjust vararg params, {A} fixed params)",
            "LOADNIL": lambda _: f"R{A} = nil",
            "LOADB": lambda _: (
                f"R{A} = {bool(B)}; goto .L{inst_index + C + 1}"
                if C != 0
                else f"R{A} = {bool(B)}"
            ),
            "LOADN": lambda _: f"R{A} = {sBx}",  # D field is signed 16-bit
            "LOADK": lambda _: (
                f"R{A} = {repr(proto['kTable'][Bx]['value']) if isinstance(proto['kTable'][Bx]['value'], str) else proto['kTable'][Bx]['value']}"
                if Bx < len(proto["kTable"])
                else f"R{A} = K{Bx}"
            ),
            "MOVE": lambda _: f"R{A} = R{B}",
            "GETGLOBAL": lambda _, curr_aux=aux, curr_A=A: (
                f"R{curr_A} = _G[{repr(proto['kTable'][curr_aux]['value'])}]"
                if curr_aux is not None and curr_aux < len(proto['kTable'])
                else f"R{curr_A} = _G[Invalid constant index]"
            ),
            "SETGLOBAL": lambda _, curr_aux=aux, curr_A=A: (
                f"_G[{repr(proto['kTable'][curr_aux]['value'])}] = R{curr_A}"
                if curr_aux is not None and curr_aux < len(proto['kTable'])
                else f"_G[Invalid constant index] = R{curr_A}"
            ),
            "GETUPVAL": lambda _: f"R{A} = U{B}",
            "SETUPVAL": lambda _: f"U{B} = R{A}",
            "CLOSEUPVALS": lambda _: f"close upvalues R{A}+",
            "GETIMPORT": __GETIMPORT_handler,
            "GETTABLE": lambda _: f"R{A} = R{B}[R{C}]",
            "SETTABLE": lambda _: f"R{B}[R{C}] = R{A}",
            "GETTABLEKS": lambda _, curr_aux=aux, curr_A=A, curr_B=B: (
                f"R{curr_A} = R{curr_B}[{repr(proto['kTable'][curr_aux]['value'])}]"
                if curr_aux is not None and curr_aux < len(proto['kTable'])
                else f"R{curr_A} = R{curr_B}[Invalid constant index]"
            ),
            "SETTABLEKS": lambda _, curr_aux=aux, curr_A=A, curr_B=B: (
                f"R{curr_B}[{repr(proto['kTable'][curr_aux]['value'])}] = R{curr_A}"
                if curr_aux is not None and curr_aux < len(proto['kTable'])
                else f"R{curr_B}[Invalid constant index] = R{curr_A}"
            ),
            "GETTABLEN": lambda _: f"R{A} = R{B}[{C + 1}]",
            "SETTABLEN": lambda _: f"R{B}[{C + 1}] = R{A}",
            "NEWCLOSURE": lambda _: f"R{A} = closure(proto[{Bx}])",
            "NAMECALL": lambda _, curr_aux=aux, curr_A=A, curr_B=B: (
                f"R{curr_A} = R{curr_B}[{repr(proto['kTable'][curr_aux]['value'])}]; R{curr_A+1} = R{curr_B}"
                if curr_aux is not None and curr_aux < len(proto['kTable'])
                else f"R{curr_A} = R{curr_B}[Invalid constant index]; R{curr_A+1} = R{curr_B}"
            ),
            "CALL": __CALL_handler,
            # B = nresults + 1 (0 = multi-return to top)
            "RETURN": lambda _: (
                f"return R{A} ..." if B == 0
                else "return" if B == 1
                else f"return R{A}" if B == 2
                else f"return R{A} ... R{A+B-2}"
            ),
            "JUMP": lambda _: f"goto .L{inst_index + 1 + sBx}",
            "JUMPBACK": lambda _: f"goto .L{inst_index + 1 + sBx}",
            "JUMPX": lambda _: f"goto .L{inst_index + 1 + sAx}",
            "JUMPXEQKNIL": lambda _, curr_aux=aux: jumpx_if_gen("nil", curr_aux),
            "JUMPXEQKB": lambda _, curr_aux=aux: jumpx_if_gen(
                str(bool(curr_aux & 1)).lower() if curr_aux is not None else "?",
                curr_aux
            ),
            "JUMPXEQKN": lambda _, curr_aux=aux: (
                jumpx_if_gen(
                    (lambda k: repr(k['value']) if isinstance(k['value'], str) else str(k['value']))(
                        proto['kTable'][(curr_aux & 0x7FFFFFFF)]
                    ) if curr_aux is not None and (curr_aux & 0x7FFFFFFF) < len(proto['kTable'])
                    else f"K{curr_aux}",
                    curr_aux
                )
            ),
            "JUMPXEQKS": lambda _, curr_aux=aux: (
                jumpx_if_gen(
                    repr(proto['kTable'][(curr_aux & 0x7FFFFFFF)]['value'])
                    if curr_aux is not None and (curr_aux & 0x7FFFFFFF) < len(proto['kTable'])
                    else f"K{curr_aux}",
                    curr_aux
                )
            ),
            # FASTCALL: A = builtin function ID, C = skip offset to jump past the following CALL
            # These are hint instructions. The results will come from the paired CALL instead of the FASTCALL itself
            "FASTCALL": lambda _: f"fastcall {builtin_name(A)}; skip +{C}",
            "FASTCALL1": lambda _: f"fastcall {builtin_name(A)}(R{B}); skip +{C}",
            "FASTCALL2": lambda _, curr_aux=aux: f"fastcall {builtin_name(A)}(R{B}, R{curr_aux}); skip +{C}",
            "FASTCALL2K": lambda _, curr_aux=aux: f"fastcall {builtin_name(A)}(R{B}, K{curr_aux}); skip +{C}",
            "FASTCALL3": lambda _, curr_aux=aux: (
                f"fastcall {builtin_name(A)}(R{B}, R{curr_aux & 0xFF}, R{(curr_aux >> 8) & 0xFF}); skip +{C}"
                if curr_aux is not None
                else f"fastcall {builtin_name(A)}(R{B}); skip +{C}"
            ),
            "COVERAGE": lambda _: "(coverage)",
            "CAPTURE": __CAPTURE_handler,
            "JUMPIFEQK": lambda _: jump_if_gen("==", k_mode=True),
            "FORNPREP": lambda _: f"R{A} -= R{A+2}; goto .L{inst_index + 1 + sBx}",
            "FORNLOOP": lambda _: f"R{A} += R{A+2}; if R{A} <= R{A+1} then goto .L{inst_index + 1 + sBx}; R{A+3} = R{A}",
            "MINUS": lambda _: f"R{A} = -R{B}",
            "LENGTH": lambda _: f"R{A} = #R{B}",
            # https://github.com/luau-lang/luau/blob/a251bc68a2b70212e53941fd541d16ce523a1e01/Compiler/src/BytecodeBuilder.cpp#L2134-L2136
            "NEWTABLE": lambda _, curr_aux=aux: (
                f"R{A} = {{}} -- hash={0 if B == 0 else 1 << (B - 1)}, array={curr_aux if curr_aux is not None else 0}"
            ),
            "DUPTABLE": lambda _: f"R{A} = K{Bx} -- duplicate",
            "SETLIST": lambda _, curr_aux=aux: (
                f"R{A}[{curr_aux}..{curr_aux+C-2}] = R{B} ... R{B+C-2}"
                if C > 0 and curr_aux is not None
                else f"R{A}[..] = R{B} ... top"
            ),
            "CONCAT": lambda _: f"R{A} = R{B} .. R{C}",
            "NOT": lambda _: f"R{A} = not R{B}",
            "FORGPREP": lambda _: f"prepare for-in R{A}..R{A+2}; goto .L{inst_index + 1 + sBx}",
            "FORGLOOP": lambda _, curr_aux=aux: (
                f"R{A+3}, ..., R{A+2+(curr_aux & 0x7F)} = R{A}(R{A+1}, R{A+2}); "
                f"if R{A+3} ~= nil then R{A+2} = R{A+3}; goto .L{inst_index + 1 + sBx}"
                if curr_aux is not None
                else f"if R{A+3} ~= nil then R{A+2} = R{A+3}; goto .L{inst_index + 1 + sBx}"
            ),
            "FORGPREP_INEXT": lambda _: f"prepare for-in (ipairs) R{A}..R{A+2}; goto .L{inst_index + 1 + sBx}",
            "NATIVECALL": lambda _: "Unimplemented",
            # B encodes count+1; B=0 means "all remaining varargs"
            "GETVARARGS": lambda _: (
                f"R{A}, ... = ..."
                if B == 0
                else f"R{A}, ..., R{A+B-2} = ..."
            ),
            "DUPCLOSURE": lambda _: (
                f"R{A} = closure(proto[{proto['kTable'][Bx]['value']}]) -- duplicate"
                if Bx < len(proto['kTable']) and proto['kTable'][Bx].get('type') == LBC_CONSTANT_CLOSURE
                else f"R{A} = K{Bx} -- duplicate"
            ),
            "LOADKX": __LOADKX_handler,
            "FORGPREP_NEXT": lambda _: f"prepare for-in (pairs) R{A}..R{A+2}; goto .L{inst_index + 1 + sBx}",
        }
 
        for condition in ["EQ", "LE", "LT", None]:
            opcode_handlers[f"JUMPIF{condition or ''}"] = lambda _, cond=condition: jump_if_gen(cond)
            opcode_handlers[f"JUMPIFNOT{condition or ''}"] = lambda _, cond=condition: jump_if_gen(cond, True)
 
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
                    return f"R{A} = R{B} {op} R{C}"
            opcode_handlers[gen_op_name] = __gen_op_handler
            opcode_handlers[f"{gen_op_name}K"] = __gen_op_handler
 
        math_ops = {
            "ADD": "+",
            "SUB": "-",
            "MUL": "*",
            "DIV": "/",
            "IDIV": "//",
            "MOD": "%",
            "POW": "^",
        }
 
        for gen_op_name in ["SUBRK", "DIVRK"]:
            def __subrk_divrk_handler(op):
                op_sym = math_ops[op[:-2]]
                k = (
                    proto["kTable"][B]
                    if B < len(proto["kTable"])
                    else {"type": "nil", "value": "nil"}
                )
                kval = repr(k['value']) if isinstance(k['value'], str) else k['value']
                return f"R{A} = {kval} {op_sym} R{C}"
            opcode_handlers[gen_op_name] = __subrk_divrk_handler
 
 
        for gen_op_name in ["ADD", "SUB", "MUL", "DIV", "IDIV", "MOD", "POW"]:
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
            handler_result = opcode_handlers[op_name](op_name)
            output += handler_result
        else:
            handler_result = f"Unknown opcode: {opc}"
            output += handler_result
 
        # Annotate instruction with variable name for the destination register (A),
        # but only if the instruction actually writes to register A (contains "R{A} =").
        annotations = []
        inst_pc = inst_index
        if f"R{A} =" in handler_result or f"R{A}," in handler_result:
            dest_name = reg_name(A, inst_pc)
            if dest_name:
                annotations.append(dest_name)
        if line_map and inst_pc < len(line_map) and line_map[inst_pc] > 0:
            annotations.append(f"line {line_map[inst_pc]}")
        if annotations:
            output += f"  -- {', '.join(annotations)}"
 
        output += "\n"
        codeIndex += 1
 
    output += "end\n"
 
    if len(proto["kTable"]) > 0:
        output += "--< Constants >--\n"
        constant_types = {
            LBC_CONSTANT_NIL: lambda k: "nil",
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
 
    if "sizeProtos" in proto and proto["sizeProtos"] > 0:
        output += "--< Protos >--\n"
        for i, proto_idx in enumerate(proto["pTable"]):
            if proto_idx < len(proto_table):
                child_proto = proto_table[proto_idx]
                output += f"{'    ' * depth}[{i}] = {read_proto(child_proto, depth + 1, proto_table, string_table, luau_version)}\n"
            else:
                output += f"{'    ' * depth}[{i}] = <invalid proto index {proto_idx}>\n"
 
    if proto["numUpValues"] > 0:
        output += "--< Upvalues >--\n"
        for i in range(proto["numUpValues"]):
            uv_name = upvalue_name(i)
            if uv_name:
                output += f"{'    ' * depth}[{i}] = {uv_name}\n"
            else:
                output += f"{'    ' * depth}[{i}] = Upvalue {i}\n"
 
    if debug_info and debug_info["varInfo"]:
        output += "--< Local Variables >--\n"
        for var in debug_info["varInfo"]:
            output += f"{'    ' * depth}R{var['reg']} = '{var['name']}' (pc {var['startpc']}..{var['endpc']})\n"
 
    return output


def disassemble(bytecode: bytes) -> Tuple[List[str], List[str], int, int, int]:
    output = []
    decompiled_output = []

    if bytecode[0] == 0:
        return [bytecode[1:].decode("utf-8")], [], 0, -1, -1

    mainProto, protoTable, stringTable, luau_version, types_version = deserialize(
        bytecode
    )

    # to figure out which protos are children we just check if they are referenced by another proto's pTable
    child_proto_indices = set()
    for proto in protoTable:
        for child_idx in proto.get("pTable", []):
            child_proto_indices.add(child_idx)

    protos = 0
    for i, proto in enumerate(protoTable):
        if i in child_proto_indices:
            continue  # skip child protos; they are shown inline by their parent
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
