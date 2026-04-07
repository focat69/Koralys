"""Control flow structure identification for Luau bytecode.

Uses the CFG and dominator tree to identify high-level control flow structures:
  - Loops (while, numeric for, generic for, repeat-until)
  - If/else/elseif chains
  - Break and continue

This bridges the gap between the raw CFG (blocks + edges) and the AST
(structured statements). The decompiler uses these structures to emit
proper Luau source instead of goto-spaghetti.

Key concepts:
  - A LOOP exists when there's a "back-edge": an edge from block A to block B
    where B dominates A. B is the "header" (loop entry), A is the "latch"
    (where the loop jumps back).
  - An IF/ELSE exists when a block has two successors (conditional branch)
    and is NOT a loop header. The two successors are the then/else branches,
    and they reconverge at a "merge" block.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Optional, Any

from koralys.cfg import (
    CFG, BasicBlock,
    UNCONDITIONAL_JUMPS, CONDITIONAL_JUMPS, NO_SUCCESSOR_OPS,
)
from koralys.dominator import DominatorTree
from koralys.luau import get_opcode, get_arg_sBx, get_op_table


class LoopType(Enum):
    """Classification of loop constructs in Luau bytecode."""
    WHILE = "while"
    FOR_NUMERIC = "for_numeric"
    FOR_GENERIC = "for_generic"
    REPEAT_UNTIL = "repeat_until"


@dataclass
class LoopInfo:
    """A detected loop in the CFG.

    Attributes:
        header: Block ID of the loop header (entry point, dominates all body blocks).
        latch: Block ID of the loop latch (contains the back-edge to header).
        exit_block: Block ID of the first block after the loop.
        body: Set of all block IDs inside the loop (including header and latch).
        loop_type: Classification of the loop construct.
    """
    header: int
    latch: int
    exit_block: Optional[int]
    body: Set[int]
    loop_type: LoopType

    def __repr__(self) -> str:
        return (
            f"Loop({self.loop_type.value}, header=BB{self.header}, "
            f"latch=BB{self.latch}, exit=BB{self.exit_block}, "
            f"body={{{', '.join(f'BB{b}' for b in sorted(self.body))}}})"
        )


@dataclass
class IfInfo:
    """A detected if/else structure in the CFG.

    Attributes:
        condition: Block ID containing the conditional branch.
        true_branch: Block ID of the first block in the then-branch.
        false_branch: Block ID of the first block in the else-branch (or merge if no else).
        merge: Block ID where branches reconverge (the block after 'end').
            None if one or both branches end with RETURN.
    """
    condition: int
    true_branch: Optional[int]
    false_branch: Optional[int]
    merge: Optional[int]

    def has_else(self) -> bool:
        """True if there's a distinct else branch (not just fall-through to merge)."""
        return (self.false_branch is not None
                and self.merge is not None
                and self.false_branch != self.merge)

    def __repr__(self) -> str:
        parts = f"If(cond=BB{self.condition}, then=BB{self.true_branch}"
        if self.has_else():
            parts += f", else=BB{self.false_branch}"
        if self.merge is not None:
            parts += f", merge=BB{self.merge}"
        return parts + ")"


@dataclass
class StructureInfo:
    """All identified control flow structures for a proto.

    Attributes:
        loops: All detected loops, ordered by header block ID.
        ifs: All detected if/else structures, ordered by condition block ID.
        block_to_loop: Maps each block ID to the index of its innermost containing loop
            in the `loops` list, or None if not in any loop.
    """
    loops: List[LoopInfo]
    ifs: List[IfInfo]
    block_to_loop: Dict[int, Optional[int]]

    def get_loop_for_block(self, block_id: int) -> Optional[LoopInfo]:
        """Return the innermost loop containing this block, or None."""
        idx = self.block_to_loop.get(block_id)
        if idx is not None:
            return self.loops[idx]
        return None

    def is_loop_header(self, block_id: int) -> bool:
        return any(loop.header == block_id for loop in self.loops)

    def __repr__(self) -> str:
        return f"StructureInfo({len(self.loops)} loops, {len(self.ifs)} ifs)"


def _get_terminator_name(block: BasicBlock, proto: Dict[str, Any], luau_version: int) -> str:
    """Get the opcode name of a block's terminator instruction."""
    code = proto["codeTable"]
    if block.end_pc >= len(code):
        return "UNKNOWN"
    OP_TABLE = get_op_table(luau_version)
    opcode_to_name = {info.number: info.name for info in OP_TABLE}
    inst = code[block.end_pc]
    opc = get_opcode(inst)
    return opcode_to_name.get(opc, "UNKNOWN")


def _find_back_edges(cfg: CFG, dtree: DominatorTree) -> List[tuple]:
    """Find all back-edges in the CFG.

    A back-edge is an edge (latch -> header) where header dominates latch.
    Each back-edge corresponds to a natural loop.

    Returns list of (latch_id, header_id) tuples.
    """
    back_edges = []
    for block in cfg.blocks:
        for succ_id in block.successors:
            if dtree.dominates(succ_id, block.id):
                back_edges.append((block.id, succ_id))
    return back_edges


def _compute_loop_body(
    header: int, latch: int, cfg: CFG
) -> Set[int]:
    """Compute the set of blocks in a natural loop.

    The loop body is: {header} union all blocks that can reach the latch
    without going through the header. We compute this by working backwards
    from the latch.
    """
    body: Set[int] = {header, latch}
    if header == latch:
        return body  # Single-block loop

    # Worklist: start from latch, walk predecessors backward
    worklist = [latch]
    while worklist:
        block_id = worklist.pop()
        block = cfg.get_block(block_id)
        for pred_id in block.predecessors:
            if pred_id not in body:
                body.add(pred_id)
                worklist.append(pred_id)

    return body


def _classify_loop(
    header: int, latch: int, body: Set[int],
    cfg: CFG, proto: Dict[str, Any], luau_version: int
) -> tuple:
    """Classify a loop and find its exit block.

    Returns (LoopType, exit_block_id).

    Classification rules:
    - FORNPREP at header or FORNLOOP at latch -> for_numeric
    - FORGLOOP at latch -> for_generic
    - Condition check at header (JUMPIF*, etc.) -> while
    - Condition check at latch (JUMPBACK with prior condition) -> repeat_until
    """
    header_term = _get_terminator_name(cfg.get_block(header), proto, luau_version)
    latch_term = _get_terminator_name(cfg.get_block(latch), proto, luau_version)

    # Find exit block: the successor of the latch (or header) that's outside the body
    exit_block = None
    # Check latch successors first (most loops exit from latch)
    latch_block = cfg.get_block(latch)
    for succ_id in latch_block.successors:
        if succ_id not in body:
            exit_block = succ_id
            break
    # Also check header successors (while loops can exit from header)
    if exit_block is None:
        header_block = cfg.get_block(header)
        for succ_id in header_block.successors:
            if succ_id not in body:
                exit_block = succ_id
                break

    # Numeric for: FORNPREP jumps to exit, FORNLOOP is the latch
    if header_term == "FORNPREP" or latch_term == "FORNLOOP":
        return LoopType.FOR_NUMERIC, exit_block

    # Generic for: FORGLOOP can be the latch OR the header.
    # Pattern A: FORGPREP -> FORGLOOP (header), body falls through to FORGLOOP
    #   back-edge: body -> FORGLOOP, so header_term = FORGLOOP
    # Pattern B: FORGPREP -> body, FORGLOOP is latch that jumps back
    #   back-edge: FORGLOOP -> body_start, so latch_term = FORGLOOP
    if header_term == "FORGLOOP" or latch_term == "FORGLOOP":
        return LoopType.FOR_GENERIC, exit_block

    # Repeat-until detection — must come BEFORE while check.
    # Pattern: the latch is a single JUMPBACK instruction, and the header
    # contains the body AND the condition (ends with a conditional jump).
    # Luau compiles `repeat body until cond` as:
    #   header: [body instructions] + [conditional jump to exit]
    #   latch:  JUMPBACK to header
    # The latch is just a bare JUMPBACK because the condition is at the end
    # of the header block, not in a separate block.
    latch_block_obj = cfg.get_block(latch)
    if latch_term == "JUMPBACK" and latch_block_obj.start_pc == latch_block_obj.end_pc:
        # Single-instruction JUMPBACK latch -> repeat-until
        return LoopType.REPEAT_UNTIL, exit_block

    if latch_term in CONDITIONAL_JUMPS:
        # Condition at latch (another repeat-until variant)
        return LoopType.REPEAT_UNTIL, exit_block

    # While loop: condition at the header (some conditional jump).
    # The header is a short condition-check block, and the body is a
    # separate block with a JUMPBACK latch containing the body.
    if header_term in CONDITIONAL_JUMPS:
        return LoopType.WHILE, exit_block

    # Default to while if we can't determine
    return LoopType.WHILE, exit_block


def _find_merge_block(
    cond_block: BasicBlock, cfg: CFG, dtree: DominatorTree,
    loop_bodies: Dict[int, Set[int]]
) -> Optional[int]:
    """Find the merge block for an if/else structure.

    The merge block is the earliest block (by ID) that is:
    1. Reachable from both branches of the conditional
    2. Not strictly inside one branch only
    3. Post-dominates the condition (or is in its dominance frontier)

    Heuristic approach: walk forward from both successors, find first common block.
    """
    if len(cond_block.successors) < 2:
        return None

    true_succ = cond_block.successors[0]
    false_succ = cond_block.successors[1]

    # Walk forward from each branch collecting reachable blocks (BFS)
    def reachable_from(start: int, limit: int = 50) -> Set[int]:
        visited: Set[int] = set()
        worklist = [start]
        while worklist and len(visited) < limit:
            bid = worklist.pop(0)
            if bid in visited:
                continue
            visited.add(bid)
            if bid in cfg.block_map:
                for succ in cfg.get_block(bid).successors:
                    if succ not in visited:
                        worklist.append(succ)
        return visited

    true_reach = reachable_from(true_succ)
    false_reach = reachable_from(false_succ)

    # Common blocks reachable from both branches
    common = true_reach & false_reach
    if not common:
        return None

    # The merge is the common block with the smallest block ID
    # (earliest in program order)
    return min(common)


def identify_structures(
    cfg: CFG, dtree: DominatorTree,
    proto: Dict[str, Any], luau_version: int
) -> StructureInfo:
    """Identify all high-level control flow structures in a proto.

    Algorithm:
    1. Find all back-edges -> loops
    2. Compute loop bodies and classify loop types
    3. For non-loop conditional blocks, identify if/else structures
    4. Build block-to-loop mapping
    """
    # --- Step 1: Find loops ---
    back_edges = _find_back_edges(cfg, dtree)
    loops: List[LoopInfo] = []
    loop_headers: Set[int] = set()

    for latch_id, header_id in back_edges:
        body = _compute_loop_body(header_id, latch_id, cfg)
        loop_type, exit_block = _classify_loop(
            header_id, latch_id, body, cfg, proto, luau_version
        )
        loops.append(LoopInfo(
            header=header_id,
            latch=latch_id,
            exit_block=exit_block,
            body=body,
            loop_type=loop_type,
        ))
        loop_headers.add(header_id)

    # Sort loops by header block ID (program order)
    loops.sort(key=lambda l: l.header)

    # Build block-to-loop mapping (innermost loop for each block)
    # Smaller body = more inner loop
    block_to_loop: Dict[int, Optional[int]] = {}
    for block in cfg.blocks:
        best_idx = None
        best_size = float('inf')
        for i, loop in enumerate(loops):
            if block.id in loop.body and len(loop.body) < best_size:
                best_idx = i
                best_size = len(loop.body)
        block_to_loop[block.id] = best_idx

    # Collect all loop body blocks for merge-finding
    loop_body_map: Dict[int, Set[int]] = {
        loop.header: loop.body for loop in loops
    }

    # --- Step 2: Find if/else structures ---
    ifs: List[IfInfo] = []

    for block in cfg.blocks:
        # Only look at blocks with exactly 2 successors (conditional branches)
        if len(block.successors) != 2:
            continue

        # Skip loop headers — they're already classified as loops
        if block.id in loop_headers:
            # But: while-loop headers ARE conditional branches.
            # We still want to identify the condition, but the loop is the
            # primary structure. For now, skip — the AST lifter will handle
            # while-loop conditions separately.
            continue

        # Skip loop latches (FORNLOOP, FORGLOOP) — these are loop iteration checks
        is_latch = any(block.id == loop.latch for loop in loops)
        if is_latch:
            continue

        # Skip FORNPREP blocks — they're numeric for-loop setup blocks, not ifs.
        # FORNPREP has 2 successors (body + exit), but it's the loop init, not
        # a real conditional branch.
        term_name = _get_terminator_name(block, proto, luau_version)
        if term_name in ("FORNPREP", "FORGPREP", "FORGPREP_INEXT", "FORGPREP_NEXT"):
            continue

        true_branch = block.successors[0]   # fall-through
        false_branch = block.successors[1]  # jump target

        merge = _find_merge_block(block, cfg, dtree, loop_body_map)

        ifs.append(IfInfo(
            condition=block.id,
            true_branch=true_branch,
            false_branch=false_branch,
            merge=merge,
        ))

    # Sort by condition block ID (program order)
    ifs.sort(key=lambda i: i.condition)

    return StructureInfo(
        loops=loops,
        ifs=ifs,
        block_to_loop=block_to_loop,
    )


def structures_to_text(info: StructureInfo, cfg: CFG) -> str:
    """Generate a human-readable summary of identified structures."""
    lines = [f"Structures: {len(info.loops)} loops, {len(info.ifs)} ifs", ""]

    if info.loops:
        lines.append("Loops:")
        for i, loop in enumerate(info.loops):
            body_str = ", ".join(f"BB{b}" for b in sorted(loop.body))
            exit_str = f"BB{loop.exit_block}" if loop.exit_block is not None else "(none)"
            lines.append(
                f"  [{i}] {loop.loop_type.value}: "
                f"header=BB{loop.header}, latch=BB{loop.latch}, "
                f"exit={exit_str}"
            )
            lines.append(f"       body: {{{body_str}}}")
        lines.append("")

    if info.ifs:
        lines.append("If/Else:")
        for i, if_info in enumerate(info.ifs):
            merge_str = f"BB{if_info.merge}" if if_info.merge is not None else "(none)"
            has_else = "with else" if if_info.has_else() else "no else"
            lines.append(
                f"  [{i}] cond=BB{if_info.condition}, "
                f"then=BB{if_info.true_branch}, "
                f"else=BB{if_info.false_branch}, "
                f"merge={merge_str} ({has_else})"
            )
        lines.append("")

    return "\n".join(lines)
