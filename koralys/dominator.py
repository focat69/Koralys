"""Dominator tree and dominance frontier computation.

Given a CFG, computes:
  1. Immediate dominators (idom) for every block
  2. Dominator tree (parent = idom, children list)
  3. Dominance frontier (DF) for every block

The dominance frontier is critical for SSA construction: phi nodes must be
placed at exactly the blocks in the dominance frontier of each variable's
definition points.

Uses the iterative algorithm from:
  Cooper, Harvey, Kennedy — "A Simple, Fast Dominance Algorithm" (2001)
This is simpler than Lengauer-Tarjan and works well for the small CFGs
produced by Luau bytecode (typically < 100 blocks).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional

from koralys.cfg import CFG, BasicBlock


@dataclass
class DominatorTree:
    """Dominator tree for a CFG.

    Attributes:
        idom: Maps block ID -> immediate dominator block ID.
            The entry block's idom is itself.
        children: Maps block ID -> list of block IDs it immediately dominates.
        dom_frontier: Maps block ID -> set of block IDs in its dominance frontier.
            Block B is in DF(A) if A dominates a predecessor of B but does not
            strictly dominate B itself.
    """
    idom: Dict[int, int]
    children: Dict[int, List[int]]
    dom_frontier: Dict[int, Set[int]]

    def dominates(self, a: int, b: int) -> bool:
        """Return True if block `a` dominates block `b`.

        A block dominates itself. Walk up the idom chain from b;
        if we hit a, then a dominates b.
        """
        runner = b
        while runner != self.idom.get(runner, runner):
            if runner == a:
                return True
            runner = self.idom[runner]
        return runner == a

    def __repr__(self) -> str:
        return f"DominatorTree(idom={self.idom})"


def _compute_postorder(cfg: CFG) -> List[int]:
    """Compute a postorder traversal of the CFG from the entry block.

    Returns a list of block IDs in postorder (deepest-first).
    Unreachable blocks are excluded.

    Uses an explicit stack so large CFGs (thousands of blocks) don't
    blow Python's call stack.
    """
    visited: Set[int] = set()
    postorder: List[int] = []

    # Stack entries: (block_id, iterator over unvisited successors)
    visited.add(cfg.entry_id)
    block = cfg.get_block(cfg.entry_id)
    succs = [s for s in block.successors if s in cfg.block_map]
    stack: list = [(cfg.entry_id, iter(succs))]

    while stack:
        bid, succ_iter = stack[-1]
        pushed = False
        for succ_id in succ_iter:
            if succ_id not in visited:
                visited.add(succ_id)
                child_block = cfg.get_block(succ_id)
                child_succs = [s for s in child_block.successors if s in cfg.block_map]
                stack.append((succ_id, iter(child_succs)))
                pushed = True
                break
        if not pushed:
            stack.pop()
            postorder.append(bid)

    return postorder


def build_dominator_tree(cfg: CFG) -> DominatorTree:
    """Build the dominator tree for a CFG.

    Algorithm: Cooper-Harvey-Kennedy iterative dominator computation.
    1. Compute reverse postorder numbering
    2. Iteratively refine idom[] until convergence
    3. Build children lists and dominance frontier from idom[]
    """
    if not cfg.blocks:
        return DominatorTree(idom={}, children={}, dom_frontier={})

    # --- Step 1: Reverse postorder numbering ---
    postorder = _compute_postorder(cfg)
    # postorder_num[block_id] = position in postorder (higher = closer to entry)
    postorder_num: Dict[int, int] = {
        bid: idx for idx, bid in enumerate(postorder)
    }
    # Reverse postorder: process blocks from entry toward leaves
    rpo = list(reversed(postorder))

    entry = cfg.entry_id

    # --- Step 2: Iterative idom computation ---
    idom: Dict[int, int] = {}
    idom[entry] = entry  # Entry block dominates itself

    def intersect(b1: int, b2: int) -> int:
        """Find the nearest common dominator of b1 and b2.

        Walk up the idom chain from both, advancing whichever has the
        lower postorder number (i.e. is deeper in the tree).
        """
        finger1 = b1
        finger2 = b2
        while finger1 != finger2:
            while postorder_num.get(finger1, -1) < postorder_num.get(finger2, -1):
                finger1 = idom[finger1]
            while postorder_num.get(finger2, -1) < postorder_num.get(finger1, -1):
                finger2 = idom[finger2]
        return finger1

    changed = True
    while changed:
        changed = False
        for b in rpo:
            if b == entry:
                continue

            block = cfg.get_block(b)
            # Find first predecessor that already has an idom
            new_idom: Optional[int] = None
            for p in block.predecessors:
                if p in idom:
                    new_idom = p
                    break

            if new_idom is None:
                continue  # Unreachable from entry (shouldn't happen after postorder filter)

            # Intersect with remaining processed predecessors
            for p in block.predecessors:
                if p == new_idom:
                    continue
                if p in idom:
                    new_idom = intersect(new_idom, p)

            if idom.get(b) != new_idom:
                idom[b] = new_idom
                changed = True

    # --- Step 3: Build children lists ---
    children: Dict[int, List[int]] = {bid: [] for bid in idom}
    for b, parent in idom.items():
        if b != parent:  # Don't add entry as its own child
            children.setdefault(parent, []).append(b)

    # --- Step 4: Compute dominance frontier ---
    dom_frontier: Dict[int, Set[int]] = {bid: set() for bid in idom}

    for b in idom:
        block = cfg.get_block(b)
        if len(block.predecessors) < 2:
            continue
        for p in block.predecessors:
            runner = p
            while runner != idom.get(b):
                if runner is None or runner not in idom:
                    break  # Safety: unreachable predecessor
                dom_frontier.setdefault(runner, set()).add(b)
                if runner == idom[runner]:
                    break  # Reached entry, stop
                runner = idom[runner]

    return DominatorTree(idom=idom, children=children, dom_frontier=dom_frontier)


def domtree_to_text(dtree: DominatorTree, cfg: CFG) -> str:
    """Generate a human-readable text representation of the dominator tree."""
    lines = ["Dominator Tree:", ""]

    # Print idom relationships
    lines.append("Immediate dominators:")
    for bid in sorted(dtree.idom.keys()):
        parent = dtree.idom[bid]
        if bid == parent:
            lines.append(f"  BB{bid} (entry)")
        else:
            lines.append(f"  BB{bid} <- idom BB{parent}")

    # Print tree structure
    lines.append("")
    lines.append("Tree structure:")

    # Iterative tree print so large dominator trees don't blow the call stack
    print_stack = [(cfg.entry_id, 1)]
    while print_stack:
        bid, indent_level = print_stack.pop()
        lines.append(f"{'  ' * indent_level}BB{bid}")
        for child in reversed(sorted(dtree.children.get(bid, []))):
            print_stack.append((child, indent_level + 1))

    # Print dominance frontiers
    lines.append("")
    lines.append("Dominance frontiers:")
    for bid in sorted(dtree.dom_frontier.keys()):
        df = dtree.dom_frontier[bid]
        if df:
            df_str = ", ".join(f"BB{d}" for d in sorted(df))
            lines.append(f"  DF(BB{bid}) = {{{df_str}}}")

    return "\n".join(lines)
