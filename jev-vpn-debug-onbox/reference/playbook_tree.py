"""Load a playbook binary decision tree and walk it with Jev noul classifications.

Flag-gated integration: reached only through the `consult_playbook` COT tool, which is
absent from the agent surface unless config.PLAYBOOK_WALK_ENABLED is on, and lazy-imports
this module so nothing loads it (or `requests` via jev_client) on the core path when off.
Companion to tools/jev_client.py and the hand-authored `<doc_id>.tree.json`.

Walk model (batch): because Jev questions are non-conditional, we send EVERY node's noul
in a single `decide()` call, then traverse the tree client-side using the returned
probabilities — so we both "check every path" (a probability for every node) and land on
a single leaf deterministically given those probabilities. The caller (the "driver")
supplies the `state` — the case evidence Jev reasons over.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from tools import jev_client
from tools.playbook_compile import source_md_path

# Indirection so tests can monkeypatch the network call (mirrors rfp_engine._call_llm).
_decide = jev_client.decide


class TreeError(Exception):
    pass


def tree_path_for(doc_id: str) -> Optional[str]:
    md = source_md_path(doc_id)
    if not md:
        return None
    return os.path.join(os.path.dirname(md), f"{doc_id}.tree.json")


def load_tree(doc_id: str) -> Dict[str, Any]:
    p = tree_path_for(doc_id)
    if not p or not os.path.exists(p):
        raise TreeError(f"no binary tree JSON for {doc_id!r} (expected {p})")
    with open(p, encoding="utf-8") as f:
        tree = json.load(f)
    validate(tree)
    return tree


def validate(tree: Dict[str, Any]) -> None:
    """Structural validation: root exists, every yes/no target resolves, every leaf
    candidate ref exists. Raises TreeError on a bad shape."""
    for k in ("root", "nodes", "leaves", "candidates"):
        if k not in tree:
            raise TreeError(f"tree missing required key {k!r}")
    nodes, leaves, cands = tree["nodes"], tree["leaves"], tree["candidates"]
    if tree["root"] not in nodes:
        raise TreeError(f"root {tree['root']!r} is not a node")
    for nid, n in nodes.items():
        for br in ("yes", "no"):
            tgt = n.get(br)
            if tgt not in nodes and tgt not in leaves:
                raise TreeError(f"node {nid!r} {br}->{tgt!r} resolves to nothing")
        if not n.get("instructions") or not isinstance(n.get("criteria"), dict):
            raise TreeError(f"node {nid!r} missing instructions/criteria")
    for lid, leaf in leaves.items():
        cid = leaf.get("candidate")
        if cid is not None and cid not in cands:
            raise TreeError(f"leaf {lid!r} references unknown candidate {cid!r}")


def _questions(tree: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """One noul question per internal node, keyed by node id."""
    return {
        nid: {"type": "noul", "instructions": n["instructions"], "criteria": n["criteria"]}
        for nid, n in tree["nodes"].items()
    }


def walk(tree: Dict[str, Any], state: Any, *, threshold: float = 0.5,
         margin: float = 0.1, max_steps: int = 64) -> Dict[str, Any]:
    """Send all node nouls in one Jev call, then traverse client-side.

    Returns:
      path            [{node, instructions, noul, branch}] visited root→leaf
      leaf            the landed leaf id
      candidate_id    the candidate at the leaf (None for escalate leaves)
      fix             the candidate's fix (None if no candidate)
      escalate        True if the leaf is an escalate leaf OR any on-path noul was
                      within ±margin of the threshold (low confidence)
      min_confidence  smallest |noul - threshold| along the path (how close to a coin-flip)
      all_nouls       every node's noul probability (the "every path" view)
    """
    answers = _decide(state, _questions(tree))
    nodes, leaves = tree["nodes"], tree["leaves"]

    all_nouls = {nid: (a.get("noul") if isinstance(a, dict) else None)
                 for nid, a in answers.items()}

    path: List[Dict[str, Any]] = []
    low_conf = False
    min_conf = 1.0
    cur = tree["root"]
    steps = 0
    while cur in nodes and steps < max_steps:
        steps += 1
        n = nodes[cur]
        ans = answers.get(cur)
        noul = ans.get("noul") if isinstance(ans, dict) else None
        if noul is None:
            # Jev didn't answer this node — cannot branch confidently.
            low_conf = True
            branch = "no"
        else:
            branch = "yes" if noul >= threshold else "no"
            dist = abs(noul - threshold)
            min_conf = min(min_conf, dist)
            if dist < margin:
                low_conf = True
        path.append({"node": cur, "instructions": n["instructions"],
                     "noul": noul, "branch": branch})
        cur = n[branch]

    if cur not in leaves:
        raise TreeError(f"walk did not terminate at a leaf (stopped at {cur!r})")
    leaf = leaves[cur]
    cid = leaf.get("candidate")
    cand = tree["candidates"].get(cid) if cid else None
    return {
        "path": path,
        "leaf": cur,
        "candidate_id": cid,
        "candidate_title": (cand or {}).get("title"),
        "fix": (cand or {}).get("fix"),
        "escalate": bool(leaf.get("escalate")) or low_conf,
        "escalate_note": leaf.get("note"),
        "min_confidence": None if not path else round(min_conf, 4),
        "all_nouls": all_nouls,
    }
