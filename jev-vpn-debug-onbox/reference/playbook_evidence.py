"""Generic, spec-driven evidence gatherer for the playbook decision-tree walk.

There is NO per-playbook code here. Each playbook's `<doc_id>.tree.json` carries an
`evidence` block that declares WHICH raw files to read and HOW to scope them; this module
interprets that block for any playbook. Jev reads the assembled raw text and applies the
per-node criteria (the "internals" live in the criteria + the raw output we feed it, not
in Python) — so adding a playbook is authoring one JSON, not writing an extractor.

The Jev *walk* is deterministic, but choosing WHICH tunnel/peer + WHICH window is a
semantic step only the agent can do — so the agent supplies the scope and this module
deterministically pulls that scope's raw evidence from the loaded techdump on disk.

Evidence-block schema (all fields optional unless noted):

  "evidence": {
    "scope_noun": "tunnel",                 # for the "which tunnel?" message
    "max_state_chars": 15000,               # size cap on the assembled state
    "max_log_events": 60,                   # cap on distinct log events

    "enumerate": {                          # how to list scopes (the "which?" hatch + resolve)
      "file": "swanctl_list_conns",
      "block_header_regex": "^(?P<name>\\S.*?): IKE",   # names each scope
      "peer_regex":   "^\\s*remote:\\s*(\\S+)",         # a matchable peer field (optional)
      "subnet_regex": "^\\s+(?:local|remote):\\s+(.+)$",# matchable subnets (optional)
      "state_from": {                       # optional: annotate each scope with a state word
        "file": "swanctl_list_sas",
        "block_header_regex": "^(?P<name>\\S.*?): #\\d+, (?P<state>[A-Z_]+),",
        "state_group": "state"
      }
    },

    "cmd_sources": [                        # verbatim cmd files, scoped
      {"file": "swanctl_list_sas", "label": "swanctl_list_sas (verbatim)",
       "scope": "block", "block_header_regex": "^(?P<name>\\S.*?): #\\d+,"},
      {"file": "swanctl_counters", "label": "counters (key rows)",
       "scope": "grep", "grep_regex": "\\b(ike-|create-child|invalid)"},
      {"file": "show_config", "label": "show_config", "scope": "none"}
    ],

    "log_sources": [                        # jsonl/plain logs, deduped + windowed
      {"file_glob": "s2s_vpn_log*", "kind": "jsonl",
       "msg_field": "msg", "time_field": "time",
       "event_regex": "ikesa-name:\\s*(?P<scope>.*?),\\s*msg:\\s*(?P<event>.*?)\\s*$",
       "label": "IKE log events"}
    ]
  }

`scope` on a cmd source: "block" keeps only the scoped block (needs block_header_regex),
"grep" keeps lines matching grep_regex (global), "none"/"all" includes the file verbatim.
"""
from __future__ import annotations

import glob
import gzip
import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

_DEFAULT_MAX_STATE_CHARS = 15000
_DEFAULT_MAX_LOG_EVENTS = 60


# --------------------------------------------------------------------------- #
# File access (off the loaded dump)
# --------------------------------------------------------------------------- #

def _read_cmd(ctx, name: str) -> str:
    p = os.path.join(ctx.base_dir, "cmds", name)
    if not os.path.isfile(p):
        return ""
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _iter_log_lines(ctx, file_glob: str):
    """Yield raw lines from a log file glob + its rotations (.N and .gz)."""
    for p in sorted(glob.glob(os.path.join(ctx.log_base_path, file_glob))):
        if os.path.basename(p).endswith(".csv"):
            continue
        try:
            opener = gzip.open if p.endswith(".gz") else open
            with opener(p, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line
        except OSError:
            continue


# --------------------------------------------------------------------------- #
# Generic block splitting (reproduces swanctl/wg per-scope blocks)
# --------------------------------------------------------------------------- #

def _split_blocks(text: str, header_regex: str) -> Tuple[str, Dict[str, str]]:
    """Split `text` into {scope_name: verbatim block} using a column-0 header regex
    with a named group `name`. Returns (preamble, blocks) — preamble is any text
    before the first header (e.g. the wg `interface:` section)."""
    rx = re.compile(header_regex)
    lines = text.splitlines()
    preamble: List[str] = []
    blocks: Dict[str, str] = {}
    cur_name: Optional[str] = None
    buf: List[str] = []

    def _flush():
        if cur_name is not None:
            blocks[cur_name] = (blocks.get(cur_name, "") + "\n".join(buf)).rstrip() + "\n"

    for line in lines:
        m = rx.match(line)
        # a scope header is at column 0 (not indented); indented matches are nested
        if m and m.groupdict().get("name") and not line[:1].isspace():
            _flush()
            cur_name = m.group("name")
            buf = [line]
        elif cur_name is None:
            preamble.append(line)
        else:
            buf.append(line)
    _flush()
    return ("\n".join(preamble).rstrip(), blocks)


# --------------------------------------------------------------------------- #
# Scope enumeration + resolution (the "which tunnel/peer?" safety hatch)
# --------------------------------------------------------------------------- #

def enumerate_scopes(ctx, spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """List the dump's scopes (tunnels/peers) per the enumerate spec."""
    enum = (spec or {}).get("enumerate") or {}
    if not enum.get("file") or not enum.get("block_header_regex"):
        return []
    _, blocks = _split_blocks(_read_cmd(ctx, enum["file"]), enum["block_header_regex"])

    # optional state annotation from a second file
    states: Dict[str, str] = {}
    sf = enum.get("state_from")
    if sf and sf.get("file") and sf.get("block_header_regex"):
        rx = re.compile(sf["block_header_regex"])
        for line in _read_cmd(ctx, sf["file"]).splitlines():
            m = rx.match(line)
            if m and not line[:1].isspace():
                states[m.group("name")] = m.groupdict().get(sf.get("state_group", "state"), "") or ""

    peer_rx = re.compile(enum["peer_regex"], re.MULTILINE) if enum.get("peer_regex") else None
    sub_rx = re.compile(enum["subnet_regex"], re.MULTILINE) if enum.get("subnet_regex") else None
    out: List[Dict[str, Any]] = []
    for name, block in blocks.items():
        peer = ""
        if peer_rx:
            pm = peer_rx.search(block)
            if pm:
                peer = pm.group(1)
        subnets = sub_rx.findall(block) if sub_rx else []
        out.append({"name": name, "peer": peer, "subnets": subnets[-2:],
                    "state": states.get(name, "")})
    return out


def resolve_scope(ctx, spec: Dict[str, Any], scope: str) -> Tuple[Optional[str], str]:
    """Match the caller's `scope` arg to a scope name. Returns (name, status) where
    status is 'ok' | 'ambiguous' | 'none'. Exact name first, then substring on
    name / peer / subnets."""
    scopes = enumerate_scopes(ctx, spec)
    if not scopes:
        return None, "none"
    t = (scope or "").strip().lower()
    if not t:
        return (scopes[0]["name"], "ok") if len(scopes) == 1 else (None, "ambiguous")
    exact = [x for x in scopes if x["name"].lower() == t]
    if len(exact) == 1:
        return exact[0]["name"], "ok"
    hits = [x for x in scopes
            if t in x["name"].lower()
            or t in (x["peer"] or "").lower()
            or any(t in s.lower() for s in x["subnets"])]
    if len(hits) == 1:
        return hits[0]["name"], "ok"
    if len(hits) > 1:
        return None, "ambiguous"
    if len(scopes) == 1:
        return scopes[0]["name"], "ok"
    return None, "none"


def scopes_summary(ctx, spec: Dict[str, Any]) -> str:
    noun = (spec or {}).get("scope_noun", "tunnel")
    lines = []
    for x in enumerate_scopes(ctx, spec):
        extra = f", {x['state']}" if x.get("state") else ""
        lines.append(f"  - {x['name']}  (peer {x['peer'] or '?'}{extra})")
    return "\n".join(lines) if lines else f"  (no {noun}s found in this dump)"


# --------------------------------------------------------------------------- #
# Scoped state assembly
# --------------------------------------------------------------------------- #

def _in_window(ts: str, start: Optional[str], end: Optional[str]) -> bool:
    if not start and not end:
        return True
    try:
        t = datetime.fromisoformat(ts)
    except ValueError:
        return True
    try:
        if start and t < datetime.fromisoformat(start):
            return False
        if end and t > datetime.fromisoformat(end):
            return False
    except ValueError:
        return True
    return True


# Volatile tokens stripped from the DEDUP KEY (not the meaning) so repeated event
# templates collapse into one `(xN)` line instead of N near-duplicates that crowd out
# the diagnostic variety. Example: "initiating IKE_SA X[1]..[76]" → one line, freeing
# budget for "peer not responding" / "giving up after 5 retransmits". IPs, names, and
# notify payloads are preserved — only counters/indices/sizes are generalized.
_DEFAULT_NORM = [
    (re.compile(r"\[\d+\]"), ""),                       # SA / child indices
    (re.compile(r"message ID \d+", re.I), "message ID N"),
    (re.compile(r"retransmit \d+ of", re.I), "retransmit N of"),
    (re.compile(r"\(\d+/\d+\)"), "(N/M)"),              # "trying again (3/0)"
    (re.compile(r"\(\d+ bytes\)"), "(N bytes)"),
    (re.compile(r"\s{2,}"), " "),
]


def _normalize_template(inner: str, extra: Optional[List] = None) -> str:
    """Collapse volatile tokens so equivalent event templates dedup together."""
    s = inner
    for rx, repl in _DEFAULT_NORM:
        s = rx.sub(repl, s)
    for pat, repl in (extra or []):
        s = re.sub(pat, repl, s)
    return s.strip()


def _log_events(ctx, src: Dict[str, Any], scope_name: str,
                window: Optional[Tuple[Optional[str], Optional[str]]],
                max_events: int) -> List[str]:
    """Distinct log-event TEMPLATES for the scope (volatile IDs normalized so diverse
    event types survive the cap), with (xN) repeat counts, windowed, chronological."""
    start, end = (window or (None, None))
    tl = scope_name.lower()
    event_rx = re.compile(src["event_regex"]) if src.get("event_regex") else None
    extra_norm = src.get("dedup_extra_norm")   # optional per-source [ [pattern, repl], ... ]
    seen: Dict[str, Dict[str, Any]] = {}
    for raw in _iter_log_lines(ctx, src["file_glob"]):
        raw = raw.strip()
        if not raw:
            continue
        ts, msg = "", raw
        if src.get("kind") == "jsonl":
            if '"' + src.get("msg_field", "msg") + '"' not in raw:
                continue
            try:
                obj = json.loads(raw)
            except ValueError:
                continue
            msg = obj.get(src.get("msg_field", "msg"), "")
            ts = obj.get(src.get("time_field", "time"), "")
        inner = msg
        if event_rx:
            m = event_rx.search(msg)
            if not m:
                continue
            gd = m.groupdict()
            ev_scope = gd.get("scope", "")
            inner = gd.get("event", msg)
            if not (ev_scope.lower() == tl or tl in inner.lower()):
                continue
        elif tl not in msg.lower():
            continue
        if not _in_window(ts, start, end):
            continue
        key = _normalize_template(inner, extra_norm)
        if key in seen:
            seen[key]["count"] += 1
        else:
            # display the normalized template (faithful log shape, volatile IDs generalized)
            seen[key] = {"ts": ts, "count": 1, "display": key}
    events = sorted(seen.items(), key=lambda kv: kv[1]["ts"])
    lines = []
    for _key, info in events[:max_events]:
        suffix = f"  (x{info['count']})" if info["count"] > 1 else ""
        lines.append(f"{(info['ts'] + '  ') if info['ts'] else ''}{info['display']}{suffix}")
    return lines


def gather_state(ctx, spec: Dict[str, Any], scope_name: str,
                 window: Optional[Tuple[Optional[str], Optional[str]]] = None) -> str:
    """Assemble the verbatim, scoped `state` for the Jev walk, per the evidence spec.
    Deterministic given (ctx, spec, scope_name, window)."""
    spec = spec or {}
    max_chars = spec.get("max_state_chars", _DEFAULT_MAX_STATE_CHARS)
    max_events = spec.get("max_log_events", _DEFAULT_MAX_LOG_EVENTS)
    parts: List[str] = [f"--- scope: {scope_name} ---"]

    for src in spec.get("cmd_sources", []):
        text = _read_cmd(ctx, src["file"])
        label = src.get("label", src["file"])
        mode = src.get("scope", "none")
        body = ""
        if not text.strip():
            body = f"({src['file']} not present)"
        elif mode == "block" and src.get("block_header_regex"):
            preamble, blocks = _split_blocks(text, src["block_header_regex"])
            blk = blocks.get(scope_name, "").strip()
            if src.get("include_preamble") and preamble.strip():
                blk = (preamble.strip() + "\n" + blk).strip()
            body = blk or f"(no block for {scope_name} in {src['file']})"
        elif mode == "grep" and src.get("grep_regex"):
            rx = re.compile(src["grep_regex"])
            rows = [ln for ln in text.splitlines() if rx.search(ln)]
            body = "\n".join(rows) if rows else f"(no matching rows in {src['file']})"
        else:  # none / all — verbatim
            body = text.strip()
        parts += [f"--- {label} ---", body]

    for src in spec.get("log_sources", []):
        label = src.get("label", src.get("file_glob", "log"))
        events = _log_events(ctx, src, scope_name, window, max_events)
        parts.append(f"--- {label} (deduped, chronological; (xN)=repeat count) ---")
        if events:
            parts.append("\n".join(events))
        else:
            windowed = window and (window[0] or window[1])
            parts.append(f"(no events for this scope{' in the given window' if windowed else ''})")

    state = "\n".join(parts)
    if len(state) > max_chars:
        state = state[:max_chars] + "\n…[evidence truncated to fit]"
    return state
