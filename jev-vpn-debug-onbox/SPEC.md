# On-box VPN Quick-Debug — Jev Playbook Walk (Go Porting Spec)

**Audience:** the on-box management system team (Go).
**Goal:** run the same deterministic VPN diagnosis the RCA agent uses, but as a
standalone on-box tool — **100% code + Jev, no LLM agent.** Given a live device,
name a tunnel/peer, get back a calibrated candidate cause + fix in one Jev call.

This is a **reimplementation** spec, not a library import (the reference impl is
Python). The *reusable asset* is the two playbook **JSON files** in `playbooks/`
— your Go code is an interpreter of that data. The Python files in `reference/`
are the authoritative behavior spec; when this document and the code disagree,
the code wins — cite it.

---

## 1. Architecture

Four pieces. Only the first is environment-specific; the rest are pure logic
over data + one HTTP call.

```
┌─ EvidenceSource ──┐   reads raw command/log text
│  (on-box: SSH)    │   e.g. `swanctl --list-sas`, `wg show`, `service show debug-logs vpn`
└─────────┬─────────┘
          ▼
┌─ Evidence engine ─┐   playbook_evidence.py  — enumerate/resolve scope, scope+dedup, assemble `state`
└─────────┬─────────┘
          ▼
┌─ Tree walk ───────┐   playbook_tree.py      — one Jev call for all nodes, traverse client-side
└─────────┬─────────┘
          ▼
┌─ Jev client ──────┐   jev_client.py         — POST /decisions, parse noul answers
└───────────────────┘

Data (drives all of it): playbooks/<doc_id>.tree.json  — tree + evidence spec + node criteria
```

**Flow (no agent):**
```
tree   := loadTree("playbooks/s2s-vpn-troubleshooting.tree.json")
src    := NewOnboxSource(sshExec)                     // runs live commands
scopes := EnumerateScopes(src, tree.Evidence)          // list tunnels/peers
name   := ResolveScope(src, tree.Evidence, userArg)    // pick the tunnel (or "which?" if ambiguous)
state  := GatherState(src, tree.Evidence, name, window)// live cmd output, scoped + deduped
result := Walk(tree, map{"case_evidence": state})      // ONE Jev call
// result.CandidateID, .CandidateTitle, .Fix, .Escalate, .Path
```

---

## 2. The playbook JSON (the data contract)

Top-level keys (see `playbooks/*.tree.json`):

| key | meaning |
|---|---|
| `doc_id` | playbook id, e.g. `s2s-vpn-troubleshooting` |
| `root` | id of the first node to evaluate |
| `evidence` | how to gather the `state` (see §3) |
| `nodes` | `{node_id: Node}` — the decision nodes |
| `leaves` | `{leaf_id: {candidate?, escalate?, note?}}` |
| `candidates` | `{cand_id: {id, title, mechanism, fix}}` — the diagnoses |
| `defers` | optional `{cand_id: other_playbook}` |

**Node** (all nodes are type `noul` = binary yes/no):
```json
"n_s_handshake": {
  "type": "noul",
  "instructions": "Does `wg show` report a recent latest handshake ...?",
  "criteria": { "true": "recent handshake + transfer ...", "false": "'latest handshake: (never)' ..." },
  "yes": "n_s_allowedips",     // next node id or leaf id if noul >= 0.5
  "no":  "n_s_inbound_permit"  // next node id or leaf id if noul <  0.5
}
```
`yes`/`no` targets resolve to either another node or a leaf. A leaf ends the walk.

**Leaf:** `{"candidate": "B3"}` (maps to a diagnosis) or
`{"candidate": null, "escalate": true, "note": "..."}` (no confident cause).

---

## 3. Evidence block (`tree.evidence`)

Declares which raw sources to read and how to scope/assemble them. Fields:

```jsonc
"evidence": {
  "scope_noun": "tunnel",              // or "peer" (WG) — for the "which one?" prompt
  "live_commands": {                   // ON-BOX: logical source name -> live command
    "swanctl_list_sas":   "swanctl --list-sas",
    "swanctl_list_conns": "swanctl --list-conns",
    "swanctl_counters":   "swanctl --counters",
    "s2s_vpn_log":        "service show debug-logs vpn"
  },
  "max_state_chars": 15000,            // hard cap on assembled state
  "max_log_events": 60,                // cap on distinct log-event templates

  "enumerate": {                       // how to list scopes (tunnels/peers)
    "file": "swanctl_list_conns",      // logical source name
    "block_header_regex": "^(?P<name>\\S.*?): IKE",   // names each scope (group `name`)
    "peer_regex":   "^\\s*remote:\\s*(\\S+)",          // a matchable peer field (optional)
    "subnet_regex": "^\\s+(?:local|remote):\\s+(.+)$", // matchable subnets (optional)
    "state_from": {                    // optional: annotate scope with a state word
      "file": "swanctl_list_sas",
      "block_header_regex": "^(?P<name>\\S.*?): #\\d+, (?P<state>[A-Z_]+),",
      "state_group": "state"
    }
  },

  "cmd_sources": [                     // command outputs included in `state`
    {"file":"swanctl_list_sas","label":"swanctl_list_sas (verbatim)",
     "scope":"block","block_header_regex":"^(?P<name>\\S.*?): #\\d+, [A-Z_]+,"},
    {"file":"swanctl_counters","label":"counters (key rows)",
     "scope":"grep","grep_regex":"\\b(ike-|create-child|invalid|info-)"},
    {"file":"show_config","label":"show_config","scope":"none"}
  ],

  "log_sources": [                     // logs — parsed, deduped, windowed
    {"file_glob":"s2s_vpn_log*","kind":"jsonl","msg_field":"msg","time_field":"time",
     "event_regex":"ikesa-name:\\s*(?P<scope>.*?),\\s*msg:\\s*(?P<event>.*?)\\s*$",
     "label":"IKE log events"}
  ]
}
```

**`scope` on a cmd source:**
- `"block"` — keep only the scoped tunnel/peer's block (needs `block_header_regex`); optional `"include_preamble": true` also keeps text before the first block (e.g. the `wg show` interface header).
- `"grep"` — keep lines matching `grep_regex` (global, not per-scope).
- `"none"`/`"all"` — include the whole output verbatim (used for global context like `show_config`, `show_feature_license`).

**On-box source resolution:** to read logical source `X`, run
`evidence.live_commands[X]` over SSH and use stdout. (In the Python/techdump
world the same `X` is a file under `cmds/`; on-box it's a live command.) For a
**log source**, `service show debug-logs vpn` returns the log text directly —
feed its stdout into the log parser (§3.2) the same way.

### 3.1 Block splitting (`_split_blocks`)
Split text into `{scope_name: block}` using `block_header_regex` (must contain a
named group `name`). A block header is a line matching the regex **at column 0**
(not indented); indented matches are part of the current block (e.g. nested
`CHILD_SA` / child lines). Text before the first header is the "preamble".
Go: `regexp` supports `(?P<name>...)`; iterate lines, start a new block on a
column-0 match, else append to current (or preamble). See `_split_blocks`.

### 3.2 Log parsing + normalization (`_log_events`, `_normalize_template`)
For each log line: if `kind == "jsonl"`, parse JSON and take `msg_field` +
`time_field`; else use the raw line. If `event_regex` is set, apply it —
`scope` group must equal the scope name (or the scope name appears in the
`event` group) to keep the line. Then **window** by ISO timestamp if a window
is given.

**Dedup by NORMALIZED template** (critical — this is what makes diagnosis work):
before counting, normalize volatile tokens so repeated templates collapse into
one `(xN)` line, freeing the event budget for *diverse* event types. Apply these
substitutions to the dedup key (display the normalized form):
```
\[\d+\]            -> ""            (SA / child indices: "IKE_SA X[17]" -> "IKE_SA X")
(?i)message ID \d+ -> "message ID N"
(?i)retransmit \d+ of -> "retransmit N of"
\(\d+/\d+\)        -> "(N/M)"       ("trying again (3/0)")
\(\d+ bytes\)      -> "(N bytes)"
\s{2,}             -> " "
```
Keep the earliest timestamp per template; emit up to `max_log_events`, sorted by
timestamp, each as `"<ts>  <template>  (xN)"`. **Do not** dedup on the raw line —
that lets 60 near-identical `initiating IKE_SA[1..60]` lines crowd out the
diagnostic `peer not responding` / `giving up after 5 retransmits` events. (This
was a real bug we fixed; see `_DEFAULT_NORM` in `reference/playbook_evidence.py`.)

### 3.3 `gather_state`
Assemble: `--- scope: <name> ---`, then each `cmd_source` (label + scoped body),
then each `log_source` (label + deduped events). Truncate to `max_state_chars`.
This exact text is what Jev reasons over. **Keep it verbatim** — Jev is robust
to raw command output; do not summarize or editorialize.

### 3.4 Scope resolution (`resolve_scope`)
Match the caller's arg to a scope: exact name (case-insensitive), then substring
on name / peer / subnets. Return `(name, "ok"|"ambiguous"|"none")`. If a single
scope exists, use it even on no match. On `ambiguous`/`none`, present the
`scopes_summary` list and ask the operator to pick — never guess.

---

## 4. The walk algorithm (`playbook_tree.walk`)

Jev questions are **non-conditional** (all evaluated in parallel against one
`state`), so send every node's question in ONE `decide()` call, then traverse
client-side:

```
questions := { node_id: {type:"noul", instructions, criteria} for each node }
answers   := jev.decide(state, questions)          // ONE call; answers[id].noul in [0,1]

cur := tree.root ; path := []
minConf := 1.0 ; lowConf := false
while cur is a node:
    noul := answers[cur].noul
    if noul == nil: branch := "no"; lowConf := true          // unanswered -> can't commit
    else:
        branch := (noul >= 0.5) ? "yes" : "no"               // THRESHOLD = 0.5
        dist := abs(noul - 0.5)
        minConf := min(minConf, dist)
        if dist < 0.10: lowConf := true                      // MARGIN = 0.10
    path.append({cur, noul, branch})
    cur := tree.nodes[cur][branch]
// cur is now a leaf
leaf := tree.leaves[cur]
return {
  path, leaf: cur,
  candidate_id:    leaf.candidate,                            // may be null
  candidate_title: candidates[leaf.candidate].title,
  fix:             candidates[leaf.candidate].fix,
  escalate:        leaf.escalate || lowConf,                  // escalate if leaf says so OR any on-path node was a near-coin-flip
  min_confidence:  round(minConf, 4),
}
```

**Semantics:** `escalate=true` means "low confidence — verify independently / run
the differential yourself." Distance from 0.5 is confidence; within ±0.10 of 0.5
flags the whole walk as escalate. Constants: `threshold=0.5`, `margin=0.10`.
Note probabilities vary slightly run-to-run, so a node near the margin may flip
the escalate flag between runs while the landed candidate stays stable.

**`validate(tree)`** before first use: root exists; every node's `yes`/`no`
resolves to a node or leaf; every node has non-empty `instructions` + a
`criteria` object; every leaf `candidate` (if non-null) exists in `candidates`.

---

## 5. Jev API contract (`jev_client.py`)

- **Endpoint:** `POST https://openrouter.ai/api/alpha/decisions`
  (base overridable via `OPENROUTER_BASE_URL`, default `https://openrouter.ai/api/alpha`)
- **Auth:** header `Authorization: Bearer $OPENROUTER_API_KEY`
- **Model:** `typesafe/jev-1.13` (pin it; overridable via `JEV_MODEL`)
- **Timeouts:** explicit connect+read timeout; treat non-200 / network error as
  "Jev unavailable" (see §6 fallback). A 401 means bad/rotated key.

**Request:**
```json
{
  "model": "typesafe/jev-1.13",
  "state": { "case_evidence": "<the gather_state text>" },
  "questions": {
    "n_sa_installed": {
      "type": "noul",
      "instructions": "Is an IPsec Child SA currently INSTALLED for this tunnel?",
      "criteria": { "true": "swanctl_list_sas shows a Child SA in INSTALLED state",
                    "false": "no INSTALLED Child SA — the tunnel has not established" }
    },
    "n_no_ike": { "type": "noul", "instructions": "...", "criteria": { "true": "...", "false": "..." } }
    /* ... one entry per node in the tree ... */
  }
}
```

**Response:**
```json
{
  "answers": {
    "n_sa_installed": { "type": "noul", "noul": 0.06 },
    "n_no_ike":       { "type": "noul", "noul": 0.85 }
    /* ... one per question ... */
  },
  "usage": { "input_tokens": 1234, "cost": 0.0001 }
}
```
`noul` ∈ [0,1] is P(criteria.true). Billed on input tokens only. Jev returns
**structured probabilities, not free text** — no hallucination; that's the whole
point of using it here. A real captured call is in `example/jev_call_example.json`.

**Logging (recommended):** log each call's request/answers/usage/latency to a
local file (the Python impl writes JSONL to `logs/jev_calls_*.jsonl`). **Never
log the API key.** This is what lets you answer "what did we send Jev and why did
a node read low" after the fact.

---

## 6. On-box specifics

- **Execution:** the on-box UI runs commands over SSH and captures stdout. To read
  a source, run `evidence.live_commands[<source>]` and use the result. Confirm each
  command against the target shell (restricted NSE CLI vs. raw shell) — the map in
  the JSON is the starting point; adjust there (data, not code) if a command name
  differs on the box.
- **Logs:** `service show debug-logs vpn` returns the VPN debug log text; feed its
  stdout to the log parser exactly as if it were `s2s_vpn_log`. (WireGuard needs no
  log source today — `wg show` state is sufficient.)
- **Offline / Jev-unreachable fallback (required):** if the device has no egress to
  the Jev endpoint or the call errors/times out, the tool must **degrade
  gracefully** — return "Jev unavailable; showing raw evidence" with the assembled
  `state` and the playbook's candidate list, not crash. The walk is advisory; the
  operator can still read the evidence.
- **Cost/latency:** one batched Jev call per debug (all nodes at once). Cheap
  (~$0.0001) and a single round-trip.

---

## 7. What to display

The verdict is **advisory — a strong prior, not a verdict to act on blindly**:

- `candidate_id` + `candidate_title` + `fix` (from `candidates[...]`)
- `escalate` flag — if true, show "low confidence, verify manually"
- `path` — the node→noul→branch trail (great for operator trust/debugging)
- If `candidate_id` is null (escalate leaf) — show the leaf `note` and the
  playbook's full differential.

---

## 8. Scope & non-goals

- **In scope:** S2S IPsec (`s2s-vpn-troubleshooting`) and WireGuard
  (`wireguard-vpn-troubleshooting`). Both trees are in `playbooks/`.
- **Maturity:** the S2S tree is tuned; the **WireGuard tree is a first cut** —
  role/handshake nodes are sharp, but deeper traffic nodes (allowedips/snat/mtu)
  can read near coin-flip and escalate (correct, honest behavior; sharpening them
  needs a tuning pass + more evidence sources like `nft`/`ip route`).
- **Not included:** the RCA agent, techdump pipeline, or any LLM. This is the
  deterministic walk only.
- **Stay in sync:** both the Python agent and this Go tool consume the *same*
  `playbooks/*.tree.json`. Treat those files as the shared source of truth — when
  a tree is retuned, both sides pick it up. Don't fork the JSON.

---

## 9. Files in this handoff

```
SPEC.md                                   ← this document
playbooks/
  s2s-vpn-troubleshooting.tree.json       ← ship as data (tuned)
  wireguard-vpn-troubleshooting.tree.json ← ship as data (first cut)
reference/                                ← authoritative behavior spec (Python)
  jev_client.py                           ← §5  (POST /decisions, noul)
  playbook_tree.py                        ← §4  (walk, validate)
  playbook_evidence.py                    ← §3  (enumerate/resolve/gather_state, split, normalize)
example/
  jev_call_example.json                   ← a real captured decide() request/response
```

Port order suggestion: (1) Jev client + one hardcoded question → confirm auth &
shape; (2) `walk` over a bundled tree with a hand-written `state` → confirm
traversal; (3) evidence engine with live commands → end-to-end. Validate against
the Python impl's output on the same inputs at each step.
