"""Client for Jev — TypeSafe's "System One" Decisions API, served via OpenRouter.

Jev answers *typed* questions about a `state` and returns structured decisions with
probabilities (no free text → no hallucination). We use the `noul` type (binary
yes/no → probability in [0,1]) to classify at each node of a playbook decision tree.

Key API property this client is built around: **questions are non-conditional** — every
question in a request is evaluated in parallel against the same `state` (they cannot see
each other's answers). So a *tree walk* is orchestrated by the caller: send all node
questions in one `decide()` call, then traverse client-side (see tools/playbook_tree.py).

External hosted dependency, reached only via the flag-gated `consult_playbook` tool
(config.PLAYBOOK_WALK_ENABLED, default off) and lazy-imported there — so `requests` /
OpenRouter is never loaded on the core agent path when the flag is off.
Modeled on tools/zendesk_client.py (env-read auth, custom error, explicit timeouts).

Env:
  OPENROUTER_API_KEY   (required)
  OPENROUTER_BASE_URL  (default https://openrouter.ai/api/alpha)
  JEV_MODEL            (default typesafe/jev-1.13)
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

_DEFAULT_BASE_URL = "https://openrouter.ai/api/alpha"
_DEFAULT_MODEL = "typesafe/jev-1.13"
_TIMEOUT_SECONDS = 30


class JevError(RuntimeError):
    """A Jev / OpenRouter request failed. Carries the HTTP status when available so
    callers can render a clean message instead of a stack trace."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


def is_configured() -> bool:
    return bool(os.environ.get("OPENROUTER_API_KEY"))


def missing_config() -> List[str]:
    return [] if is_configured() else ["OPENROUTER_API_KEY"]


def _base_url() -> str:
    return os.environ.get("OPENROUTER_BASE_URL", _DEFAULT_BASE_URL).rstrip("/")


def _model() -> str:
    return os.environ.get("JEV_MODEL", _DEFAULT_MODEL)


def _headers() -> Dict[str, str]:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise JevError("OPENROUTER_API_KEY is not set")
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}


# --------------------------------------------------------------------------- #
# Request/response logging (append-only JSONL). One line per decide() call:
# the full request (state + questions) and the response (answers + usage) or the
# error. The Authorization header / API key is NEVER logged. Disable with JEV_LOG=0;
# override the directory with JEV_LOG_DIR (default <cwd>/logs, matching the repo's
# logs/ convention).
# --------------------------------------------------------------------------- #

def log_path() -> str:
    log_dir = os.environ.get("JEV_LOG_DIR") or os.path.join(os.getcwd(), "logs")
    return os.path.join(log_dir, f"jev_calls_{datetime.now():%Y%m%d}.jsonl")


def _logging_enabled() -> bool:
    return os.environ.get("JEV_LOG", "1").lower() not in ("0", "false", "no")


def _log_call(record: Dict[str, Any]) -> None:
    """Append one JSON record; never let a logging failure break the API call."""
    if not _logging_enabled():
        return
    try:
        path = log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except Exception:  # noqa: BLE001 — logging is best-effort
        pass


def decide(state: Any, questions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Ask Jev a batch of typed questions about `state`. Returns the `answers` dict,
    keyed by question id — e.g. {"n_ts": {"type": "noul", "noul": 0.94}, ...}.

    `state`     — any JSON-serializable context object the model reasons over.
    `questions` — {question_id: {"type": "noul"|"choice"|"score", "instructions": str,
                                 "criteria": {...}}}.
    Raises JevError on transport / HTTP / shape problems (never leaks a stack trace)."""
    if not questions:
        return {}
    url = f"{_base_url()}/decisions"
    payload = {"model": _model(), "state": state, "questions": questions}
    t0 = time.monotonic()

    def _log(*, status=None, answers=None, usage=None, error=None):
        _log_call({
            "ts": datetime.now().isoformat(timespec="seconds"),
            "model": payload["model"], "url": url,
            "request": {"state": state, "questions": questions},
            "status": status, "answers": answers, "usage": usage, "error": error,
            "latency_ms": int((time.monotonic() - t0) * 1000),
        })

    try:
        resp = requests.post(url, headers=_headers(), json=payload, timeout=_TIMEOUT_SECONDS)
    except requests.RequestException as e:
        _log(error=f"transport: {e}")
        raise JevError(f"Jev request failed: {e}") from e
    if resp.status_code == 401:
        _log(status=401, error=resp.text[:300])
        raise JevError(
            "Jev auth failed (401) — check OPENROUTER_API_KEY. "
            f"OpenRouter said: {resp.text[:300]}",
            status_code=401,
        )
    if not resp.ok:
        _log(status=resp.status_code, error=resp.text[:300])
        raise JevError(
            f"Jev API error {resp.status_code}: {resp.text[:300]}",
            status_code=resp.status_code,
        )
    try:
        body = resp.json()
    except ValueError as e:
        _log(status=resp.status_code, error=f"non-JSON: {e}")
        raise JevError(f"Jev returned non-JSON: {e}") from e
    answers = body.get("answers")
    if not isinstance(answers, dict):
        _log(status=resp.status_code, error="missing 'answers'")
        raise JevError(f"Jev response missing 'answers': {str(body)[:300]}")
    _log(status=resp.status_code, answers=answers, usage=body.get("usage"))
    return answers


def noul_question(instructions: str, true_criterion: str, false_criterion: str) -> Dict[str, Any]:
    """Convenience builder for a single noul (yes/no) question."""
    return {
        "type": "noul",
        "instructions": instructions,
        "criteria": {"true": true_criterion, "false": false_criterion},
    }
