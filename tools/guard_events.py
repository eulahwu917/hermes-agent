"""Guard event ledger -- the single writer for ``$HERMES_HOME/security/guard_events.jsonl``.

One append-only JSONL row per guard event, so denial / carryover / scanner-degradation
transitions are reviewable without diffing transcripts. Both the approval layer
(``tools.approval``) and the scanner wrapper (``tools.tirith_security``) write here, so the
row schema and the rotation rule exist exactly once.

Vocabulary -- these states are NOT interchangeable, and no consumer may relabel one as another:

``kind``
    ``denied``       a command carrying a tracked override was DENIED by the guard.
    ``carryover``    a previously denied override value re-appeared in a later command.
    ``degradation``  the scanner could not scan, so the decision was made WITHOUT it.
``outcome``
    ``blocked``      the guard refused the command.
    ``admitted``     an explicitly trusted path (yolo / mode=off / allowlist / approve-context
                     / isolated container) let a re-appearing value through. This is NOT a
                     denial, and NOT evidence that the command executed.
    ``allowed``      the guard permitted the command (used by degradation rows).
``phase``
    ``approval``     the first pass of the gate for this command.
    ``replay``       a user-confirmed (``force``) replay of an earlier pending request.

A ledger write must NEVER be able to change a guard verdict: every failure path here is
swallowed to a debug log.

Raw-text policy (pending David's D2 ruling on the guard ledger)
    The ``value`` / ``command`` fields of the ``denied`` and ``carryover`` rows are written as
    raw, truncated text today, and the ledger file/dir permissions are not explicitly set
    (umask default). Both are the subject of the open D2 decision (digests + force-redacted
    excerpts + owner-only permissions, or an explicit retention/opt-in policy). Nothing in
    this module changes that policy -- the degradation rows deliberately carry NO raw command
    text, so the pending decision stays confined to the denial rows.
"""

import json
import logging
import os
import time

from hermes_constants import get_hermes_home, hermes_home_key

logger = logging.getLogger(__name__)

LEDGER_MAX_BYTES = 4 * 1024 * 1024
LEDGER_DIR_NAME = "security"
LEDGER_NAME = "guard_events.jsonl"
_VALUE_MAX_CHARS = 500
_COMMAND_MAX_CHARS = 1000
_SOURCE_MAX_CHARS = 500

KIND_DENIED = "denied"
KIND_CARRYOVER = "carryover"
KIND_DEGRADATION = "degradation"

OUTCOME_BLOCKED = "blocked"
OUTCOME_ADMITTED = "admitted"
OUTCOME_ALLOWED = "allowed"

PHASE_APPROVAL = "approval"
PHASE_REPLAY = "replay"


def ledger_path() -> str:
    """Absolute path of the guard event ledger for the active HERMES_HOME."""
    return os.path.join(str(get_hermes_home()), LEDGER_DIR_NAME, LEDGER_NAME)


def _profile_key() -> str:
    """Home/profile this process is serving (``~/.hermes`` -> ``.hermes``, a profile dir -> its name)."""
    try:
        return os.path.basename(str(get_hermes_home()).rstrip(os.sep)) or hermes_home_key()
    except Exception:  # pragma: no cover - defensive, the ledger must never raise
        return ""


def record_guard_event(kind: str, session: str, *, outcome: str = "", var: str = "",
                       value: str = "", source: str = "", command: str = "", phase: str = "",
                       extra: dict | None = None) -> None:
    """Append one event row. Never raises -- callers are guard verdict paths.

    ``var``/``value``/``source``/``command``/``phase`` are omitted from the row when empty so a
    degradation row carries only its structured fields. ``extra`` merges additional
    event-specific fields (e.g. the degradation reason/paths/acknowledgement source).
    """
    row = {"ts": time.time(), "kind": kind, "session": session, "profile": _profile_key(),
           "outcome": outcome}
    if var:
        row["var"] = var[:200]
        row["value"] = value[:_VALUE_MAX_CHARS]
    if source:
        row["source"] = source[:_SOURCE_MAX_CHARS]
    if command:
        row["command"] = command[:_COMMAND_MAX_CHARS]
    if phase:
        row["phase"] = phase
    if extra:
        row.update({k: v for k, v in extra.items() if v not in ("", None)})
    logger.warning("[guard-event] %s", json.dumps(row, default=str))
    try:
        path = ledger_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.isfile(path) and os.path.getsize(path) > LEDGER_MAX_BYTES:
            os.rename(path, path + ".prev")
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, default=str) + "\n")
    except Exception as exc:  # never alter a guard verdict
        logger.debug("guard event ledger write failed: %s", exc)
