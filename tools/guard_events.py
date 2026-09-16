"""Guard event ledger -- the single writer for ``$HERMES_HOME/security/guard_events.jsonl``.

One append-only JSONL row per guard event, so denial / carryover / scanner-degradation
transitions are reviewable without diffing transcripts. Both the approval layer
(``tools.approval``) and the scanner wrapper (``tools.tirith_security``) write here, so the
row schema, the retention rule and the file permissions exist exactly once.

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

Raw-text policy (D2, ruled by David 2026-09-15 -- DIGESTS, not raw text)
    The ledger stores NO raw override value and NO raw command text. A ``denied`` / ``carryover``
    row carries ``value_digest`` / ``command_digest`` (stable sha256 of the raw text, so a human can
    still correlate repeats) plus light length metadata; ``var`` and ``source`` (a variable name and
    an absolute script path, neither of which is raw command text) are kept as-is because they are
    what makes a row attributable. No human-readable excerpt of the value or the command is written
    at all -- if one is ever added it MUST go through the redactor
    (``agent.redact.redact_sensitive_text(..., force=True)``), never a bare truncation.

    Raw-value MATCHING deliberately does not depend on the ledger: it lives in the approval layer's
    TTL'd, capped, in-memory per-session store (``tools.approval._denied_env_overrides``). Raw values
    are never persisted in order to make correlation work.

Permissions
    The security directory and the ledger file are owner-only: ``0700`` / ``0600``, set explicitly and
    idempotently on the write path (a creation mode alone is umask-masked). A mode that grants access to
    anyone besides the owner is REPAIRED and reported at WARNING; the writer NEVER adds group/other
    access, and a difference confined to the owner bits is normalised without a warning.

Retention
    ``LEDGER_MAX_BYTES``     size cap for the live ledger; exceeding it rotates. (module constant)
    ``.prev``                exactly ONE previous generation is kept -- each rotation overwrites it,
                             so archives do not accumulate.
    ``LEDGER_MAX_AGE_DAYS``  the age rule is applied to the generation rotation actually retains:
                             a rotated ledger older than the window is NOT kept as ``.prev``. The
                             operator knob is
                             ``security.guard_event_ledger_max_age_days`` in ``config.yaml``
                             (declared in ``hermes_cli/config_defaults.py``), overridden by the
                             ``HERMES_GUARD_LEDGER_MAX_AGE_DAYS`` environment variable.
"""

import hashlib
import json
import logging
import os
import stat
import time
from contextlib import suppress

from hermes_constants import get_hermes_home, hermes_home_key

logger = logging.getLogger(__name__)

LEDGER_MAX_BYTES = 4 * 1024 * 1024
LEDGER_MAX_AGE_DAYS = 30
LEDGER_MAX_AGE_ENV = "HERMES_GUARD_LEDGER_MAX_AGE_DAYS"
LEDGER_DIR_NAME = "security"
LEDGER_NAME = "guard_events.jsonl"
LEDGER_DIR_MODE = 0o700
LEDGER_FILE_MODE = 0o600
_OTHER_ACCESS = 0o077  # group + other bits: access by any principal besides the owner
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


def _digest(text: str) -> str:
    """Stable, non-reversible digest of a raw value/command: equal inputs correlate, text does not survive."""
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _enforce_mode(path: str, mode: int, *, fd: int | None = None) -> None:
    """Set the exact intended mode (idempotent); REPORT a change that removed non-owner access.

    Never adds group/other access (the target mode grants none). A mode that differs only in its
    owner bits is normalised without a warning -- that is not a security repair.
    """
    current = stat.S_IMODE(os.fstat(fd).st_mode if fd is not None else os.stat(path).st_mode)
    if current == mode:
        return
    if current & _OTHER_ACCESS:
        logger.warning("%s had mode %04o (accessible beyond the owner); tightening to %04o",
                       path, current, mode)
    if fd is not None:
        os.fchmod(fd, mode)
    else:
        os.chmod(path, mode)


def _ensure_private_dir(path: str) -> None:
    """Create ``path`` owner-only (0700); REPAIR an existing wider mode and report it."""
    os.makedirs(path, mode=LEDGER_DIR_MODE, exist_ok=True)
    _enforce_mode(path, LEDGER_DIR_MODE)


def _open_private_ledger(path: str) -> int:
    """Open the ledger for append, created 0600; REPAIR an existing wider mode and report it.

    The mode is enforced BEFORE the open when the file already exists, so a ledger whose owner bits
    were narrowed (e.g. a stray ``0400``) is repaired instead of silently swallowing every row: the
    write path must not become a silent no-op. Owner-only is preserved throughout -- the repair never
    grants group/other access.
    """
    if os.path.exists(path):
        with suppress(OSError):
            _enforce_mode(path, LEDGER_FILE_MODE)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, LEDGER_FILE_MODE)
    _enforce_mode(path, LEDGER_FILE_MODE, fd=fd)
    return fd


def _max_age_seconds() -> float:
    """Retention window for a retained previous generation.

    Operator knob: ``security.guard_event_ledger_max_age_days`` (config.yaml), overridden by the
    ``HERMES_GUARD_LEDGER_MAX_AGE_DAYS`` environment variable; falls back to the module default.
    Read per rotation (rare) so a config change applies without a restart, and never raises --
    an unreadable config must not block a ledger write.
    """
    days: float | None = None
    try:
        from hermes_cli.config import load_config_readonly
        raw = (load_config_readonly().get("security", {}) or {}).get("guard_event_ledger_max_age_days")
        if raw is not None:
            days = float(raw)
    except Exception:
        days = None
    env = os.getenv(LEDGER_MAX_AGE_ENV)
    if env:
        try:
            days = float(env)
        except ValueError:
            logger.warning("ignoring non-numeric %s=%r", LEDGER_MAX_AGE_ENV, env)
    if days is None:
        days = float(LEDGER_MAX_AGE_DAYS)
    return max(0.0, days) * 86400.0


def _rotate_if_needed(path: str) -> None:
    """Rotate to a single ``.prev`` generation once the live ledger exceeds the size cap.

    Retention at rotation: the file that rotation actually RETAINS is the live ledger itself
    (renamed aside to ``.prev``), so the maximum age is applied to THAT generation — the bytes
    that are kept — and not to the older ``.prev`` that is about to be overwritten anyway. A
    live ledger already older than the window is rotated out but NOT retained, so the window
    genuinely bounds the retained data instead of being a knob that changes nothing.
    """
    try:
        if not os.path.isfile(path) or os.path.getsize(path) <= LEDGER_MAX_BYTES:
            return
        retained_age = time.time() - os.path.getmtime(path)
    except OSError:
        return
    prev = path + ".prev"
    max_age = _max_age_seconds()
    os.replace(path, prev)
    try:
        _enforce_mode(prev, LEDGER_FILE_MODE)
    except OSError:
        pass
    if retained_age > max_age:
        logger.info("guard event ledger: not retaining a rotated generation older than %.0f days",
                    max_age / 86400.0)
        with suppress(OSError):
            os.unlink(prev)


def record_guard_event(kind: str, session: str, *, outcome: str = "", var: str = "",
                       value: str = "", source: str = "", command: str = "", phase: str = "",
                       extra: dict | None = None) -> None:
    """Append one event row. Never raises -- callers are guard verdict paths.

    ``value`` and ``command`` are passed in RAW and never stored raw: the row gets
    ``value_digest``/``value_len`` and ``command_digest``/``command_len`` instead (D2 -- digests,
    not raw text). ``var``/``source``/``phase`` are omitted from the row when empty so a
    degradation row carries only its structured fields. ``extra`` merges additional
    event-specific fields (e.g. the degradation reason/paths/acknowledgement source).
    """
    row = {"ts": time.time(), "kind": kind, "session": session, "profile": _profile_key(),
           "outcome": outcome}
    if var:
        row["var"] = var[:200]
    if value:
        row["value_digest"] = _digest(value)
        row["value_len"] = len(value)
    if source:
        row["source"] = source[:_SOURCE_MAX_CHARS]
    if command:
        row["command_digest"] = _digest(command)
        row["command_len"] = len(command)
    if phase:
        row["phase"] = phase
    if extra:
        row.update({k: v for k, v in extra.items() if v not in ("", None)})
    logger.warning("[guard-event] %s", json.dumps(row, default=str))
    try:
        path = ledger_path()
        _ensure_private_dir(os.path.dirname(path))
        _rotate_if_needed(path)
        fd = _open_private_ledger(path)
        try:
            os.write(fd, (json.dumps(row, default=str) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except Exception as exc:  # never alter a guard verdict
        logger.debug("guard event ledger write failed: %s", exc)
