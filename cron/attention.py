"""Unified Attention read model (spec §4.2): cron_incidents + attention_events.

One item shape crosses every consumer (RPC, Desktop UI):

    {kind: cron_incident|alert_event, id, source, severity, title, body_excerpt,
     first_seen_at, last_seen_at, state: open|closed, acked_at, evidence_ref?}
    + cron_incident: job_id, job_name, error_sig, output_file
    + alert_event:   producer, alert_type

``cron_incidents`` lives here too: detected|alerted → open, closed → closed, severity
defaults to ``warning``. ``attention_events`` is created here but only WRITTEN by the
Phase-3 receiver; Phase 2 ships the table + the read/ack paths. The sentinel
``cron/attention.changed`` is touched after every commit (ack here, CLI ack via
``cron.incidents.ack_incident``, future receiver writes) because the DB mtime does not
move on WAL commits — the change watcher must never watch the DB file itself.
"""

from __future__ import annotations

import contextlib
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from cron import executions as _executions
from hermes_constants import get_hermes_home
from hermes_time import now as _hermes_now

# Optional test override (mirrors ``cron.executions.EXECUTIONS_FILE``); the shared
# incidents override wins when installed so attention always lands in the SAME database
# as ``cron.incidents``.
EXECUTIONS_FILE: Optional[Path] = None

ATTENTION_KINDS = ("cron_incident", "alert_event")
ATTENTION_STATES = ("open", "closed")
_EXCERPT_CHARS = 200
_CHANGED_FILENAME = "attention.changed"

_lock = threading.RLock()


class InvalidAttentionKind(ValueError):
    """``ack_attention`` kind is not a recognized attention item kind."""


class UnknownAttentionItem(KeyError):
    """``ack_attention`` id does not exist for the given kind (fail-closed)."""


def _db_path() -> Path:
    """Shared cron DB path — the SAME database ``cron.incidents`` uses. Override
    precedence: executions ledger → incidents store → this module's own → home."""
    from cron.incidents import EXECUTIONS_FILE as _incidents_file

    for override in (
        getattr(_executions, "EXECUTIONS_FILE", None),
        _incidents_file,
        EXECUTIONS_FILE,
    ):
        if override is not None:
            return Path(override)
    return get_hermes_home().resolve() / "cron" / "executions.db"


def _connect() -> sqlite3.Connection:
    # Late imports, same guarantee as cron.executions._connect / cron.incidents._connect:
    # a scheduler daemon that outlives an on-disk upgrade keeps old modules cached, so
    # connection helpers are resolved at call time (0.21.2 moved the shared SQLite stack
    # to hermes_cli.sqlite_util and dropped the ledger helpers this module used to import).
    from cron.jobs import _ensure_cron_dir
    from hermes_cli.sqlite_util import open_db

    path = _db_path()
    _ensure_cron_dir(path.parent)
    return open_db(path, db_label="cron/executions.db", synchronous_full=True,
                   initialize=_initialize_schema)


def _initialize_schema(conn: sqlite3.Connection) -> None:
    # The shared executions.db carries the executions + incidents tables too; each
    # module's DDL is idempotent, so one open initializes all three schemas. The unified
    # read selects from cron_incidents even on a fresh DB no incident write has
    # initialized yet (incidents' DDL is idempotent).
    from cron.executions import _initialize_schema as _executions_schema
    from cron.incidents import _initialize_schema as _incidents_schema

    _executions_schema(conn)
    _incidents_schema(conn)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS attention_events (
             id           TEXT PRIMARY KEY,
             source       TEXT NOT NULL,
             event_id     TEXT NOT NULL,
             producer     TEXT NOT NULL,
             alert_type   TEXT NOT NULL,
             severity     TEXT NOT NULL
                          CHECK(severity IN ('critical','warning','info')),
             title        TEXT NOT NULL,
             body         TEXT NOT NULL,
             occurred_at  TEXT NOT NULL,
             received_at  TEXT NOT NULL,
             state        TEXT NOT NULL DEFAULT 'open'
                          CHECK(state IN ('open','closed')),
             acked_at     TEXT,
             acked_by     TEXT,
             UNIQUE(source, event_id)
           )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS attention_sources (
             source            TEXT PRIMARY KEY,
             last_heartbeat_at TEXT,
             last_event_at     TEXT
           )"""
    )


@contextmanager
def _transaction() -> Iterator[sqlite3.Connection]:
    from hermes_cli.sqlite_util import transaction

    with _lock, transaction(_connect()) as conn:
        yield conn


# --- change sentinel -------------------------------------------------------------------------


def attention_changed_path() -> Path:
    """``cron/attention.changed`` sentinel beside the shared executions DB."""
    return _db_path().parent / _CHANGED_FILENAME


def touch_attention_changed() -> None:
    """Best-effort mtime bump of the attention.changed sentinel. Explicit ``utime``
    (nanosecond) so back-to-back commits still move the signature; never raises — the
    ack commit has already happened and must not be reported as failed."""
    with contextlib.suppress(OSError):
        path = attention_changed_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            path.touch(exist_ok=True)
        os.utime(path, ns=(time.time_ns(), time.time_ns()))


# --- unified read model -----------------------------------------------------------------------


def _excerpt(text: Any, limit: int = _EXCERPT_CHARS) -> str:
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def _read_output_excerpt(path: Any, limit: int = _EXCERPT_CHARS) -> Optional[str]:
    """Bounded first-chunk excerpt of an incident's output file — the contract's
    ``excerpt from output_file`` (spec §3.2). Missing or unreadable files return
    None so the caller falls back to the error text honestly; the read is capped
    at ``limit + 1`` chars, never the whole file."""
    if not path:
        return None
    try:
        with open(Path(str(path)), "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(limit + 1)
    except OSError:
        return None
    return _excerpt(head, limit)


def _job_name_lookup(job_ids: set) -> Dict[str, str]:
    """Best-effort job_id → job_name from the cron registry (jobs may be deleted; a
    missing registry must never break the attention read)."""
    names: Dict[str, str] = {}
    if not job_ids:
        return names
    try:
        from cron.jobs import list_jobs

        for job in list_jobs():
            if job.get("id") in job_ids:
                name = str(job.get("name") or "").strip()
                if name:
                    names[job["id"]] = name
    except Exception:
        pass
    return names


def _map_cron_incident(row: Dict[str, Any], job_names: Dict[str, str]) -> Dict[str, Any]:
    raw_state = row.get("state")
    job_id = row.get("job_id") or ""
    job_name = job_names.get(job_id) or None
    # The excerpt's required source is the run's OUTPUT FILE (spec §3.2); the
    # error text is the honest fallback when the file is missing/unreadable.
    file_excerpt = _read_output_excerpt(row.get("output_file"))
    return {
        "kind": "cron_incident",
        "id": row.get("id"),
        "source": "cron",
        "severity": "warning",
        "title": job_name or job_id or "cron incident",
        "body_excerpt": file_excerpt if file_excerpt is not None else _excerpt(row.get("error")),
        "first_seen_at": row.get("first_seen_at"),
        "last_seen_at": row.get("last_seen_at"),
        "state": "closed" if raw_state == "closed" else "open",
        "acked_at": row.get("acked_at"),
        "evidence_ref": row.get("output_file"),
        # kind-specific metadata
        "job_id": job_id,
        "job_name": job_name,
        "error_sig": row.get("error_sig"),
        "output_file": row.get("output_file"),
    }


def _map_alert_event(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "kind": "alert_event",
        "id": row.get("id"),
        "source": row.get("source"),
        "severity": row.get("severity"),
        "title": row.get("title"),
        "body_excerpt": _excerpt(row.get("body")),
        "first_seen_at": row.get("occurred_at"),
        "last_seen_at": row.get("received_at"),
        "state": row.get("state"),
        "acked_at": row.get("acked_at"),
        "evidence_ref": None,
        # kind-specific metadata
        "producer": row.get("producer"),
        "alert_type": row.get("alert_type"),
    }


def list_attention(open_only: bool = True, state: Optional[str] = None) -> List[Dict[str, Any]]:
    """Unified attention items, newest activity first.

    ``open_only`` keeps only ``state == "open"`` items; ``state`` narrows to one wire
    state. STRICT filter validation: an invalid ``open_only``/``state`` value raises
    ``ValueError`` — never silently returns an empty list (the raw
    ``cron.incidents.list_incidents`` returns [] on a bad filter; the unified contract
    turns that into an error)."""
    if not isinstance(open_only, bool):
        raise ValueError(
            f"invalid attention filter: open_only must be a boolean, "
            f"got {type(open_only).__name__}")
    if state is not None and state not in ATTENTION_STATES:
        raise ValueError(f"invalid attention state filter: {state!r} (expected {ATTENTION_STATES})")

    with _transaction() as conn:
        incident_rows = [dict(r) for r in conn.execute(
            "SELECT * FROM cron_incidents ORDER BY last_seen_at DESC, id DESC").fetchall()]
        event_rows = [dict(r) for r in conn.execute(
            "SELECT * FROM attention_events ORDER BY received_at DESC, id DESC").fetchall()]

    job_names = _job_name_lookup({str(r.get("job_id") or "") for r in incident_rows})
    items = [_map_alert_event(row) for row in event_rows] + [
        _map_cron_incident(row, job_names) for row in incident_rows
    ]
    # The unions' own ORDER BYs are not comparable — sort the merged list.
    items.sort(
        key=lambda item: (str(item.get("last_seen_at") or ""), str(item.get("id") or "")),
        reverse=True)
    if state is not None:
        items = [item for item in items if item["state"] == state]
    if open_only:
        items = [item for item in items if item["state"] == "open"]
    return items


def _ack_alert_event(item_id: str) -> Dict[str, Any]:
    now = _hermes_now().isoformat()
    with _transaction() as conn:
        row = conn.execute(
            "SELECT state FROM attention_events WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise UnknownAttentionItem(item_id)
        if row["state"] == "closed":
            return {"status": "already-closed", "changed": False}
        conn.execute(
            "UPDATE attention_events SET state='closed', acked_at=? WHERE id=?",
            (now, item_id),
        )
    touch_attention_changed()
    return {"status": "closed-ok", "changed": True}


def ack_attention(kind: str, item_id: str) -> Dict[str, Any]:
    """Acknowledge (close) one attention item. Explicit outcomes: ``closed-ok`` /
    ``already-closed`` (``changed: False``, idempotent ok) / ``unknown-id`` error
    (fail-closed). Resolution is by (kind, id) — never job-registry-bound, so acking
    survives job deletion."""
    if kind not in ATTENTION_KINDS:
        raise InvalidAttentionKind(f"invalid attention kind: {kind!r} (expected {ATTENTION_KINDS})")
    item_id = str(item_id or "")
    if not item_id:
        raise UnknownAttentionItem(item_id)
    if kind == "alert_event":
        return _ack_alert_event(item_id)
    from cron.incidents import ack_incident, get_incident

    if ack_incident(item_id):
        # cron.incidents.ack_incident touches the sentinel on a successful close.
        return {"status": "closed-ok", "changed": True}
    if get_incident(item_id) is None:
        raise UnknownAttentionItem(item_id)
    return {"status": "already-closed", "changed": False}
