"""Turn-end guard for kanban workers, which must end with ``kanban_complete`` or
``kanban_block``. Some models narrate the next step and stop with no tool calls;
Hermes treats that as a clean exit → ``rc=0`` → dispatcher ``protocol_violation``.
Policy-only: return a bounded synthetic nudge so the loop continues instead of exiting.
"""

from __future__ import annotations

import os
from typing import Any, Iterable, Optional


_TERMINAL_KANBAN_TOOLS = frozenset({"kanban_complete", "kanban_block"})

_DEFAULT_MAX_ATTEMPTS = 2


def kanban_stop_nudge_enabled() -> bool:
    """On when ``HERMES_KANBAN_TASK`` is set, unless ``HERMES_KANBAN_STOP_NUDGE`` disables it."""
    if (os.environ.get("HERMES_KANBAN_STOP_NUDGE") or "").strip().lower() in {"0", "false", "no", "off"}:
        return False
    return bool((os.environ.get("HERMES_KANBAN_TASK") or "").strip())


def _tool_call_name(tc: Any) -> str:
    """Tool name from a dict or object tool call (``function.name`` first, then ``name``)."""
    if isinstance(tc, dict):
        fn = tc.get("function")
        return str((fn.get("name") if isinstance(fn, dict) else tc.get("name")) or "")
    fn = getattr(tc, "function", None)
    return str((getattr(fn, "name", "") if fn is not None else getattr(tc, "name", "")) or "")


def session_called_kanban_terminal(messages: Iterable[dict] | None) -> bool:
    """True if this conversation already invoked a terminal kanban tool."""
    for msg in filter(lambda m: isinstance(m, dict), messages or ()):
        role = msg.get("role")
        if role == "assistant" and any(
            _tool_call_name(tc) in _TERMINAL_KANBAN_TOOLS for tc in msg.get("tool_calls") or []
        ):
            return True
        if role == "tool" and str(msg.get("name") or "") in _TERMINAL_KANBAN_TOOLS:
            return True
    return False


def _worker_run_identity() -> "tuple[Optional[str], Optional[int]]":
    """``(task_id, run_id)`` of the dispatcher run this process was spawned for.

    ``run_id`` is ``None`` when ``HERMES_KANBAN_RUN_ID`` is absent — callers then
    cannot (and must not) consult the board about this process, so the exit
    guard keeps its legacy behaviour instead of guessing."""
    tid = (os.environ.get("HERMES_KANBAN_TASK") or "").strip() or None
    raw = (os.environ.get("HERMES_KANBAN_RUN_ID") or "").strip()
    try:
        run_id = int(raw) if raw else None
    except ValueError:
        run_id = None
    return tid, run_id


def worker_run_finished(task_id: Optional[str] = None) -> bool:
    """True when this process's own kanban run can no longer be nudged to finish.

    False when the worker is still the live, unfinished run OR the board cannot
    be checked: a read failure must never silence the guard — the dispatcher's
    bounded protocol-violation retry stays the backstop.

    Two independent end-states suppress the nudge:
    - the run already reached a terminal outcome on the board (``review_requested``;
      also ``changes_requested`` for reviewer runs, ``completed``, ...) — a review
      handoff is a valid end-state for an implementation run, not a protocol
      violation; and
    - ``tasks.current_run_id`` no longer equals this run (a card being ``running``
      under a DIFFERENT run id is a normal review-claim transition, not evidence
      this old run is unfinished)."""
    tid, run_id = _worker_run_identity()
    if task_id:
        tid = task_id
    if not tid or run_id is None:
        return False
    try:
        from hermes_cli.kanban_db import read_worker_run_state
    except Exception:
        return False
    try:
        outcome, current_run = read_worker_run_state(tid, run_id)
    except Exception:
        return False
    if outcome is None and current_run is None:
        return False  # cannot determine — fail closed (nudge still fires)
    if outcome is not None:
        return True
    return current_run != run_id


def build_kanban_stop_nudge(
    *,
    messages: Iterable[dict] | None = None,
    attempts: int = 0,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    task_id: Optional[str] = None,
) -> Optional[str]:
    """Synthetic follow-up when a kanban worker exits without a terminal tool; ``None`` when
    the guard should not fire (not a kanban worker, already completed/blocked, budget exhausted,
    or the worker's own run already reached a terminal outcome / lost the card — see
    :func:`worker_run_finished`)."""
    if (
        not kanban_stop_nudge_enabled()
        or attempts >= max_attempts
        or session_called_kanban_terminal(messages)
    ):
        return None

    tid = (task_id or os.environ.get("HERMES_KANBAN_TASK") or "").strip() or "this task"
    if worker_run_finished(task_id=task_id):
        return None

    return (
        "[System: You are a Hermes kanban worker. A plain-text reply is NOT a "
        "terminal state for the board.\n\n"
        f"Task `{tid}` is still `running`. Ending now without a board tool "
        "causes a protocol violation (clean exit with no "
        "`kanban_complete` / `kanban_block`).\n\n"
        "Do this immediately in your next response — do not narrate intent:\n"
        "1. Finish any remaining deliverable (write the required file(s) now).\n"
        "2. Call `kanban_complete(summary=..., artifacts=[...])` if the work "
        "is done, OR `kanban_block(reason=...)` if you are blocked.\n\n"
        "Never end a turn with only a promise of future action. Repeated "
        "protocol violations will block this task and require manual intervention.]"
    )


__all__ = [
    "build_kanban_stop_nudge",
    "kanban_stop_nudge_enabled",
    "session_called_kanban_terminal",
    "worker_run_finished",
]
