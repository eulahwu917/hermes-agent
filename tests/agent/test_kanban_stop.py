"""Tests for the kanban worker turn-end stop guard."""

from __future__ import annotations

import pytest

from agent.kanban_stop import (
    build_kanban_stop_nudge,
    kanban_stop_nudge_enabled,
    session_called_kanban_terminal,
    worker_run_finished,
)

_KANBAN_ENV_VARS = (
    "HERMES_KANBAN_TASK",
    "HERMES_KANBAN_RUN_ID",
    "HERMES_KANBAN_DB",
    "HERMES_KANBAN_STOP_NUDGE",
)


@pytest.fixture
def clear_kanban_env(monkeypatch):
    for var in _KANBAN_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def _make_board(tmp_path, monkeypatch):
    """A real on-disk kanban board pinned via ``HERMES_KANBAN_DB``."""
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc

    db = tmp_path / "kanban.db"
    kbc.init_db(db_path=db)
    monkeypatch.setenv("HERMES_KANBAN_DB", str(db))
    return kb, kbc


def _claim_open_run(kb, kbc, title: str = "worker task"):
    """Create + claim a task; the returned run has no terminal outcome yet."""
    with kbc.connect_closing() as conn:
        tid = kb.create_task(conn, title=title, assignee="worker")
        claimed = kb.claim_task(conn, tid)
    assert claimed is not None
    return tid, claimed.current_run_id


def test_env_can_disable(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_abc")
    clear_kanban_env.setenv("HERMES_KANBAN_STOP_NUDGE", "0")
    assert kanban_stop_nudge_enabled() is False
    assert build_kanban_stop_nudge(messages=[]) is None


def test_nudge_when_no_terminal_tool(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_46be8aa5")
    messages = [
        {"role": "user", "content": "work kanban task"},
        {
            "role": "assistant",
            "content": "Let me write the comprehensive recipe.",
            "tool_calls": [
                {
                    "id": "1",
                    "type": "function",
                    "function": {"name": "kanban_heartbeat", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "name": "kanban_heartbeat", "tool_call_id": "1", "content": "ok"},
    ]
    nudge = build_kanban_stop_nudge(messages=messages, attempts=0)
    assert nudge is not None
    assert "kanban_complete" in nudge
    assert "kanban_block" in nudge
    assert "t_46be8aa5" in nudge
    assert "protocol violation" in nudge.lower() or "protocol" in nudge.lower()


def test_no_nudge_after_kanban_complete(clear_kanban_env):
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_abc")
    messages = [
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "1",
                    "type": "function",
                    "function": {"name": "kanban_complete", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "name": "kanban_complete", "tool_call_id": "1", "content": "done"},
    ]
    assert session_called_kanban_terminal(messages) is True
    assert build_kanban_stop_nudge(messages=messages) is None


# ── Run-identity / terminal-outcome awareness (t_62cf0f31) ─────────────────
# The exit guard must not remind an ENDED implementation run to finish: a
# review_requested handoff is a terminal outcome for that run, and a card
# running under a DIFFERENT run id is a normal review-claim transition.


def test_no_run_id_env_keeps_legacy_nudge(clear_kanban_env):
    """Workers without HERMES_KANBAN_RUN_ID keep the pre-existing behaviour."""
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_norun")
    assert worker_run_finished() is False
    assert build_kanban_stop_nudge(messages=[]) is not None


def test_no_nudge_after_review_requested_handoff(tmp_path, clear_kanban_env):
    """The observed bug: after kanban_request_review the implementer run has a
    terminal outcome — no further exit reminders may fire at that process."""
    kb, kbc = _make_board(tmp_path, clear_kanban_env)
    tid, run_id = _claim_open_run(kb, kbc, title="handoff")
    with kbc.connect_closing() as conn:
        assert kb.request_review(conn, tid, summary="handed off", expected_run_id=run_id)
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", tid)
    clear_kanban_env.setenv("HERMES_KANBAN_RUN_ID", str(run_id))
    assert worker_run_finished() is True
    assert build_kanban_stop_nudge(
        messages=[{"role": "user", "content": "work kanban task"}]
    ) is None


def test_no_nudge_when_card_owned_by_different_run(tmp_path, clear_kanban_env):
    """A card ``running`` under a different run id is not evidence that THIS
    worker's run is unfinished — the nudge must stay silent."""
    kb, kbc = _make_board(tmp_path, clear_kanban_env)
    tid, run_id = _claim_open_run(kb, kbc, title="owner")
    with kbc.connect_closing() as conn:
        with kb.write_txn(conn):
            # Synthetic divergence: the card is owned by a newer run while this
            # worker's own run row is still open — isolates the run-identity
            # comparison from the terminal-outcome check.
            conn.execute(
                "UPDATE tasks SET current_run_id = ? WHERE id = ?", (run_id + 1, tid)
            )
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", tid)
    clear_kanban_env.setenv("HERMES_KANBAN_RUN_ID", str(run_id))
    assert worker_run_finished() is True
    assert build_kanban_stop_nudge(messages=[{"role": "user", "content": "x"}]) is None


def test_evidence_timeline_replay(tmp_path, clear_kanban_env):
    """Exact t_f158f2e6 timeline: implementer hands off (run 1 ends
    ``review_requested``), the reviewer claims from ``review`` (run 2,
    card ``running`` again) — the implementer's still-alive process must
    get NO exit reminder afterwards."""
    kb, kbc = _make_board(tmp_path, clear_kanban_env)
    with kbc.connect_closing() as conn:
        tid = kb.create_task(conn, title="avatar v4", assignee="marketer")
        implementation = kb.claim_task(conn, tid)
        assert implementation is not None
        run1 = implementation.current_run_id
        assert kb.request_review(
            conn, tid, summary="handed to review", reviewer="bepop",
            expected_run_id=run1,
        )
        review = kb.claim_review_task(conn, tid)
        assert review is not None
        assert review.current_run_id != run1
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", tid)
    clear_kanban_env.setenv("HERMES_KANBAN_RUN_ID", str(run1))
    # Session never called kanban_complete/kanban_block (request_review is not
    # in the terminal-tool set) — the board state alone must suppress the nudge.
    assert worker_run_finished() is True
    assert build_kanban_stop_nudge(
        messages=[{"role": "user", "content": "work kanban task"}]
    ) is None


def test_nudge_fires_when_own_run_live_and_unfinished(tmp_path, clear_kanban_env):
    """Own run still open and still current → the guard keeps nudging."""
    kb, kbc = _make_board(tmp_path, clear_kanban_env)
    tid, run_id = _claim_open_run(kb, kbc, title="live")
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", tid)
    clear_kanban_env.setenv("HERMES_KANBAN_RUN_ID", str(run_id))
    assert worker_run_finished() is False
    nudge = build_kanban_stop_nudge(messages=[{"role": "user", "content": "x"}])
    assert nudge is not None
    assert tid in nudge


def test_unreadable_board_fails_closed_to_nudge(tmp_path, clear_kanban_env):
    """A missing / unreadable board must never silence the guard."""
    clear_kanban_env.setenv("HERMES_KANBAN_TASK", "t_ghost")
    clear_kanban_env.setenv("HERMES_KANBAN_RUN_ID", "7")
    clear_kanban_env.setenv("HERMES_KANBAN_DB", str(tmp_path / "no-such-board.db"))
    assert worker_run_finished() is False
    assert build_kanban_stop_nudge(messages=[]) is not None
