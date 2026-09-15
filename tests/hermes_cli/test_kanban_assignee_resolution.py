"""Assignee-resolution fail-fast: validate at creation, surface at dispatch.

A card assigned to a profile that does not exist on disk is silently invisible
to every dispatcher tick — it sits in ``ready``/``todo`` forever with no
diagnostic anywhere (the 2026-09-14 ``bepop`` incident). These tests pin the
three defences: the resolution primitive, creation/assign event recording +
CLI warnings, and dispatch-time surfacing (event + warning + result field).
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from hermes_cli import kanban as kc
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import kanban_db_dispatch as kbd


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


@pytest.fixture
def only_alice_on_disk(monkeypatch):
    """The dispatcher resolves only ``alice`` to a real profile."""
    from hermes_cli import profiles
    monkeypatch.setattr(profiles, "profile_exists", lambda name: name == "alice")


def _events_of_kind(conn, task_id: str, kind: str) -> list:
    return conn.execute(
        "SELECT kind, payload FROM task_events WHERE task_id = ? AND kind = ? "
        "ORDER BY id", (task_id, kind),
    ).fetchall()


def _fake_spawn_factory(spawns: list):
    def fake_spawn(task, workspace, board=None):
        spawns.append(task.id)
        return 42
    return fake_spawn


# ---------------------------------------------------------------------------
# 1. Resolution primitive
# ---------------------------------------------------------------------------

def test_assignee_resolves_to_profile(monkeypatch):
    import hermes_cli.profiles as profiles

    monkeypatch.setattr(profiles, "profile_exists", lambda name: name == "alice")
    assert kb.assignee_resolves_to_profile("alice") is True
    assert kb.assignee_resolves_to_profile("ghost") is False
    assert kb.assignee_resolves_to_profile("Bepop") is False  # normalizes lowercase
    assert kb.assignee_resolves_to_profile("") is False
    assert kb.assignee_resolves_to_profile(None) is False


def test_assignee_resolves_fail_open_when_unimportable(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "hermes_cli.profiles":
            raise ImportError("nope")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert kb.assignee_resolves_to_profile("alice") is None


# ---------------------------------------------------------------------------
# 2. Creation-time recording
# ---------------------------------------------------------------------------


def test_create_task_records_unresolved_assignee_event(kanban_home, only_alice_on_disk):
    with kbc.connect() as conn:
        ghost = kb.create_task(conn, title="ghost card", assignee="ghost")
        alice = kb.create_task(conn, title="ok card", assignee="alice")
    with kbc.connect() as conn:
        assert len(_events_of_kind(conn, ghost, "assignee_unresolved")) == 1
        assert _events_of_kind(conn, alice, "assignee_unresolved") == []


def test_assign_records_unresolved_event(kanban_home, only_alice_on_disk):
    import json
    with kbc.connect() as conn:
        tid = kb.create_task(conn, title="t", assignee="alice")
    with kbc.connect() as conn:
        assert kb.assign_task(conn, tid, "ghost") is True
    with kbc.connect() as conn:
        evs = _events_of_kind(conn, tid, "assignee_unresolved")
        assert len(evs) == 1
        assert json.loads(evs[0]["payload"])["stage"] == "assigned"


# ---------------------------------------------------------------------------
# 3. CLI warnings (create / assign / reassign)
# ---------------------------------------------------------------------------


def test_cli_create_warns_on_unresolved_assignee(kanban_home, only_alice_on_disk):
    out = kc.run_slash("create 'x' --assignee ghost")
    assert "does not resolve to a profile on disk" in out
    assert "NEVER be dispatched" in out


def test_cli_stays_silent_for_valid_assignee(kanban_home, only_alice_on_disk):
    out = kc.run_slash("create 'x' --assignee alice")
    assert "does not resolve to a profile on disk" not in out


def test_cli_assign_warns_on_unresolved_assignee(kanban_home, only_alice_on_disk):
    tid = kc.run_slash("create 'x' --assignee alice").split()[1]
    out = kc.run_slash(f"assign {tid} ghost")
    assert "does not resolve to a profile on disk" in out


def test_cli_reassign_warns_on_unresolved_assignee(kanban_home, only_alice_on_disk):
    tid = kc.run_slash("create 'x' --assignee alice").split()[1]
    out = kc.run_slash(f"reassign {tid} ghost")
    assert "does not resolve to a profile on disk" in out


# ---------------------------------------------------------------------------
# 4. Dispatch-time surfacing
# ---------------------------------------------------------------------------


def test_dispatch_surfaces_unresolved_assignee(kanban_home, only_alice_on_disk, caplog):
    import json
    with kbc.connect() as conn:
        ghost = kb.create_task(conn, title="ghost card", assignee="ghost")
        alice = kb.create_task(conn, title="ok card", assignee="alice")

    spawns: list = []
    with caplog.at_level(logging.WARNING):
        with kbc.connect() as conn:
            res = kbd.dispatch_once(
                conn, spawn_fn=_fake_spawn_factory(spawns), max_in_progress=4,
            )

    assert (ghost, "ghost") in res.assignee_unresolved
    assert ghost in res.skipped_nonspawnable
    assert alice in spawns
    # The ghost card now carries BOTH the created and dispatch-stage events.
    with kbc.connect() as conn:
        evs = _events_of_kind(conn, ghost, "assignee_unresolved")
        assert len(evs) == 2
        stages = {json.loads(e["payload"])["stage"] for e in evs}
        assert stages == {"created", "dispatch"}
        assert _events_of_kind(conn, alice, "assignee_unresolved") == []
    assert any("does not resolve to a profile on disk" in r.message for r in caplog.records)


def test_dispatch_warning_is_deduped_across_ticks(kanban_home, only_alice_on_disk, caplog):
    with kbc.connect() as conn:
        ghost = kb.create_task(conn, title="ghost card", assignee="ghost")

    spawns: list = []
    with caplog.at_level(logging.WARNING):
        with kbc.connect() as conn:
            kbd.dispatch_once(conn, spawn_fn=_fake_spawn_factory(spawns), max_in_progress=4)
        with kbc.connect() as conn:
            kbd.dispatch_once(conn, spawn_fn=_fake_spawn_factory(spawns), max_in_progress=4)
    with kbc.connect() as conn:
        # One created + one dispatch — the second tick must not re-emit.
        assert len(_events_of_kind(conn, ghost, "assignee_unresolved")) == 2


def test_dispatch_silent_for_valid_assignees(kanban_home, only_alice_on_disk, caplog):
    with kbc.connect() as conn:
        alice = kb.create_task(conn, title="ok card", assignee="alice")

    spawns: list = []
    with caplog.at_level(logging.WARNING):
        with kbc.connect() as conn:
            res = kbd.dispatch_once(
                conn, spawn_fn=_fake_spawn_factory(spawns), max_in_progress=4,
            )

    assert res.assignee_unresolved == []
    assert res.skipped_nonspawnable == []
    assert alice in spawns
    with kbc.connect() as conn:
        assert _events_of_kind(conn, alice, "assignee_unresolved") == []
    assert not any("does not resolve" in r.message for r in caplog.records)