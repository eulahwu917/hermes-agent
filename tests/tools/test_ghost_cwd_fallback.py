"""Regression tests for the ghost-cwd fallback on the local backend.

``_resolve_command_cwd()`` persists each session's cwd record (cwd
rearchitecture, step 1). When a recorded cwd's directory disappears from the
local filesystem — the classic case is a Kanban worktree removed after
``hermes kanban archive`` — the shell's defensive ``cd <cwd>`` prefix fails
with exit 126 BEFORE the command runs, killing every bare terminal call in
the session. ``workdir=``-scoped calls sidestep the ghost but never heal it:
recording is deliberately skipped for scoped calls (they are transient by
contract), so the session stays broken until something re-records a real
directory.

Fix: on ``env_type == "local"``, a recorded cwd that no longer passes
``os.path.isdir()`` is ignored and the default cwd is used instead; the next
successful un-scoped command re-records a real directory.

Remote backends are deliberately NOT covered: their recorded paths resolve
inside the remote host/sandbox, so a local ``os.path.isdir()`` proves nothing
about them (mirrors the split between the container guard
``_is_unusable_container_cwd`` — which only applies to ``_CONTAINER_BACKENDS``
— and this host-side check).
"""

import os

import pytest

import tools.terminal_tool as tt


@pytest.fixture(autouse=True)
def _clean_store(monkeypatch):
    monkeypatch.setattr(tt, "_session_cwd", {})
    monkeypatch.setattr(tt, "_task_env_overrides", {})


def _resolve(**kwargs):
    return tt._resolve_command_cwd(**kwargs)


class TestGhostCwdFallbackLocal:

    def test_missing_recorded_dir_falls_back_to_default(self, tmp_path, monkeypatch):
        ghost = str(tmp_path / "gone-worktree")
        os.makedirs(ghost, exist_ok=True)
        tt.record_session_cwd("sess-1", ghost)
        default = str(tmp_path / "scratch")
        os.makedirs(default, exist_ok=True)
        monkeypatch.setattr(tt.os.path, "isdir", lambda p: p == default)

        assert _resolve(
            workdir=None, default_cwd=default, session_key="sess-1", env_type="local",
        ) == default


    def test_live_recorded_dir_still_wins(self, tmp_path, monkeypatch):
        live = str(tmp_path / "worktree")
        default = str(tmp_path / "scratch")
        for p in (live, default):
            os.makedirs(p, exist_ok=True)
        monkeypatch.setattr(tt.os.path, "isdir", lambda p: p == live)

        tt.record_session_cwd("sess-1", live)
        assert _resolve(
            workdir=None, default_cwd=default, session_key="sess-1", env_type="local",
        ) == live


    def test_workdir_still_overrides_everything(self, tmp_path, monkeypatch):
        ghost = str(tmp_path / "gone-worktree")
        explicit = str(tmp_path / "explicit")
        os.makedirs(ghost, exist_ok=True)
        os.makedirs(explicit, exist_ok=True)
        monkeypatch.setattr(tt.os.path, "isdir", lambda p: p == explicit)

        tt.record_session_cwd("sess-1", ghost)
        assert _resolve(
            workdir=explicit, default_cwd=str(tmp_path / "scratch"),
            session_key="sess-1", env_type="local",
        ) == explicit


    def test_no_record_uses_default_without_isdir_call(self, tmp_path, monkeypatch):
        default = str(tmp_path / "scratch")
        os.makedirs(default, exist_ok=True)

        def _boom(p):
            raise AssertionError("isdir must not be called without a record")

        monkeypatch.setattr(tt.os.path, "isdir", _boom)
        assert _resolve(
            workdir=None, default_cwd=default, session_key="sess-9", env_type="local",
        ) == default


class TestGhostCwdScopeBoundaries:

    def test_missing_dir_not_forgiven_on_container_backend(self, tmp_path, monkeypatch):
        """The container guard owns container backends; the host isdir() check
        must not silently widen its scope (a container path may legitimately
        not exist on the host)."""
        ghost = str(tmp_path / "gone-worktree")
        default = str(tmp_path / "scratch")
        os.makedirs(ghost, exist_ok=True)
        os.makedirs(default, exist_ok=True)
        monkeypatch.setattr(tt.os.path, "isdir", lambda p: False)

        tt.record_session_cwd("sess-1", ghost)
        assert _resolve(
            workdir=None, default_cwd=default, session_key="sess-1",
            env_type="docker",
        ) == ghost


    def test_missing_dir_not_probed_on_remote_backend(self, tmp_path, monkeypatch):
        """A remote recorded path resolves inside the remote host; a local
        isdir() must not run against it (so it must not influence the result)."""
        remote_path = "/remote-host-only/wt-a"
        default = str(tmp_path / "scratch")
        os.makedirs(default, exist_ok=True)

        def _boom(p):
            raise AssertionError("isdir must not be called for ssh backend")

        monkeypatch.setattr(tt.os.path, "isdir", _boom)
        tt.record_session_cwd("sess-1", remote_path)
        assert _resolve(
            workdir=None, default_cwd=default, session_key="sess-1",
            env_type="ssh",
        ) == remote_path
