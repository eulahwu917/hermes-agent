"""Codex singleton retirement state — what upstream does now, and what is NOT carried (R1).

This file REPLACES the pre-recap `tests/agent/test_codex_singleton_write_through.py`, which
asserted the carried root write-through + root-resolved refresh + reuse-rescue
(C1/C2/C3, PR #95984). Those symbols (`_write_through_codex_to_global_root`,
`_codex_root_rescue_seen`, `_global_auth_file_path`, `_load_global_auth_store`) were removed
from the tree because ``hermes_cli/auth.py`` and ``auth_codex.py`` are byte-identical to fixed
upstream — see the R1 decision brief. Deleting the old suite outright is not a passing
retirement, so this equivalent pins the ACTUAL behaviour the tree now has:

* The carried C1/C2/C3 machinery is genuinely absent (no half-reverted symbols).
* upsteam's deliberate profile-isolation holds at the codex endpoints (its own
  ``tests/hermes_cli/test_auth_profile_isolation.py`` is the authority; here we pin the
  codex-specific consequences: ``_save_codex_tokens`` lands in the ACTIVE profile store and
  the root store is untouched).
* Upstream's intra-store alias sync and CLI recovery exist and are wired:
  ``_sync_codex_pool_entries`` (singleton→pool alias sync, ACTIVE store only) and
  ``_recover_codex_tokens_from_cli`` (workspace-identity-gated CLI recovery). Neither reads the
  ROOT store: the dropped root-rescue portion of C3 (adopting a fresher sibling chain from the
  root Hermes singleton before CLI recovery) has NO upstream successor - see the R1 decision
  brief, where it stays inside the open decision.

Whether to re-home C1/C2 (cross-profile root write-through / root-resolved direct write) and/or
C3's root-rescue onto the shared-store model is a POLICY decision owned by David, not asserted
here as either done or dropped.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ── C1/C2/C3 absent ────────────────────────────────────────────────────────


def test_carried_root_writethrough_machinery_is_absent():
    """The reverted write-through helpers are gone, not merely unfindable in the delta."""
    import hermes_cli.auth as auth
    import hermes_cli.auth_codex as codex

    for name in ("_write_through_codex_to_global_root", "_codex_root_rescue_seen",
                 "_reset_codex_root_rescue_seen", "_codex_token_identity",
                 "_global_auth_file_path", "_load_global_auth_store"):
        assert not hasattr(auth, name), f"{name} should be absent from hermes_cli.auth"
        assert not hasattr(codex, name), f"{name} should be absent from hermes_cli.auth_codex"


def test_supersession_functions_exist_and_are_wired():
    """Upstream's intra-store alias sync and CLI recovery are present and callable; note these
    cover the ACTIVE store and the Codex CLI, not the dropped root-rescue source (ROOT store),
    which is kept OPEN in the R1 brief rather than treated as superseded (gate 7170)."""
    from hermes_cli.auth_codex import _recover_codex_tokens_from_cli, _save_codex_tokens, _sync_codex_pool_entries

    assert callable(_sync_codex_pool_entries)
    assert callable(_save_codex_tokens)
    assert callable(_recover_codex_tokens_from_cli)


# ── profile isolation at the codex endpoints ────────────────────────────────


def _root_store() -> dict:
    return {
        "version": 1,
        "providers": {
            "openai-codex": {"auth_mode": "chatgpt",
                             "tokens": {"access_token": "root-codex-access",
                                        "refresh_token": "root-codex-refresh"},
                             "last_refresh": "2026-01-01T00:00:00"},
        },
        "credential_pool": {},
    }


@pytest.fixture()
def profile_env(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    global_root = tmp_path / ".hermes"
    global_root.mkdir()
    profile_dir = global_root / "profiles" / "coder"
    profile_dir.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(profile_dir))
    return {"global": global_root, "profile": profile_dir}


def test_codex_save_lands_in_the_active_profile_store_not_root(profile_env):
    """``_save_codex_tokens`` writes the active (named-profile) store; the root auth.json is
    byte-identical afterwards — the carried cross-profile write-through is NOT present."""
    from hermes_cli.auth_codex import _save_codex_tokens

    root_file = profile_env["global"] / "auth.json"
    (profile_env["profile"] / "auth.json").write_text(json.dumps(_root_store()))
    root_file.write_text(json.dumps(_root_store()))
    before = root_file.read_bytes()

    _save_codex_tokens({"access_token": "codex-new", "refresh_token": "codex-new-rt"})

    assert root_file.read_bytes() == before
    profile_store = json.loads((profile_env["profile"] / "auth.json").read_text())
    assert profile_store["providers"]["openai-codex"]["tokens"]["refresh_token"] == "codex-new-rt"


def test_codex_read_misses_when_only_the_root_has_credentials(profile_env):
    """Failure mode that the (removed) write-through used to paper over: a named profile with
    no codex store never falls back to the root singleton and fails closed."""
    from hermes_cli.auth_codex import _read_codex_tokens

    root_file = profile_env["global"] / "auth.json"
    root_file.write_text(json.dumps(_root_store()))
    (profile_env["profile"] / "auth.json").write_text(
        json.dumps({"version": 1, "providers": {}, "credential_pool": {}}))

    with pytest.raises(Exception):  # AuthError (codex_auth_missing) — fail closed, no root fallback
        _read_codex_tokens()


# ── supersession behaviour ──────────────────────────────────────────────────


def test_pool_sync_only_touches_singleton_aliases():
    """``_sync_codex_pool_entries`` syncs ``device_code`` and the matching legacy alias, never an
    independent ``manual:api_key`` or an independent ``manual:device_code`` account."""
    from hermes_cli.auth_codex import _sync_codex_pool_entries

    store = {"credential_pool": {"openai-codex": [
        {"id": "singleton", "source": "device_code", "access_token": "old-at", "refresh_token": "old-rt"},
        {"id": "legacy-alias", "source": "manual:device_code", "access_token": "old-at", "refresh_token": "old-rt"},
        {"id": "independent", "source": "manual:device_code", "access_token": "someone-else", "refresh_token": "sr"},
        {"id": "apikey", "source": "manual:api_key", "access_token": "sk-key"},
    ]}}
    _sync_codex_pool_entries(store, {"access_token": "new-at", "refresh_token": "new-rt"},
                             "2026-02-01T00:00:00", previous_singleton_tokens={"access_token": "old-at"})
    entries = {e["id"]: e for e in store["credential_pool"]["openai-codex"]}
    assert entries["singleton"]["access_token"] == "new-at"
    assert entries["legacy-alias"]["access_token"] == "new-at"  # matching old singleton token → alias
    assert entries["independent"]["access_token"] == "someone-else"  # independent account untouched
    assert entries["apikey"]["access_token"] == "sk-key"  # api_key never synced


def test_cli_recovery_refuses_a_different_workspace_identity(monkeypatch, tmp_path):
    """``_recover_codex_tokens_from_cli`` is identity-gated: an adopted CLI login for a
    DIFFERENT ChatGPT workspace must not replace the stored credential (#73667)."""
    import hermes_cli.auth as auth

    monkeypatch.setattr("agent.credential_sources.adopt_external_logins_enabled", lambda: True)
    # The recovery helper late-imports these names, so patch the re-export bindings it will bind.
    monkeypatch.setattr(auth, "_import_codex_cli_tokens",
                        lambda: {"access_token": "cli-at", "refresh_token": "cli-rt"})
    monkeypatch.setattr("agent.credential_pool._codex_principal_identity",
                        lambda at: "known-owner" if at == "observed-at" else "other-workspace")
    saved = []
    monkeypatch.setattr(auth, "_save_codex_tokens", lambda tokens, *a, **k: saved.append(tokens))

    import hermes_cli.auth_codex as codex

    result = codex._recover_codex_tokens_from_cli("relogin-required", observed_access_token="observed-at")
    assert result is None, "a CLI login for another workspace must never be adopted"
    assert saved == [], "identity refusal must not reach the token-save path"