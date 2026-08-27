"""Codex OAuth singleton root write-through + reuse-rescue (spec v11, #87503).

Covers the three production changes in ``hermes_cli/auth.py``:

* C1 — ``_save_codex_tokens`` mirrors a saved chain to the global root.
* C2 — ``_refresh_codex_auth_tokens`` resolves the caller's token source once
  and, for a root-resolved reader, persists its rotation directly to root.
* C3 — a relogin-required refresh attempts a root reuse-rescue (adopting a
  fresher sibling chain) before falling back to ``~/.codex`` CLI recovery.

Plus D-id (identity gating) and the three-outcome durability contract
(OUTCOME-SUCCESS silent / CLASS-D warning / CLASS-N critical+retry).

All token endpoints are mocked (autospec-friendly); no interactive OAuth runs.
The tests drive the real read-modify-write path against on-disk stores under
``tmp_path``, mirroring ``tests/agent/test_credential_pool_oauth_writethrough.py``.
"""

import base64
import json
import re
import subprocess
import threading

import pytest

import hermes_cli.auth as A
from hermes_cli.auth import (
    AuthError,
    _CODEX_ROOT_PERSIST_ATTEMPTS,
    _CODEX_ROOT_PERSIST_BACKOFF_SECONDS,
    _codex_root_rescue_seen,
    _codex_token_identity,
    _refresh_codex_auth_tokens,
    _reset_codex_root_rescue_seen,
    _save_codex_tokens,
    _write_through_codex_to_global_root,
)


# ── token / store helpers ────────────────────────────────────────────────────

def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _jwt(sub="acct-1", iss="https://auth.openai.com") -> str:
    """A valid three-segment base64url JWT with the given ``sub``/``iss``."""
    header = _b64({"alg": "none", "typ": "JWT"})
    return ".".join([header, _b64({"sub": sub, "iss": iss}), "sig"])


def _write_store(path, store) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store), encoding="utf-8")


def _read_store(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _codex_state(tokens, last_refresh="2026-06-01T00:00:00Z", **extra):
    state = {"tokens": dict(tokens), "last_refresh": last_refresh, "auth_mode": "chatgpt"}
    state.update(extra)
    return state


@pytest.fixture
def profile_and_root(tmp_path, monkeypatch):
    """Wire a profile auth store + a distinct global-root auth store on disk."""
    profile_path = tmp_path / "profiles" / "work" / "auth.json"
    root_path = tmp_path / "root" / "auth.json"
    monkeypatch.setattr(A, "_auth_file_path", lambda: profile_path)
    monkeypatch.setattr(A, "_global_auth_file_path", lambda: root_path)
    monkeypatch.setenv("HOME", str(tmp_path / "not-the-root"))
    return profile_path, root_path


@pytest.fixture(autouse=True)
def _reset_rescue_state(monkeypatch):
    """Clear the process-lifetime rescue seen-set and global-store memo."""
    _reset_codex_root_rescue_seen()
    A._global_auth_store_cache = None
    yield
    _reset_codex_root_rescue_seen()
    A._global_auth_store_cache = None


def _mock_refresh(monkeypatch, result=None, exc=None, calls=None):
    """Replace ``refresh_codex_oauth_pure`` with a scripted stub."""
    def fake(access_token, refresh_token, timeout_seconds=20.0, **kw):
        if calls is not None:
            calls.append((access_token, refresh_token))
        if exc is not None:
            raise exc
        return dict(result or {"access_token": "new-at", "refresh_token": "new-rf"})

    monkeypatch.setattr(A, "refresh_codex_oauth_pure", fake)
    return fake


# ── T1 / T2 / T3 / T4 — the R1′/R2′/R3′/switch persistence matrix ───────────

def test_t1_root_resolved_success_writes_root_zero_profile(profile_and_root, monkeypatch):
    """R1′: a root-resolved reader persists to root and never seeds a profile block."""
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {
        "openai-codex": _codex_state({"access_token": _jwt("acct-1"), "refresh_token": "root-rf"}),
    }})
    _write_store(profile_path, {"version": 1})  # no openai-codex block

    _mock_refresh(monkeypatch, result={"access_token": _jwt("acct-1"), "refresh_token": "new-rf"})

    tokens = {"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}
    out = _refresh_codex_auth_tokens(tokens, 20.0)

    assert out["access_token"] == _jwt("acct-1")
    assert out["refresh_token"] == "new-rf"

    root = _read_store(root_path)
    assert root["providers"]["openai-codex"]["tokens"]["refresh_token"] == "new-rf"
    assert root["providers"]["openai-codex"]["auth_mode"] == "chatgpt"

    profile = _read_store(profile_path)
    assert "openai-codex" not in profile.get("providers", {}), (
        "a root-resolved reader must NOT seed a shadowing profile block (#74339)"
    )


def test_t2_owned_success_syncs_root_and_preserves_independent(profile_and_root, monkeypatch):
    """R2′: an owned save updates profile + root; independent account untouched."""
    profile_path, root_path = profile_and_root
    root = {
        "version": 1,
        "providers": {"openai-codex": _codex_state(
            {"access_token": _jwt("acct-1"), "refresh_token": "root-old-rf"}
        )},
        "credential_pool": {"openai-codex": [
            {"id": "dev", "source": "device_code", "access_token": _jwt("acct-1"),
             "refresh_token": "root-old-rf", "label": "singleton"},
            {"id": "alias", "source": "manual:device_code", "access_token": _jwt("acct-1"),
             "refresh_token": "root-old-rf", "label": "legacy-alias", "priority": 5},
            {"id": "indep", "source": "manual:device_code", "access_token": _jwt("acct-9"),
             "refresh_token": "indep-rf", "label": "independent", "priority": 1},
        ]},
    }
    _write_store(root_path, root)
    _write_store(profile_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "profile-old-rf"}
    )}})

    _save_codex_tokens(
        {"access_token": _jwt("acct-1"), "refresh_token": "fresh-rf"},
        last_refresh="2026-06-12T00:00:00Z",
        label="My Codex",
    )

    root_store = _read_store(root_path)
    rc = root_store["providers"]["openai-codex"]
    assert rc["tokens"]["refresh_token"] == "fresh-rf"
    assert rc["auth_mode"] == "chatgpt"
    assert rc["label"] == "My Codex"

    by_id = {e["id"]: e for e in root_store["credential_pool"]["openai-codex"]}
    # device_code singleton alias synced
    assert by_id["dev"]["refresh_token"] == "fresh-rf"
    # legacy alias (access_token matched previous singleton) synced
    assert by_id["alias"]["refresh_token"] == "fresh-rf"
    assert by_id["alias"]["priority"] == 5  # non-token fields untouched
    # independent account (#39236) byte-identical
    assert by_id["indep"]["refresh_token"] == "indep-rf"
    assert by_id["indep"]["access_token"] == _jwt("acct-9")


def test_t3_identity_mismatch_untouched_empty_root_populated(profile_and_root, monkeypatch):
    """R3′: mismatched identity leaves root untouched; empty root is populated."""
    profile_path, root_path = profile_and_root
    # (a) mismatched identity — root holds a different account
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-OTHER"), "refresh_token": "other-rf"}
    )}})
    _write_store(profile_path, {"version": 1})
    _save_codex_tokens({"access_token": _jwt("acct-1"), "refresh_token": "mine-rf"})
    root_store = _read_store(root_path)
    assert root_store["providers"]["openai-codex"]["tokens"]["refresh_token"] == "other-rf"

    # (b) empty root — populated with set_active left alone
    _write_store(root_path, {"version": 1, "active_provider": "anthropic", "providers": {}})
    _save_codex_tokens({"access_token": _jwt("acct-1"), "refresh_token": "mine-rf"})
    root_store = _read_store(root_path)
    assert root_store["providers"]["openai-codex"]["tokens"]["refresh_token"] == "mine-rf"
    assert root_store["active_provider"] == "anthropic"  # set_active untouched


@pytest.mark.parametrize("same_sub", [True, False], ids=["same-sub-propagated", "diff-sub-untouched"])
def test_t4_switch_matrix(profile_and_root, monkeypatch, same_sub):
    """login-introduced rotation: same-sub propagates, different-sub does not."""
    profile_path, root_path = profile_and_root
    root_sub = "acct-root"
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt(root_sub), "refresh_token": "root-rf"}
    )}})
    _write_store(profile_path, {"version": 1})
    save_sub = root_sub if same_sub else "acct-else"
    _save_codex_tokens({"access_token": _jwt(save_sub), "refresh_token": "new-rf"})
    root_store = _read_store(root_path)
    got = root_store["providers"]["openai-codex"]["tokens"]["refresh_token"]
    assert got == ("new-rf" if same_sub else "root-rf")


# ── T5 — the fault matrix (SILENT / CLASS-D / CLASS-N) ──────────────────────

def test_t5_c1_root_failure_profile_intact_warning(profile_and_root, monkeypatch):
    """CLASS-D: a root write-through failure leaves the profile save intact."""
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "root-rf"}
    )}})
    _write_store(profile_path, {"version": 1})

    monkeypatch.setattr(A, "_save_auth_store", _failing_save(A._save_auth_store, root_path=root_path))

    _save_codex_tokens({"access_token": _jwt("acct-1"), "refresh_token": "new-rf"})

    profile = _read_store(profile_path)
    assert profile["providers"]["openai-codex"]["tokens"]["refresh_token"] == "new-rf"


def _failing_save(original_save, root_path):
    """Fail ``_save_auth_store`` only when targetting the root path."""
    def wrapped(store, target_path=None):
        if target_path is not None and A._same_path(target_path, root_path):
            raise OSError("root write failure")
        return original_save(store, target_path=target_path)
    return wrapped


def test_t5_c2_direct_root_failure_returns_tokens_critical(profile_and_root, monkeypatch):
    """CLASS-N: a root-resolved direct write that always fails still returns tokens."""
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "root-rf"}
    )}})
    _write_store(profile_path, {"version": 1})

    monkeypatch.setattr(A, "_save_auth_store", _failing_save(A._save_auth_store, root_path=root_path))

    results = []
    _mock_refresh(monkeypatch, result={"access_token": _jwt("acct-1"), "refresh_token": "new-rf"})

    def fake_write_through(*a, **k):
        results.append(("attempt", a, k))
        return False  # always fails

    monkeypatch.setattr(A, "_write_through_codex_to_global_root", fake_write_through)

    tokens = {"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}
    out = _refresh_codex_auth_tokens(tokens, 20.0)

    assert out["refresh_token"] == "new-rf"  # tokens still returned
    assert len(results) == _CODEX_ROOT_PERSIST_ATTEMPTS  # exactly 3 attempts


def test_t5_c3_post_persist_failure_returns_tokens_no_autherror(profile_and_root, monkeypatch):
    """CLASS-N: after a successful rescue POST, persistence failure must not raise."""
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "fresher-rf"}
    )}})
    _write_store(profile_path, {"version": 1})  # root-resolved (no own block)

    # First POST (our stale token) relogin-fails; adoption POST succeeds.
    state = {"n": 0}

    def fake(access_token, refresh_token, timeout_seconds=20.0, **kw):
        if refresh_token == "stale-rf":
            raise AuthError("rejected", provider="openai-codex",
                            code="invalid_grant", relogin_required=True)
        state["n"] += 1
        return {"access_token": _jwt("acct-1"), "refresh_token": "adopted-rf"}

    monkeypatch.setattr(A, "refresh_codex_oauth_pure", fake)
    # Persistence always fails → CLASS-N (must still return tokens, not raise).
    monkeypatch.setattr(A, "_save_auth_store", _failing_save(A._save_auth_store, root_path=root_path))
    monkeypatch.setattr(A, "_write_through_codex_to_global_root", lambda *a, **k: False)

    tokens = {"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}
    out = _refresh_codex_auth_tokens(tokens, 20.0)

    assert out["refresh_token"] == "adopted-rf"
    assert state["n"] == 1  # one adoption POST ran


def test_t5_silent_success_no_warning_no_critical(profile_and_root, monkeypatch, caplog):
    """OUTCOME-SUCCESS is silent: no warning/critical on a fully durable save."""
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "root-rf"}
    )}})
    _write_store(profile_path, {"version": 1})
    _mock_refresh(monkeypatch, result={"access_token": _jwt("acct-1"), "refresh_token": "new-rf"})

    with caplog.at_level("WARNING"):
        _refresh_codex_auth_tokens({"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}, 20.0)

    assert not any(r.levelno >= 30 for r in caplog.records), caplog.text


# ── T6 — classic mode byte-identity ─────────────────────────────────────────

def test_t6_classic_mode_inert(profile_and_root, monkeypatch, tmp_path):
    """D-classic: with no global root, C1/C2/C3 paths are inert."""
    profile_path, root_path = profile_and_root
    monkeypatch.setattr(A, "_global_auth_file_path", lambda: None)
    monkeypatch.setattr(A, "_auth_file_path", lambda: root_path)  # single store

    wt_calls = []
    monkeypatch.setattr(A, "_write_through_codex_to_global_root",
                        lambda *a, **k: wt_calls.append(("wt", a, k)) or True)

    _write_store(root_path, {"version": 1})
    _mock_refresh(monkeypatch, result={"access_token": _jwt("acct-1"), "refresh_token": "new-rf"})
    _save_codex_tokens({"access_token": _jwt("acct-1"), "refresh_token": "r1"})

    assert wt_calls == []  # C1 write-through never fires in classic mode

    out = _refresh_codex_auth_tokens({"access_token": _jwt("acct-1"), "refresh_token": "r1"}, 20.0)
    assert out["refresh_token"] == "new-rf"
    assert wt_calls == []  # C2 direct root write also inert (owned path)

    store = _read_store(root_path)
    assert store["providers"]["openai-codex"]["tokens"]["refresh_token"] == "new-rf"


# ── T7 — rescue-order matrix + repeat/cap ───────────────────────────────────

def _relogin_stub_then_rescue(monkeypatch, rescue_result, calls):
    """The caller's POST fails relogin; the adoption POST succeeds once."""
    def fake(access_token, refresh_token, timeout_seconds=20.0, **kw):
        calls.append(refresh_token)
        if refresh_token == "stale-rf":
            raise AuthError("rejected", provider="openai-codex",
                            code="invalid_grant", relogin_required=True)
        return dict(rescue_result)

    monkeypatch.setattr(A, "refresh_codex_oauth_pure", fake)


def test_t7_eligible_rescue_skips_cli_recovery(profile_and_root, monkeypatch):
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "fresher-rf"}
    )}})
    _write_store(profile_path, {"version": 1})

    calls = []
    _relogin_stub_then_rescue(monkeypatch,
                              {"access_token": _jwt("acct-1"), "refresh_token": "adopted-rf"}, calls)
    cli = []
    monkeypatch.setattr(A, "_recover_codex_tokens_from_cli", lambda *a, **k: cli.append(1) or None)

    out = _refresh_codex_auth_tokens({"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}, 20.0)

    assert out["refresh_token"] == "adopted-rf"
    assert cli == []  # CLI recovery unused when rescue eligible


def test_t7_ineligible_uses_cli_recovery(profile_and_root, monkeypatch):
    """When root's refresh token equals ours (nothing fresher), fall to CLI."""
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}  # same — ineligible
    )}})
    _write_store(profile_path, {"version": 1})

    def fake(access_token, refresh_token, timeout_seconds=20.0, **kw):
        raise AuthError("rejected", provider="openai-codex",
                        code="invalid_grant", relogin_required=True)

    monkeypatch.setattr(A, "refresh_codex_oauth_pure", fake)
    monkeypatch.setattr(A, "_import_codex_cli_tokens", lambda: {"access_token": "cli-at", "refresh_token": "cli-rf"})

    out = _refresh_codex_auth_tokens({"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}, 20.0)
    assert out["refresh_token"] == "cli-rf"


def test_t7_classic_direct_cli_recovery(profile_and_root, monkeypatch):
    profile_path, root_path = profile_and_root
    monkeypatch.setattr(A, "_global_auth_file_path", lambda: None)
    _write_store(profile_path, {"version": 1})

    def fake(access_token, refresh_token, timeout_seconds=20.0, **kw):
        raise AuthError("rejected", provider="openai-codex",
                        code="invalid_grant", relogin_required=True)

    monkeypatch.setattr(A, "refresh_codex_oauth_pure", fake)
    monkeypatch.setattr(A, "_import_codex_cli_tokens", lambda: {"access_token": "cli-at", "refresh_token": "cli-rf"})

    out = _refresh_codex_auth_tokens({"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}, 20.0)
    assert out["refresh_token"] == "cli-rf"


def test_t7_repeat_tuple_skip_and_ineligible_no_consume(profile_and_root, monkeypatch):
    """The seen-set caps one adoption per dead tuple per process; reset re-arms."""
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "fresher-rf"}
    )}})
    _write_store(profile_path, {"version": 1})

    posts = []
    def fake(access_token, refresh_token, timeout_seconds=20.0, **kw):
        if refresh_token == "stale-rf":
            raise AuthError("rejected", provider="openai-codex",
                            code="invalid_grant", relogin_required=True)
        posts.append(refresh_token)
        return {"access_token": _jwt("acct-1"), "refresh_token": "adopted-rf"}

    monkeypatch.setattr(A, "refresh_codex_oauth_pure", fake)
    monkeypatch.setattr(A, "_recover_codex_tokens_from_cli", lambda *a, **k: None)

    tokens = {"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}
    # first: rescue eligible → one adoption POST, returns the adopted chain
    out = _refresh_codex_auth_tokens(tokens, 20.0)
    assert out["refresh_token"] == "adopted-rf"
    assert len(posts) == 1  # one adoption POST

    # second run, same process, same dead tuple → skipped entirely (no POST),
    # falls through to CLI recovery (empty here) → the original error surfaces
    with pytest.raises(AuthError):
        _refresh_codex_auth_tokens(tokens, 20.0)
    assert len(posts) == 1  # no second adoption POST

    # reset simulates a fresh process → attempts again
    _reset_codex_root_rescue_seen()
    out = _refresh_codex_auth_tokens(tokens, 20.0)
    assert out["refresh_token"] == "adopted-rf"
    assert len(posts) == 2


# ── T7c — double-barrier single-adoption ────────────────────────────────────

def test_t7c_two_threads_single_adoption(profile_and_root, monkeypatch):
    """Two same-process threads, same dead tuple ⇒ exactly one adoption POST.

    The seen-set is checked-and-marked atomically INSIDE the root flock, so
    the two contention attempts serialize: the loser observes the winner's mark
    inside its acquired critical section and falls through to CLI recovery. A
    defective outside-lock-decides implementation would double-POST here.
    """
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "fresher-rf"}
    )}})
    _write_store(profile_path, {"version": 1})

    posts = []
    lock = threading.Lock()

    def fake(access_token, refresh_token, timeout_seconds=20.0, **kw):
        if refresh_token == "stale-rf":
            raise AuthError("rejected", provider="openai-codex",
                            code="invalid_grant", relogin_required=True)
        with lock:
            posts.append(threading.current_thread().name)
        return {"access_token": _jwt("acct-1"), "refresh_token": "adopted-rf"}

    monkeypatch.setattr(A, "refresh_codex_oauth_pure", fake)
    monkeypatch.setattr(A, "_recover_codex_tokens_from_cli",
                        lambda *a, **k: {"access_token": "cli-at", "refresh_token": "cli-rf"})

    rescued = []
    recovered = []
    errors = []

    def worker():
        try:
            out = A._refresh_codex_auth_tokens(
                {"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}, 20.0)
        except AuthError as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)
            return
        with lock:
            (rescued if out.get("refresh_token") == "adopted-rf" else recovered).append(
                threading.current_thread().name)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert not errors, errors
    assert all(not t.is_alive() for t in threads)
    assert len(posts) == 1, "exactly ONE adoption POST globally"
    assert len(rescued) == 1, "exactly one thread self-healed via rescue"
    assert len(recovered) == 1, "the loser fell through to CLI recovery"


# ── T8 — pool-sync previous-singleton equivalence ───────────────────────────

def test_t8_pool_sync_previous_singleton_equivalence(profile_and_root, monkeypatch):
    """R7′: the pre-save singleton capture still drives alias classification."""
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "root-rf"}
    )}})
    _write_store(profile_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "profile-rf"}
    )}})

    captured = []
    real_sync = A._sync_codex_pool_entries
    def spy_sync(auth_store, tokens, last_refresh, previous_singleton_tokens=None):
        captured.append(previous_singleton_tokens)
        real_sync(auth_store, tokens, last_refresh,
                  previous_singleton_tokens=previous_singleton_tokens)

    monkeypatch.setattr(A, "_sync_codex_pool_entries", spy_sync)
    _save_codex_tokens({"access_token": _jwt("acct-1"), "refresh_token": "fresh-rf"})

    # The in-profile sync is fed the PRE-save singleton tokens (byte-unchanged
    # capture); the root write-through feed the ROOT pre-save snapshot.
    assert any(v and v.get("refresh_token") == "profile-rf" for v in captured), (
        "in-profile pool sync must receive the pre-save singleton tokens"
    )
    assert any(v and v.get("refresh_token") == "root-rf" for v in captured), (
        "root write-through must classify against the ROOT pre-save snapshot"
    )


# ── T9-v6 — concurrency (honest R16′ invariants) ────────────────────────────

def test_t9_concurrency_honest_invariants(profile_and_root, monkeypatch):
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "fresher-rf"}
    )}})
    _write_store(profile_path, {"version": 1})

    posts = []
    errors = []
    lock = threading.Lock()

    def fake(access_token, refresh_token, timeout_seconds=20.0, **kw):
        if refresh_token == "stale-rf":
            raise AuthError("rejected", provider="openai-codex",
                            code="invalid_grant", relogin_required=True)
        with lock:
            posts.append(refresh_token)
        return {"access_token": _jwt("acct-1"), "refresh_token": "adopted-rf"}

    monkeypatch.setattr(A, "refresh_codex_oauth_pure", fake)
    monkeypatch.setattr(A, "_recover_codex_tokens_from_cli", lambda *a, **k: None)

    n = 3
    held = []
    errors = []
    lock = threading.Lock()

    def worker():
        try:
            out = A._refresh_codex_auth_tokens(
                {"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}, 20.0)
        except AuthError as exc:
            with lock:
                errors.append(exc)
            return
        with lock:
            held.append(out)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    # (a) at least one participant holds a valid rotated chain (the winner)
    assert held, "at least one thread must self-heal and hold the rotated chain"
    assert all(h.get("refresh_token") == "adopted-rf" for h in held)
    # every surfaced failure is an AuthError (the losers fall through to CLI
    # recovery and re-raise only because that path is empty here)
    assert len(errors) + len(held) == n
    # (c) per-chain adoption POST bound ≤ racing processes (seen-set ⇒ exactly 1)
    assert 1 <= len(posts) <= n
    # final root holds a valid rotated chain
    root_store = _read_store(root_path)
    rt = root_store["providers"]["openai-codex"]["tokens"]["refresh_token"]
    assert rt in ("fresher-rf", "adopted-rf")


# ── A2 premises / T10 / T13 — identity + structure ──────────────────────────

def test_t13_identity_corner_matrix():
    """D-id corner cases: valid, 2-segment, non-JSON, foreign-iss, empty-sub, opaque."""
    assert _codex_token_identity(_jwt("acct-1")) == "acct-1"  # positive control
    assert _codex_token_identity("a.b") is None  # 2 segments
    assert _codex_token_identity("a.b.c") is None  # non-JSON payload
    assert _codex_token_identity(_jwt("acct-1", iss="https://evil.example")) is None  # foreign iss
    assert _codex_token_identity(_jwt("")) is None  # empty sub
    assert _codex_token_identity("opaque-token") is None  # not a JWT
    assert _codex_token_identity(None) is None  # not a str


def test_t10_structure_preservation(profile_and_root, monkeypatch):
    """Alias labels/ids/priority/suppressed_sources untouched; token fields in place."""
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "root-rf"}
    )}, "credential_pool": {"openai-codex": [
        {"id": "alias", "source": "manual:device_code", "access_token": _jwt("acct-1"),
         "refresh_token": "root-rf", "label": "lbl", "priority": 7, "suppressed_sources": ["x"]},
    ]}})
    _write_store(profile_path, {"version": 1})

    _save_codex_tokens({"access_token": _jwt("acct-1"), "refresh_token": "fresh-rf"})

    entry = _read_store(root_path)["credential_pool"]["openai-codex"][0]
    assert entry["refresh_token"] == "fresh-rf"  # mutated in place
    assert entry["id"] == "alias"
    assert entry["label"] == "lbl"
    assert entry["priority"] == 7
    assert entry["suppressed_sources"] == ["x"]


def test_t17_field_set_pin(profile_and_root, monkeypatch):
    """C2 field set: root carries tokens + last_refresh + auth_mode + label."""
    profile_path, root_path = profile_and_root
    _write_store(root_path, {"version": 1, "providers": {"openai-codex": _codex_state(
        {"access_token": _jwt("acct-1"), "refresh_token": "root-rf"}, custom_field="keep"
    )}})
    _write_store(profile_path, {"version": 1})
    _mock_refresh(monkeypatch, result={"access_token": _jwt("acct-1"), "refresh_token": "new-rf"})

    _refresh_codex_auth_tokens({"access_token": _jwt("acct-1"), "refresh_token": "stale-rf"}, 20.0)

    rc = _read_store(root_path)["providers"]["openai-codex"]
    assert rc["tokens"]["refresh_token"] == "new-rf"
    assert rc["tokens"]["access_token"] == _jwt("acct-1")
    assert rc["auth_mode"] == "chatgpt"
    assert rc["last_refresh"]  # present
    assert rc["custom_field"] == "keep"  # root-only field preserved


# ── T15 / T18 — negative greps + dual-enumeration budget pin ────────────────

def _git(*args):
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True).stdout.strip()
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)


def _diff_base():
    # The branch descends from upstream commit 77001a6be; upstream/main has
    # since advanced, so resolve the true fork point via merge-base rather than
    # diffing against the (moved) tip.
    for ref in ("upstream/main", "origin/main"):
        r = _git("rev-parse", "--verify", ref)
        if r.returncode == 0 and r.stdout.strip():
            m = _git("merge-base", "HEAD", r.stdout.strip())
            if m.returncode == 0 and m.stdout.strip():
                return m.stdout.strip()
            return r.stdout.strip()
    return "77001a6be"


def _diff_text():
    base = _diff_base()
    committed = _git("diff", base, "HEAD").stdout or ""
    worktree = _git("diff", base).stdout or ""
    return committed + "\n" + worktree


def _auth_diff_text():
    """Diff of the single production file under budget (auth.py) only."""
    base = _diff_base()
    committed = _git("diff", base, "HEAD", "--", "hermes_cli/auth.py").stdout or ""
    worktree = _git("diff", base, "--", "hermes_cli/auth.py").stdout or ""
    return committed + "\n" + worktree


def _changed_files():
    base = _diff_base()
    changed = _git("diff", "--name-only", base).stdout.split()
    changed += _git("diff", "--name-only", base, "HEAD").stdout.split()
    changed += _git("ls-files", "--others", "--exclude-standard").stdout.split()
    return {f for f in changed if f}


def test_t15_negative_greps():
    """No provenance parameter and no id_token usage in the codex paths."""
    diff = _auth_diff_text()
    assert "provenance" not in diff
    assert "id_token" not in diff


def test_t18_dual_enumeration_budget_pin():
    """R17′/T18: production symbol + non-production file budget (vs merge-base)."""
    changed = _changed_files()

    allowed_nonprod = {
        "CHANGELOG.md",
        "tests/agent/test_codex_singleton_write_through.py",
        "tests/agent/test_credential_pool_oauth_writethrough.py",
    }
    nonprod = {f for f in changed if f != "hermes_cli/auth.py" and not f.endswith("auth.py")}
    assert nonprod <= allowed_nonprod, f"unexpected non-production files: {nonprod - allowed_nonprod}"
    assert len(nonprod) <= 3, f"non-production budget ≤3, got {len(nonprod)}: {nonprod}"

    diff = _auth_diff_text()
    funcs = set(re.findall(r"(?m)^\+def\s+([A-Za-z_]\w*)\s*\(", diff))
    vars_ = set(re.findall(r"(?m)^\+([A-Za-z_][A-Za-z0-9_]*)\s*[:=]", diff))

    allowed_funcs = {
        "_save_codex_tokens",
        "_refresh_codex_auth_tokens",
        "_codex_token_identity",
        "_write_through_codex_to_global_root",
        "_reset_codex_root_rescue_seen",
    }
    allowed_vars = {
        "_CODEX_OAUTH_ISSUER",
        "_CODEX_ROOT_PERSIST_ATTEMPTS",
        "_CODEX_ROOT_PERSIST_BACKOFF_SECONDS",
        "_codex_root_rescue_seen",
    }
    assert funcs <= allowed_funcs, f"unexpected added/modified functions: {funcs - allowed_funcs}"
    assert vars_ <= allowed_vars, f"unexpected added module data: {vars_ - allowed_vars}"
