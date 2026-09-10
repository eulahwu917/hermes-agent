"""Desktop workstream-scoped recall (SPEC-INFRA-DESKRECALL-001, §3.8).

Desktop sessions carry chat_id=None/thread_id=None, so the Discord
thread-routing override never fired for them and recall fell back to the
global allowlist. The plugin now resolves, per recall call, the session cwd
(session ContextVar override OR terminal-scope fallback, §3.1) against
``desktop_context_root/<domain>/`` and applies that domain key's
``extra_tags`` as an ``any_strict`` filter (§3.2/§3.4) — with a fail-open
matrix that keeps every unrouted session byte-identical.

These tests pin the outgoing-filter behavior through fake ``arecall`` /
``areflect`` clients capturing kwargs (sync-mode automatic injection is what
``MemoryManager.prefetch_all`` drives — it calls ``provider.prefetch()``),
the two-session interleaved isolation, the Discord regression controls, and
the recall_sync trips-closed guard.
"""

import contextvars
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from agent import runtime_cwd
from plugins.memory.hindsight import HindsightMemoryProvider


# ---------------------------------------------------------------------------
# Fixtures / factories
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _hermetic_cwd(tmp_path, monkeypatch):
    """No TERMINAL_CWD, and no session-cwd ContextVar binding leaks between tests."""
    monkeypatch.delenv("TERMINAL_CWD", raising=False)
    token = runtime_cwd._SESSION_CWD.set(runtime_cwd._UNSET)
    yield
    runtime_cwd._SESSION_CWD.reset(token)


def _fact(text, tags):
    return SimpleNamespace(text=text, tags=tags)


def _capturing_client(results=None, reflect_text="synthesized", recall_error=None):
    """Fake Hindsight client capturing outgoing arecall/areflect kwargs."""
    recall_calls = []
    reflect_calls = []

    def _arecall(**kwargs):
        recall_calls.append(dict(kwargs))
        if recall_error is not None:
            raise recall_error
        return SimpleNamespace(results=results or [])

    def _areflect(**kwargs):
        reflect_calls.append(dict(kwargs))
        if recall_error is not None:
            raise recall_error
        return SimpleNamespace(text=reflect_text)

    client = SimpleNamespace()
    client.arecall = AsyncMock(side_effect=_arecall)
    client.areflect = AsyncMock(side_effect=_areflect)
    client.recall_calls = recall_calls
    client.reflect_calls = reflect_calls
    return client


def _desktop_provider(tmp_path, monkeypatch, *, config=None, routing=None,
                      routing_raw=None, platform="desktop", thread_id="",
                      results=None, reflect_text="synthesized", recall_error=None):
    """Initialized provider with a capturing fake client.

    ``routing`` (dict) is written as thread_routing.json; ``routing_raw``
    (str) writes arbitrary file content for malformed-table cases; neither
    means no routing file at all.
    """
    cfg = {
        "mode": "cloud",
        "apiKey": "test-key",
        "api_url": "http://localhost:9999",
        "bank_id": "test-bank",
        "recall_sync": True,
        "desktop_context_root": str(tmp_path / "desktop-context"),
    }
    cfg.update(config or {})
    cfg_path = tmp_path / "hindsight" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg))
    monkeypatch.setattr("plugins.memory.hindsight.get_hermes_home", lambda: tmp_path)
    routing_path = tmp_path / "hindsight" / "thread_routing.json"
    if routing is not None:
        routing_path.parent.mkdir(parents=True, exist_ok=True)
        routing_path.write_text(json.dumps(routing))
    if routing_raw is not None:
        routing_path.parent.mkdir(parents=True, exist_ok=True)
        routing_path.write_text(routing_raw)

    provider = HindsightMemoryProvider()
    kwargs = {"session_id": "test-session", "platform": platform}
    if thread_id:
        kwargs["thread_id"] = thread_id
    provider.initialize(**kwargs)
    client = _capturing_client(results=results, reflect_text=reflect_text,
                               recall_error=recall_error)
    provider._client = client
    return provider, client, tmp_path / "desktop-context"


def _bind(root, domain):
    """Bind the session-cwd ContextVar through the REAL setter (integration
    path, R2-3) and return the reset token."""
    return runtime_cwd.set_session_cwd(str(root / domain))


def _pack(root, *domains):
    root.mkdir(parents=True, exist_ok=True)
    for domain in domains:
        (root / domain).mkdir()


# ---------------------------------------------------------------------------
# §3.8.1 — outgoing-filter assertions (recall, reflect, tool path)
# ---------------------------------------------------------------------------


class TestOutgoingFilterDomain:
    ROUTING = {
        "infrastructure": {"extra_tags": ["infrastructure"]},
        "investments": {"extra_tags": ["investments"]},
    }

    def test_recall_forwards_domain_filter_and_passes_results_through(self, tmp_path, monkeypatch):
        mixed = _fact("shared infra+investments fact", ["infrastructure", "investments"])
        disjoint = _fact("investments-only fact", ["investments"])
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch, routing=self.ROUTING, results=[mixed, disjoint])
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            out = p._recall("icenova investments")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        kwargs = client.recall_calls[0]
        assert kwargs["tags"] == ["infrastructure"]
        assert kwargs["tags_match"] == "any_strict"
        # Disjoint-domain tags are never requested...
        assert "investments" not in kwargs["tags"]
        # ...and OR semantics live on the server: the plugin must NOT
        # post-filter a mixed-tag fact out (any_strict admits every fact
        # carrying >=1 domain tag, §3.5).
        assert [r.text for r in out] == [mixed.text, disjoint.text]
        # The stored baseline is left untouched (resolved per call, not stored).
        assert p._recall_tags is None
        assert p._recall_tags_match == "any"

    def test_reflect_entry_point_forwards_domain_filter(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing=self.ROUTING)
        _pack(root, "infrastructure")
        p._prefetch_method = "reflect"
        token = _bind(root, "infrastructure")
        try:
            direct = p._reflect("direct question")
            text = p.prefetch("prefetch reflect question")  # sync-mode auto-injection
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert direct == "synthesized"
        assert client.reflect_calls[0]["tags"] == ["infrastructure"]
        assert client.reflect_calls[0]["tags_match"] == "any_strict"
        assert client.reflect_calls[1]["tags"] == ["infrastructure"]
        assert "synthesized" in text  # nonempty eligible injection through prefetch

    def test_tool_path_recall_provenance(self, tmp_path, monkeypatch):
        fact = _fact("infra status fact", ["infrastructure"])
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch, routing=self.ROUTING, results=[fact])
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            raw = p.handle_tool_call("hindsight_recall", {"query": "where are we"})
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        payload = json.loads(raw)
        assert "tags=infrastructure" in payload["result"]  # tool-path provenance
        assert client.recall_calls[0]["tags"] == ["infrastructure"]

    def test_empty_bank_positive_control(self, tmp_path, monkeypatch):
        # Absence of hits alone is NOT a success signal: recall must still be
        # CALLED with the domain filter and return zero results without error.
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch, routing=self.ROUTING, results=[])
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            out = p._recall("anything")
            raw = p.handle_tool_call("hindsight_recall", {"query": "anything"})
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert out == []
        assert len(client.recall_calls) == 2
        assert all(c["tags"] == ["infrastructure"] for c in client.recall_calls)
        assert json.loads(raw)["result"] == "No relevant memories found."


# ---------------------------------------------------------------------------
# §3.8.2 — two-session interleaved isolation + real setter binding
# ---------------------------------------------------------------------------


class TestTwoSessionIsolation:
    ROUTING = {
        "infrastructure": {"extra_tags": ["infrastructure"]},
        "investments": {"extra_tags": ["investments"]},
    }

    def test_interleaved_contexts_stay_isolated(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing=self.ROUTING)
        _pack(root, "infrastructure", "investments")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)  # process cwd sits in a third, unrelated dir

        ctx_infra = contextvars.copy_context()
        ctx_infra.run(lambda: runtime_cwd.set_session_cwd(str(root / "infrastructure")))
        ctx_invest = contextvars.copy_context()
        ctx_invest.run(lambda: runtime_cwd.set_session_cwd(str(root / "investments")))

        ctx_infra.run(lambda: p._recall("infra question"))
        ctx_invest.run(lambda: p._recall("invest question"))
        ctx_infra.run(lambda: p._recall("infra question 2"))

        got = [c["tags"] for c in client.recall_calls]
        assert got == [["infrastructure"], ["investments"], ["infrastructure"]]
        assert all(c["tags_match"] == "any_strict" for c in client.recall_calls)

    def test_real_setter_binding_in_main_context(self, tmp_path, monkeypatch):
        # Integration path (R2-3): bind through the session-cwd ContextVar
        # setter in the caller's own context — not hand-set ContextVars only.
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing=self.ROUTING)
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            tags, tags_match = p._effective_recall_filter()
            p._recall("scoped question")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert tags == ["infrastructure"]
        assert tags_match == "any_strict"
        assert client.recall_calls[0]["tags"] == ["infrastructure"]


# ---------------------------------------------------------------------------
# §3.8.3 — fail-open matrix
# ---------------------------------------------------------------------------


class TestFailOpenMatrix:
    ROUTING = {
        "infrastructure": {"extra_tags": ["infrastructure"]},
        "investments": {"extra_tags": ["investments"]},
    }

    def test_unbound_context_terminal_scope_wins_not_launch_dir(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing=self.ROUTING)
        _pack(root, "infrastructure", "investments")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        monkeypatch.setenv("TERMINAL_CWD", str(root / "infrastructure"))
        p._recall("q")
        # Terminal-scope fallback wins; the process launch dir is never consulted.
        assert client.recall_calls[0]["tags"] == ["infrastructure"]

    def test_cleared_context_no_terminal_cwd_global_baseline(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing=self.ROUTING)
        _pack(root, "infrastructure")
        p._recall("q")
        assert "tags" not in client.recall_calls[0]
        assert p._recall_tags is None

    def test_nonexistent_session_override_is_final_over_valid_terminal_cwd(self, tmp_path, monkeypatch):
        # A NONEMPTY but nonexistent session override returns None and does NOT
        # fall through to a valid competing terminal cwd (§3.1 finality).
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing=self.ROUTING)
        _pack(root, "investments")
        monkeypatch.setenv("TERMINAL_CWD", str(root / "investments"))
        token = runtime_cwd.set_session_cwd(str(tmp_path / "ghost-dir"))
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]

    def test_outside_root(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing=self.ROUTING)
        _pack(root, "infrastructure")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        token = runtime_cwd.set_session_cwd(str(elsewhere))
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]

    def test_cwd_equals_root(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing=self.ROUTING)
        _pack(root, "infrastructure")
        token = runtime_cwd.set_session_cwd(str(root))
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]

    def test_unmatched_domain(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing=self.ROUTING)
        _pack(root, "unrouted-domain")
        token = runtime_cwd.set_session_cwd(str(root / "unrouted-domain"))
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]

    @pytest.mark.parametrize("entry", [{}, {"extra_tags": None}, {"extra_tags": []}])
    def test_empty_null_missing_tags_keep_baseline(self, tmp_path, monkeypatch, entry):
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch, routing={"infrastructure": entry})
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]

    def test_blank_tags_keep_baseline(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch,
            routing={"infrastructure": {"extra_tags": ["  ", ""]}})
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]

    def test_root_key_absent_branch_inert(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch, routing=self.ROUTING,
            config={"desktop_context_root": None})
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]

    @pytest.mark.parametrize("raw", ["{not valid json", "[1, 2]", "null"])
    def test_malformed_non_object_routing_table(self, tmp_path, monkeypatch, raw):
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing_raw=raw)
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]

    def test_missing_routing_file(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing=None)
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]

    def test_dormant_domain_route_is_absent(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch,
            routing={"infrastructure": {"extra_tags": ["infrastructure"], "dormant": True}})
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]

    def test_symlink_boundary_across_root_edge(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(tmp_path, monkeypatch, routing=self.ROUTING)
        _pack(root, "infrastructure")
        outside = tmp_path / "outside-real"
        outside.mkdir()
        link = root / "escape-link"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("symlinks unavailable on this host")
        token = runtime_cwd.set_session_cwd(str(link))
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        # Path.resolve() collapses the symlink: the cwd lands OUTSIDE the root.
        assert "tags" not in client.recall_calls[0]

    def test_root_pointing_at_file_resolution_failure(self, tmp_path, monkeypatch):
        # Path-resolution failure: desktop_context_root points at a FILE, so no
        # cwd can resolve under it -> baseline, not a crash.
        root_file = tmp_path / "rootfile"
        root_file.write_text("x")
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch, routing=self.ROUTING,
            config={"desktop_context_root": str(root_file)})
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]


# ---------------------------------------------------------------------------
# §3.8.4 — Discord regression controls
# ---------------------------------------------------------------------------


class TestDiscordRegression:
    def test_discord_thread_override_unchanged(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch, platform="discord", thread_id="thread-A",
            routing={
                "discord:thread-A": {"extra_tags": ["domain-a"]},
                "infrastructure": {"extra_tags": ["infrastructure"]},
            })
        p._recall("q")
        kwargs = client.recall_calls[0]
        assert kwargs["tags"] == ["channel:discord:thread-A", "domain-a"]
        assert kwargs["tags_match"] == "any_strict"

    def test_dormant_discord_entry_keeps_dormant_semantics(self, tmp_path, monkeypatch):
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch, platform="discord", thread_id="thread-B",
            routing={"discord:thread-B": {"extra_tags": ["domain-b"], "dormant": True}})
        p._recall("q")
        assert "tags" not in client.recall_calls[0]

    def test_desktop_domain_branch_never_shadows_thread_override(self, tmp_path, monkeypatch):
        # platform == "desktop" AND a platform:thread override already applied:
        # the thread override stays authoritative (§3.2 disjoint condition).
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch, platform="desktop", thread_id="thread-C",
            routing={
                "desktop:thread-C": {"extra_tags": ["thread-scoped"]},
                "infrastructure": {"extra_tags": ["infrastructure"]},
            })
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        kwargs = client.recall_calls[0]
        assert kwargs["tags"] == ["channel:desktop:thread-C", "thread-scoped"]
        assert "infrastructure" not in kwargs["tags"]


# ---------------------------------------------------------------------------
# §3.8.5 — automatic injection + observable failure signals
# ---------------------------------------------------------------------------


class TestAutomaticInjection:
    ROUTING = {"infrastructure": {"extra_tags": ["infrastructure"]}}

    def test_sync_prefetch_injects_domain_scoped_results(self, tmp_path, monkeypatch):
        # prefetch() is the provider surface MemoryManager.prefetch_all drives
        # for automatic injection (sync mode here, matching the deployed config).
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch, routing=self.ROUTING,
            results=[_fact("infra memory one", ["infrastructure"]),
                     _fact("infra memory two", ["infrastructure", "investments"])])
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            text = p.prefetch("current turn question")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "infra memory one" in text
        assert "infra memory two" in text
        kwargs = client.recall_calls[0]
        assert kwargs["tags"] == ["infrastructure"]
        assert kwargs["tags_match"] == "any_strict"
        status = p.recall_status()
        assert status is not None
        assert status.count == 2  # observable success signal, not just non-empty

    def test_prefetch_failure_surfaces_in_log_and_never_crashes(self, tmp_path, monkeypatch, caplog):
        # Recall errors must surface via the log envelope (not silently render
        # empty context) AND must not crash the conversation — optional memory
        # failures stay optional. Distinct from the valid-empty-bank case.
        caplog.set_level(logging.DEBUG, logger="plugins.memory.hindsight")
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch, routing=self.ROUTING,
            recall_error=TimeoutError("bank timeout"))
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            text = p.prefetch("current turn question")  # must not raise
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert text == ""
        assert p.recall_status() is None  # no false success signal
        failures = [r for r in caplog.records
                    if "Hindsight recall failed" in r.getMessage()]
        assert failures, "recall failure must surface in the log envelope, not silently"
        assert any(r.exc_info and r.exc_info[0] is TimeoutError for r in failures)


# ---------------------------------------------------------------------------
# §3.8.6 — sync-mode guard (trips closed, logged, every routing evaluation)
# ---------------------------------------------------------------------------


class TestSyncModeGuard:
    def test_sync_false_trips_closed_and_logs_every_evaluation(self, tmp_path, monkeypatch, caplog):
        caplog.set_level(logging.DEBUG, logger="plugins.memory.hindsight")
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch,
            routing={"infrastructure": {"extra_tags": ["infrastructure"]}},
            config={"recall_sync": False})
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")  # routable cwd bound from the start
        try:
            p._recall("initial cwd evaluation")
            p._reflect("second evaluation")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        assert "tags" not in client.recall_calls[0]
        assert "tags" not in client.reflect_calls[0]
        trips = [r for r in caplog.records if "trips closed" in r.getMessage()]
        assert len(trips) >= 2  # logged for EVERY routing evaluation

    def test_sync_false_keeps_installed_global_list(self, tmp_path, monkeypatch):
        # Feature disablement, not confidentiality: the baseline global list
        # stays in force verbatim when the desktop branch trips closed.
        p, client, root = _desktop_provider(
            tmp_path, monkeypatch,
            routing={"infrastructure": {"extra_tags": ["infrastructure"]}},
            config={"recall_sync": False, "recall_tags": ["global-tag"]})
        _pack(root, "infrastructure")
        token = _bind(root, "infrastructure")
        try:
            p._recall("q")
        finally:
            runtime_cwd._SESSION_CWD.reset(token)
        kwargs = client.recall_calls[0]
        assert kwargs["tags"] == ["global-tag"]
        assert kwargs["tags_match"] == "any"
