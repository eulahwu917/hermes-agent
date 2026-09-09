"""Spec §3.4 Phase-2 acceptance: the unified Attention read model, 14 cases.

Entry points: E1 = the live serve-scoped RPC client — the REAL ``web_server`` app +
``/api/ws`` sidecar + ``tui_gateway.handle_ws`` dispatch (loopback token auth), the exact
transport the Desktop client uses. EVERY §3.4 matrix read/ack (cases 1–7, 14) runs over
this boundary via the ``live_ws`` fixture; the dedicated ``test_e1_live_serve_ws_matrix``
additionally exercises the full cases 1–4 sequence over ONE connection with the
normalized post-ack read, B-unchanged, zero-mutation and timestamp-idempotence assertions
at that boundary. E1-direct (``tui_gateway.server.handle_request``) remains only for the
non-matrix extras (case 13's negative control, the scheduler-path write-failure test, the
E4 pins) — NOT labelled a live-client test. E2 = Desktop UI (Playwright, separate e2e
spec); E3 = real scheduler path via scratch ``zz-test-`` no_agent jobs (job NAME *and*
job ID carry the reserved prefix) created and deleted inside the test; E4 = raw rows
straight against ``cron.incidents``.

Guards baked into the module:
- fixture incident/job ids use the reserved ``zz-test-`` prefix;
- the production ``~/.hermes/cron/executions.db`` incident rows are snapshotted before the
  suite and content-compared after — the suite must never touch production rows;
- case 13 is the negative control: disabling the real list wrapper must make case 1 FAIL.
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import cron.attention as attention
import cron.executions as executions
import cron.incidents as incidents
import cron.jobs as cron_jobs
import cron.scheduler as sched
from tui_gateway import server

# --- helpers ---------------------------------------------------------------------------------


def _point_db(monkeypatch, tmp_path: Path) -> Path:
    """One throwaway executions.db for incidents + attention + executions (same file the
    scheduler uses)."""
    db = tmp_path / "cron" / "executions.db"
    monkeypatch.setattr(executions, "EXECUTIONS_FILE", db)
    monkeypatch.setattr(incidents, "EXECUTIONS_FILE", db)
    monkeypatch.setattr(attention, "EXECUTIONS_FILE", db)
    return db


def _rpc(**params):
    """E1-direct: the real cron.manage RPC registration via ``server.handle_request`` —
    the same handler the serve WS invokes (the live WS boundary itself is exercised by
    ``test_e1_live_serve_ws_matrix``; this is NOT labelled a live-client test)."""
    return server.handle_request(
        {"id": "1", "method": "cron.manage", "params": params})


def _rpc_ok(**params) -> dict:
    resp = _rpc(**params)
    assert "result" in resp, resp
    return resp["result"]


def _rpc_error(**params) -> dict:
    resp = _rpc(**params)
    assert "error" in resp, resp
    return resp["error"]


@pytest.fixture
def live_ws(monkeypatch):
    """E1 live: the real ``web_server`` app + ``/api/ws`` sidecar +
    ``tui_gateway.handle_ws`` dispatch over an authenticated loopback-token WebSocket —
    the exact transport the Desktop client uses. Only the peer/IP guard is bypassed
    (TestClient is not a loopback socket); the token credential check and the full
    handle_ws → cron.manage dispatch stay real. Yields a client whose ``ok``/``err``
    closures round-trip one cron.manage call each; frames are matched by request id so
    interleaved gateway pushes cannot confuse reads."""
    from starlette.testclient import TestClient

    from hermes_cli import web_server
    from hermes_cli.web_routers import chat_ws as chat_ws_mod

    monkeypatch.setattr(chat_ws_mod, "_DASHBOARD_EMBEDDED_CHAT_ENABLED", True)
    monkeypatch.setattr(chat_ws_mod, "_ws_request_is_allowed", lambda ws: True)
    prior_auth = getattr(web_server.app.state, "auth_required", False)
    web_server.app.state.auth_required = False

    token = web_server._SESSION_TOKEN

    class _LiveWs:
        def __init__(self, ws):
            self.ws = ws
            self._rid = 0

        def rpc(self, **params):
            self._rid += 1
            rid = str(self._rid)
            self.ws.send_text(json.dumps(
                {"id": rid, "method": "cron.manage", "params": params}))
            while True:
                frame = json.loads(self.ws.receive_text())
                if frame.get("id") == rid:
                    return frame

        def ok(self, **params):
            resp = self.rpc(**params)
            assert "result" in resp, resp
            return resp["result"]

        def err(self, **params):
            resp = self.rpc(**params)
            assert "error" in resp, resp
            return resp["error"]

    try:
        with TestClient(web_server.app) as client:
            with client.websocket_connect(f"/api/ws?token={token}") as ws:
                ready = json.loads(ws.receive_text())
                assert ready.get("params", {}).get("type") == "gateway.ready"
                yield _LiveWs(ws)
    finally:
        web_server.app.state.auth_required = prior_auth


@pytest.fixture
def cron_env(tmp_path, monkeypatch):
    """Isolated cron home (jobs registry + output dir + scripts) shared by E1/E3."""
    home = tmp_path / ".hermes"
    (home / "cron" / "output").mkdir(parents=True)
    (home / "scripts").mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(cron_jobs, "HERMES_DIR", home)
    monkeypatch.setattr(cron_jobs, "CRON_DIR", home / "cron")
    monkeypatch.setattr(cron_jobs, "JOBS_FILE", home / "cron" / "jobs.json")
    monkeypatch.setattr(cron_jobs, "OUTPUT_DIR", home / "cron" / "output")
    monkeypatch.setattr(sched, "_hermes_home", home)
    _point_db(monkeypatch, home)
    return home


def _write_script(home: Path, name: str, body: str) -> Path:
    script = home / "scripts" / name
    script.write_text(body)
    script.chmod(0o755)
    return script


def _scratch_job(home: Path, script_name: str, *, alarm: bool = False) -> dict:
    """Scratch no_agent job whose NAME **and ID** both carry the reserved ``zz-test-``
    provenance prefix (create_job mints a uuid hex id — the name prefix alone does not
    satisfy §3.4). The minted record is rewritten under the prefixed id in the isolated
    registry, so every incident id derives from ``zz-tes_`` and the tmp_path teardown
    removes all traces post-run."""
    job = cron_jobs.create_job(
        prompt=None,
        schedule="every 5m",
        name=f"zz-test-{script_name}",
        script=str(_write_script(home, script_name, _SCRIPT_BODIES[script_name])),
        no_agent=True,
        deliver="local",
        alarm=alarm,
    )
    job_id = f"zz-test-{uuid.uuid4().hex[:12]}"
    with cron_jobs.use_cron_store(home):
        cron_jobs.save_jobs(
            [j for j in cron_jobs.load_jobs() if j["id"] != job["id"]]
            + [{**job, "id": job_id}])
    return {**job, "id": job_id}


_SCRIPT_BODIES = {
    "fail.sh": "#!/bin/bash\necho 'zz-test scratch failure text'\nexit 1\n",
    "alarm.sh": "#!/bin/bash\necho 'zz-test exit-0 alarm text'\n",
    "silent.sh": "#!/bin/bash\ntrue\n",
}


def _run_scratch_tick(job: dict, home: Path, deliveries: list) -> bool:
    """E3: one real scheduler tick for a scratch job (mirrors the proven drift-alert
    harness; the no_agent path short-circuits before any agent machinery)."""
    fake_db = MagicMock()

    def fake_deliver(jb, content, adapters=None, loop=None, **kwargs):
        deliveries.append(content)
        return None

    with cron_jobs.use_cron_store(home):
        cron_jobs.save_jobs([job])
        with patch("cron.scheduler._hermes_home", home), \
             patch("cron.scheduler._launch_external_cron_worker", return_value=False), \
             patch("cron.scheduler_delivery._resolve_origin", return_value=None), \
             patch("hermes_cli.env_loader.load_hermes_dotenv"), \
             patch("hermes_cli.env_loader.reset_secret_source_cache"), \
             patch("hermes_state_registry.acquire", return_value=fake_db), \
             patch("tools.mcp_tool_discovery.discover_mcp_tools", return_value=[]), \
             patch("hermes_cli.runtime_provider.resolve_runtime_provider",
                   return_value={
                       "api_key": "test-key",
                       "base_url": "https://example.invalid/v1",
                       "provider": "openrouter",
                       "api_mode": "chat_completions",
                   }), \
             patch.object(sched, "_deliver_result", side_effect=fake_deliver):
            return sched.run_one_job(dict(job))


def _incident_ids_for_job(job_id: str) -> list[str]:
    return [row["id"] for row in incidents.list_incidents() if row["job_id"] == job_id]


def _db_row_count() -> int:
    return incidents.count_incidents()


def _db_max_rowid() -> int:
    with incidents._transaction() as conn:
        row = conn.execute("SELECT MAX(rowid) AS m FROM cron_incidents").fetchone()
    return int(row["m"] or 0)


# --- production-row protection (spec §3.4 provenance) ------------------------------------------


def _read_production_rows():
    """Read-only snapshot of the real production incident rows; None when the file does not
    exist on this host. NEVER opens the production DB for writing."""
    db = Path.home() / ".hermes" / "cron" / "executions.db"
    if not db.is_file():
        return None
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT id, job_id, error_sig, state, failure_type, first_seen_at, last_seen_at, "
            "acked_at, closed_at, error, output_file FROM cron_incidents ORDER BY id"
        ).fetchall()
        return [tuple(r) for r in rows]
    finally:
        conn.close()


@pytest.fixture(scope="module")
def production_rows():
    """Snapshot production cron_incidents before the module's tests and content-compare after.
    The 576b65cc2144 row (and every other production row) must be byte-identical."""
    before = _read_production_rows()
    yield before
    after = _read_production_rows()
    assert before == after, (
        "production cron_incidents rows changed during the attention suite — a test touched "
        "the real execution DB")


# ===============================================================================================
# §3.4 case 1 — list-open shows seeded incidents (E3 seed + E1 read), strict filter error
# ===============================================================================================


def _case1_assertions(cron_env, rpc_ok=_rpc_ok, rpc_error=_rpc_error):
    """The case-1 wire assertions, runnable over ANY E1 boundary (the live WS client in
    the §3.4 matrix, or the direct dispatch used by the extras)."""
    # Seed incident A via the REAL scheduler path (E3): scratch failing no_agent job.
    job_a = _scratch_job(cron_env, "fail.sh")
    deliveries: list = []
    assert _run_scratch_tick(job_a, cron_env, deliveries) is True
    # Seed incident B via direct raw insert (E4-level seeding).
    b_id, b_new = incidents.upsert_incident(
        "zz-test-job-b", "zz-test direct insert boom", output_file="/tmp/zz-test-b-output.md")
    assert b_new and b_id.startswith("zz-tes")

    result = rpc_ok(action="list_attention", open_only=True)
    items = result["items"]
    assert result["count"] == len(items)
    by_job = {item["job_id"]: item for item in items}
    assert set(by_job) == {job_a["id"], "zz-test-job-b"}

    # Normalized wire shape for both items.
    for item in items:
        assert item["kind"] == "cron_incident"
        assert item["state"] == "open"
        assert item["severity"] == "warning"
        assert item["source"] == "cron"
        assert set(item) >= {
            "kind", "id", "source", "severity", "title", "body_excerpt", "first_seen_at",
            "last_seen_at", "state", "acked_at", "evidence_ref",
            "job_id", "job_name", "error_sig", "output_file"}
        assert item["first_seen_at"] and item["last_seen_at"]
        assert item["acked_at"] is None

    # E3 item carries the real scheduler metadata (registry-backed job name + output file).
    item_a = by_job[job_a["id"]]
    assert item_a["job_name"] == f"zz-test-fail.sh"
    assert item_a["error_sig"]
    assert item_a["output_file"] and Path(item_a["output_file"]).is_file()
    # Excerpt source = the run's output file (delivery framing + stdout); the dedicated
    # distinct-source test pins file-vs-error precedence exactly.
    assert "script failed" in item_a["body_excerpt"]
    assert item_a["evidence_ref"] == item_a["output_file"]
    # Direct-insert item: honest fallbacks, no invented metadata.
    item_b = by_job["zz-test-job-b"]
    assert item_b["job_name"] is None
    assert item_b["title"] == "zz-test-job-b"
    assert item_b["output_file"] == "/tmp/zz-test-b-output.md"
    assert "direct insert boom" in item_b["body_excerpt"]

    # STRICT filter validation: invalid state is an explicit error, never an empty list.
    err = rpc_error(action="list_attention", open_only=False, state="bogus")
    assert err["code"] == 4066
    assert "invalid attention state filter" in err["message"]

    return by_job, job_a


def test_case1_list_open_shows_seeded_incidents(cron_env, production_rows, live_ws):
    _case1_assertions(cron_env, live_ws.ok, live_ws.err)


# ===============================================================================================
# R7-1 strict-filter negatives — malformed filter values are EXPLICIT 4066 errors over the
# live WS, validated BEFORE any lossy coercion (is_truthy_value would map unknown strings to
# False; _str_arg would collapse falsey values to '' → None). An invalid filter must never
# silently become a successful (possibly empty) query, and must never mutate any row.
# ===============================================================================================

_SCRATCH_ROW_COLS = (
    "id, job_id, error_sig, state, failure_type, first_seen_at, last_seen_at, "
    "acked_at, closed_at, error, output_file")

# falsey/non-string supplied states: each would survive _str_arg('' collapse) as None today.
_INVALID_STATE_VALUES = [False, 0, "", [], {}]
# non-bool supplied open_only: each would survive is_truthy_value coercion today.
_INVALID_OPEN_ONLY_VALUES = ["bogus", 1, 0, [], {}]


def _all_scratch_rows():
    """Raw E4 content snapshot of every scratch-DB cron_incidents row (id-ordered) —
    the unchanged-row read-back oracle for the strict-filter negatives."""
    with incidents._transaction() as conn:
        return [
            tuple(r) for r in conn.execute(
                f"SELECT {_SCRATCH_ROW_COLS} FROM cron_incidents ORDER BY id").fetchall()
        ]


@pytest.mark.parametrize("bad_state", _INVALID_STATE_VALUES, ids=repr)
def test_strict_state_filter_rejects_falsey_non_strings(
        cron_env, production_rows, live_ws, bad_state):
    # EMPTY control: with zero rows an invalid filter is STILL an explicit error —
    # never a successful empty list.
    err = live_ws.err(action="list_attention", open_only=False, state=bad_state)
    assert err["code"] == 4066
    assert "invalid attention state filter" in err["message"]

    # SEEDED control: an open row exists; the invalid filter still errors and the row is
    # untouched (unchanged-row read-back).
    seed_id, seed_new = incidents.upsert_incident(
        "zz-test-strict-state", "zz-test strict state filter seed")
    assert seed_new and seed_id.startswith("zz-tes")
    before = _all_scratch_rows()
    err = live_ws.err(action="list_attention", open_only=False, state=bad_state)
    assert err["code"] == 4066
    assert "invalid attention state filter" in err["message"]
    assert _all_scratch_rows() == before, "invalid filter must not mutate any row"

    # VALID control: only malformed values error — the seeded row is still listable.
    items = live_ws.ok(action="list_attention", open_only=True)["items"]
    assert any(item["id"] == seed_id for item in items)


@pytest.mark.parametrize("bad_open", _INVALID_OPEN_ONLY_VALUES, ids=repr)
def test_strict_open_only_filter_rejects_non_bools(
        cron_env, production_rows, live_ws, bad_open):
    # EMPTY control: an invalid open_only errors even with zero rows.
    err = live_ws.err(action="list_attention", open_only=bad_open)
    assert err["code"] == 4066
    assert "open_only must be a boolean" in err["message"]

    # SEEDED control: the invalid filter errors and the row is untouched.
    seed_id, seed_new = incidents.upsert_incident(
        "zz-test-strict-open", "zz-test strict open_only filter seed")
    assert seed_new and seed_id.startswith("zz-tes")
    before = _all_scratch_rows()
    err = live_ws.err(action="list_attention", open_only=bad_open)
    assert err["code"] == 4066
    assert "open_only must be a boolean" in err["message"]
    assert _all_scratch_rows() == before, "invalid filter must not mutate any row"

    # VALID control: only malformed values error — the seeded row is still listable.
    items = live_ws.ok(action="list_attention", open_only=True)["items"]
    assert any(item["id"] == seed_id for item in items)


# ===============================================================================================
# §3.4 case 2 — ack closes exactly one
# ===============================================================================================


def test_case2_ack_closes_exactly_one(cron_env, production_rows, live_ws):
    by_job, job_a = _case1_assertions(cron_env, live_ws.ok, live_ws.err)
    item_a = by_job[job_a["id"]]
    item_b = by_job["zz-test-job-b"]

    outcome = live_ws.ok(action="ack_attention", kind="cron_incident", id=item_a["id"])
    assert outcome == {"status": "closed-ok", "changed": True}

    # B unchanged (still open, same id); A closed on the wire — the normalized
    # post-ack list read happens over the same live boundary.
    after = {i["id"]: i for i in live_ws.ok(action="list_attention", open_only=False)["items"]}
    assert after[item_a["id"]]["state"] == "closed"
    assert after[item_a["id"]]["acked_at"], "acked_at must be set on the wire item"
    assert "closed_at" not in after[item_a["id"]], "closed_at is raw-E4 only, never wire"
    assert after[item_b["id"]]["state"] == "open"
    assert after[item_b["id"]]["acked_at"] is None

    # Raw E4 read-back: acked_at + closed_at both persisted.
    raw_a = incidents.get_incident(item_a["id"])
    assert raw_a["state"] == "closed" and raw_a["acked_at"] and raw_a["closed_at"]

    # The ack commit touched the attention.changed sentinel (cross-process refresh signal).
    sentinel = attention.attention_changed_path()
    assert sentinel.is_file()


# ===============================================================================================
# §3.4 case 3 — unknown id fail-closed
# ===============================================================================================


def test_case3_unknown_id_fail_closed(cron_env, production_rows, live_ws):
    _case1_assertions(cron_env, live_ws.ok, live_ws.err)
    before_count, before_max = _db_row_count(), _db_max_rowid()

    err = live_ws.err(action="ack_attention", kind="cron_incident", id="zz-tes_doesnotexist")
    assert err["code"] == 4065
    assert "unknown-id" in err["message"]

    assert _db_row_count() == before_count, "unknown-id ack must not mutate rows"
    assert _db_max_rowid() == before_max, "unknown-id ack must not mint rows"


# ===============================================================================================
# §3.4 case 4 — already-closed idempotent
# ===============================================================================================


def test_case4_already_closed_idempotent(cron_env, production_rows, live_ws):
    by_job, _ = _case1_assertions(cron_env, live_ws.ok, live_ws.err)
    item_a = next(i for i in by_job.values() if i["job_name"] == "zz-test-fail.sh")

    assert live_ws.ok(action="ack_attention", kind="cron_incident", id=item_a["id"])["changed"] is True
    raw_after_first = incidents.get_incident(item_a["id"])

    outcome = live_ws.ok(action="ack_attention", kind="cron_incident", id=item_a["id"])
    assert outcome == {"status": "already-closed", "changed": False}

    raw_after_second = incidents.get_incident(item_a["id"])
    assert raw_after_second["acked_at"] == raw_after_first["acked_at"], "no double timestamp mutation"
    assert raw_after_second["closed_at"] == raw_after_first["closed_at"]


# ===============================================================================================
# §3.4 case 5 — ack survives job deletion
# ===============================================================================================


def test_case5_ack_survives_job_deletion(cron_env, production_rows, live_ws):
    by_job, job_a = _case1_assertions(cron_env, live_ws.ok, live_ws.err)
    item_a = by_job[job_a["id"]]

    # E3: delete the scratch job, then ack its incident — id-based resolution, not
    # job-registry-bound.
    with cron_jobs.use_cron_store(cron_env):
        assert cron_jobs.remove_job(job_a["id"]) is True
    assert cron_jobs.list_jobs() == [] or all(j["id"] != job_a["id"] for j in cron_jobs.list_jobs())

    outcome = live_ws.ok(action="ack_attention", kind="cron_incident", id=item_a["id"])
    assert outcome == {"status": "closed-ok", "changed": True}
    assert incidents.get_incident(item_a["id"])["state"] == "closed"


# ===============================================================================================
# §3.4 case 6 — recurrence re-arms (episodic)
# ===============================================================================================


def test_case6_recurrence_rearms(cron_env, production_rows, live_ws):
    by_job, job_a = _case1_assertions(cron_env, live_ws.ok, live_ws.err)
    item_a = by_job[job_a["id"]]
    item_b = by_job["zz-test-job-b"]

    # Close episode A, then the SAME signature recurs through the real scheduler (E3).
    assert live_ws.ok(action="ack_attention", kind="cron_incident", id=item_a["id"])["changed"] is True
    deliveries: list = []
    assert _run_scratch_tick(job_a, cron_env, deliveries) is True

    ids = _incident_ids_for_job(job_a["id"])
    assert item_a["id"] in ids and len(ids) == 2, f"expected a new episode, got {ids}"
    rearmed = next(i for i in ids if i != item_a["id"])

    # Raw E4: the NEW row is detected; the old episode stays closed.
    raw_new = incidents.get_incident(rearmed)
    assert raw_new["state"] == "detected"
    assert incidents.get_incident(item_a["id"])["state"] == "closed"

    # E1: the re-armed episode appears open; B unchanged.
    wire = {i["id"]: i for i in live_ws.ok(action="list_attention", open_only=False)["items"]}
    assert wire[rearmed]["state"] == "open"
    assert wire[item_a["id"]]["state"] == "closed"
    assert wire[item_b["id"]]["state"] == "open"
    assert wire[item_b["id"]]["id"] == item_b["id"]


# ===============================================================================================
# §3.4 case 7 — exit-0 alarm ingestion (per-job alarm flag)
# ===============================================================================================


def test_case7_exit0_alarm_ingestion(cron_env, production_rows, live_ws):
    job = _scratch_job(cron_env, "alarm.sh", alarm=True)
    deliveries: list = []
    assert _run_scratch_tick(job, cron_env, deliveries) is True

    ids = _incident_ids_for_job(job["id"])
    assert len(ids) == 1, "exit-0 alarm stdout must mint an incident despite exit 0"
    raw = incidents.get_incident(ids[0])
    assert raw["state"] == "detected"
    assert "exit-0 alarm text" in raw["error"]

    # E1: normalized item present with the alarm text as the body excerpt.
    items = live_ws.ok(action="list_attention", open_only=True)["items"]
    mine = [i for i in items if i["job_id"] == job["id"]]
    assert len(mine) == 1 and mine[0]["kind"] == "cron_incident"
    assert mine[0]["state"] == "open" and mine[0]["severity"] == "warning"
    assert "exit-0 alarm text" in mine[0]["body_excerpt"]
    assert mine[0]["output_file"] and Path(mine[0]["output_file"]).is_file()

    # Control: the same script WITHOUT the alarm flag stays silent-green (no incident).
    plain = _scratch_job(cron_env, "alarm.sh", alarm=False)
    assert _run_scratch_tick(plain, cron_env, deliveries) is True
    assert _incident_ids_for_job(plain["id"]) == []

    # Control (review round-1 regression): an alarm-flagged job whose script emits NOTHING is
    # silent-green — the scheduler's SILENT_MARKER sentinel is not stdout and must never mint
    # an incident (the first cut fired the gate on the "[SILENT]" sentinel).
    silent = _scratch_job(cron_env, "silent.sh", alarm=True)
    assert _run_scratch_tick(silent, cron_env, deliveries) is True
    assert _incident_ids_for_job(silent["id"]) == [], (
        "silent (empty-stdout) alarm-flagged run must not mint an incident")


# ===============================================================================================
# §3.4 case 12 — auth fail-closed (no valid serve session → rejected, no state change)
# ===============================================================================================


def test_case12_auth_fail_closed(cron_env, production_rows, monkeypatch):
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect
    from hermes_cli import web_server
    from hermes_cli.web_routers import chat_ws as chat_ws_mod

    _case1_assertions(cron_env)
    before_count = _db_row_count()

    # Gated mode (the tailnet serve): the real WS auth gate requires a ticket.
    monkeypatch.setattr(chat_ws_mod, "_DASHBOARD_EMBEDDED_CHAT_ENABLED", True)
    web_server.app.state.auth_required = True
    try:
        with TestClient(web_server.app) as client:
            with pytest.raises(WebSocketDisconnect) as exc_info:
                with client.websocket_connect("/api/ws"):
                    pass  # pragma: no cover — the connect itself must refuse
    finally:
        web_server.app.state.auth_required = False

    assert exc_info.value.code == 4401, "unauthenticated WS must be refused"
    assert _db_row_count() == before_count, "refused session must not change attention state"
    assert incidents.count_incidents(state="closed") == 0


# ===============================================================================================
# §3.4 case 13 — negative control: disabling the real wrapper makes case 1 FAIL
# ===============================================================================================


def test_case13_negative_control_wrapper_disabled(cron_env, production_rows, monkeypatch):
    # Seed the same way case 1 does.
    _case1_assertions(cron_env)

    # Disable the real list wrapper (patch out the underlying read the RPC delegates to).
    # If the suite mocked the RPC, disabling the real implementation would change nothing and
    # this test would pass — the point is that it must FAIL the case-1 assertions.
    monkeypatch.setattr(
        attention, "list_attention",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("attention wrapper disabled")))

    resp = _rpc(action="list_attention", open_only=True)
    assert "error" in resp, "disabled wrapper must surface as an RPC error, not fake data"


# ===============================================================================================
# §3.4 case 14 — CLI parity (CLI stays raw-schema; same DB end-state as the RPC ack)
# ===============================================================================================


def test_case14_cli_parity(cron_env, production_rows, capsys, live_ws):
    from hermes_cli.cron import cron_incidents

    open_id, _ = incidents.upsert_incident("zz-test-cli-open", "cli parity boom")
    closed_id, _ = incidents.upsert_incident("zz-test-cli-closed", "cli parity closed boom")
    assert incidents.ack_incident(closed_id) is True  # raw close for the parity pair

    # E1 wire states for the same rows, over the live serve boundary.
    wire = {i["id"]: i for i in live_ws.ok(action="list_attention", open_only=False)["items"]}
    assert wire[open_id]["state"] == "open"
    assert wire[closed_id]["state"] == "closed"

    # CLI list prints RAW states (detected/closed), mapped by the documented table to the same
    # open/closed the RPC reports. detected → open; closed → closed.
    list_args = argparse.Namespace(incident_action="list", state=None, incident_id=None)
    assert cron_incidents(list_args) == 0
    out = capsys.readouterr().out
    assert open_id in out and closed_id in out
    assert "detected" in out and "closed" in out  # raw schema, not the wire vocabulary

    # CLI ack on the open row: same DB end-state the RPC ack produces (closed + timestamps).
    sentinel = attention.attention_changed_path()
    sentinel.unlink(missing_ok=True)
    ack_args = argparse.Namespace(incident_action="ack", state=None, incident_id=open_id)
    assert cron_incidents(ack_args) == 0
    out = capsys.readouterr().out
    assert "acknowledged" in out.lower()

    raw = incidents.get_incident(open_id)
    assert raw["state"] == "closed" and raw["acked_at"] and raw["closed_at"]
    # CLI ack is a commit too — the cross-process refresh signal must fire.
    assert sentinel.is_file(), "CLI ack must touch the attention.changed sentinel"

    # Parity close: E1 now reports the same closed the DB holds.
    wire = {i["id"]: i for i in live_ws.ok(action="list_attention", open_only=False)["items"]}
    assert wire[open_id]["state"] == "closed"


# ===============================================================================================
# §3.1 R2-residual-3a — scheduler-path write failure: WARNING + documented accepted loss
# ===============================================================================================


def test_r2_3a_scheduler_write_failure_warns_and_accepts_loss(cron_env, production_rows, caplog):
    job = _scratch_job(cron_env, "fail.sh")

    # Induced write failure (store raises as if locked): delivery unaffected, WARNING logged.
    deliveries: list = []
    with caplog.at_level(logging.WARNING, logger="cron.scheduler"), \
         patch("cron.incidents.upsert_incident", side_effect=RuntimeError("db locked")):
        assert _run_scratch_tick(job, cron_env, deliveries) is True
    assert any("Incident store unavailable" in r.message for r in caplog.records), (
        "write failure must be logged at WARNING (spec §3.1 R2 residual 3a)")

    # Next run healthy/silent: successful empty reads; the missing row is the documented
    # ACCEPTED outcome (opportunistic recovery — no retry queue).
    silent = _scratch_job(cron_env, "silent.sh")
    assert _run_scratch_tick(silent, cron_env, deliveries) is True
    assert _incident_ids_for_job(job["id"]) == []
    assert _rpc_ok(action="list_attention", open_only=True)["items"] == []


# ===============================================================================================
# Direct module-level contract pins (E4): alert_event ack + wire mapping table
# ===============================================================================================


def test_e4_alert_event_ack_and_union(cron_env, production_rows, monkeypatch):
    db = cron_env / "cron" / "executions.db"
    with attention._transaction() as conn:
        conn.execute(
            """INSERT INTO attention_events
               (id, source, event_id, producer, alert_type, severity, title, body,
                occurred_at, received_at)
               VALUES ('alpharelay_ev1','alpharelay','ev1','producer-x','price_alert','critical',
                       'CRIT title', 'long body text', '2026-09-08T00:00:00',
                       '2026-09-08T01:00:00')""")

    # Wire mapping table for alert_event (raw attention_events → unified shape).
    items = _rpc_ok(action="list_attention", open_only=True, state="open")["items"]
    ev = [i for i in items if i["kind"] == "alert_event"]
    assert len(ev) == 1
    item = ev[0]
    assert (item["id"], item["source"], item["severity"], item["title"]) == (
        "alpharelay_ev1", "alpharelay", "critical", "CRIT title")
    assert item["producer"] == "producer-x" and item["alert_type"] == "price_alert"
    assert item["first_seen_at"] == "2026-09-08T00:00:00"  # occurred_at
    assert item["last_seen_at"] == "2026-09-08T01:00:00"  # received_at
    assert item["body_excerpt"] == "long body text"

    # RPC ack of an alert_event: closed-ok → already-closed; sentinel touched on the close.
    sentinel = attention.attention_changed_path()
    sentinel.unlink(missing_ok=True)
    assert _rpc_ok(action="ack_attention", kind="alert_event", id="alpharelay_ev1") == {
        "status": "closed-ok", "changed": True}
    assert sentinel.is_file()
    assert _rpc_ok(action="ack_attention", kind="alert_event", id="alpharelay_ev1") == {
        "status": "already-closed", "changed": False}
    err = _rpc_error(action="ack_attention", kind="alert_event", id="alpharelay_ghost")
    assert err["code"] == 4065
    err = _rpc_error(action="ack_attention", kind="banana", id="alpharelay_ev1")
    assert err["code"] == 4066

    # Raw→wire mapping table pins (E4): detected/alerted → open; closed → closed.
    d_id, _ = incidents.upsert_incident("zz-test-e4", "map me detected")
    a_id, _ = incidents.upsert_incident("zz-test-e4", "map me alerted")
    incidents.set_incident_state(a_id, "alerted")
    c_id, _ = incidents.upsert_incident("zz-test-e4", "map me closed")
    incidents.ack_incident(c_id)
    wire = {i["id"]: i for i in _rpc_ok(action="list_attention", open_only=False)["items"]}
    assert wire[d_id]["state"] == "open"  # raw detected → wire open
    assert wire[a_id]["state"] == "open"  # raw alerted → wire open
    assert wire[c_id]["state"] == "closed"  # raw closed → wire closed
    assert "closed_at" not in wire[c_id]  # closed_at stays raw-only
    assert wire[c_id]["acked_at"]  # acked_at is wire-visible


# ===============================================================================================
# §3.4 E1 across the LIVE serve boundary — the real WS transport, not a direct dispatch
# ===============================================================================================


def test_e1_live_serve_ws_matrix(cron_env, production_rows, live_ws):
    """The §3.4 cases 1–4 matrix over ONE live serve-scoped WebSocket connection — the
    full boundary sequence the reviewer required: A+B seeded (case 1 requires both), the
    NORMALIZED post-ack list read over the wire, B unchanged, unknown-id zero mutation,
    and byte-identical timestamps across the second (idempotent) ack. Raw E4 read-backs
    stay direct (explicitly raw fields only)."""
    # case 1 over the wire: both seeded incidents as normalized items (reuses the strong
    # assertions — every wire-shape field, strict-filter error, metadata, excerpt source).
    by_job, job_a = _case1_assertions(cron_env, live_ws.ok, live_ws.err)
    item_a = by_job[job_a["id"]]
    item_b = by_job["zz-test-job-b"]

    # case 2 over the wire: ack closes exactly one. The NORMALIZED post-ack list read
    # happens over the SAME boundary — A closed + acked_at set (closed_at raw-only),
    # B untouched.
    outcome = live_ws.ok(action="ack_attention", kind="cron_incident", id=item_a["id"])
    assert outcome == {"status": "closed-ok", "changed": True}
    after = {i["id"]: i for i in live_ws.ok(action="list_attention", open_only=False)["items"]}
    assert after[item_a["id"]]["state"] == "closed"
    assert after[item_a["id"]]["acked_at"], "acked_at must be set on the wire item"
    assert "closed_at" not in after[item_a["id"]], "closed_at is raw-E4 only, never wire"
    assert after[item_b["id"]]["state"] == "open"
    assert after[item_b["id"]]["acked_at"] is None
    raw_after_first = incidents.get_incident(item_a["id"])
    assert raw_after_first["state"] == "closed" and raw_after_first["acked_at"] and raw_after_first["closed_at"]

    # case 3 over the wire: unknown id fail-closed with ZERO DB mutation.
    before_count, before_max = _db_row_count(), _db_max_rowid()
    err = live_ws.err(action="ack_attention", kind="cron_incident", id="zz-tes_ghost")
    assert err["code"] == 4065
    assert _db_row_count() == before_count, "unknown-id ack must not mutate rows"
    assert _db_max_rowid() == before_max, "unknown-id ack must not mint rows"

    # case 4 over the wire: already-closed idempotent, timestamps byte-identical.
    outcome = live_ws.ok(action="ack_attention", kind="cron_incident", id=item_a["id"])
    assert outcome == {"status": "already-closed", "changed": False}
    raw_after_second = incidents.get_incident(item_a["id"])
    assert raw_after_second["acked_at"] == raw_after_first["acked_at"], "no double timestamp mutation"
    assert raw_after_second["closed_at"] == raw_after_first["closed_at"]



# ===============================================================================================
# §3.2 excerpt-source pin — body_excerpt comes from the OUTPUT FILE; error text is the fallback
# ===============================================================================================


def test_body_excerpt_prefers_output_file_with_honest_fallback(cron_env, production_rows):
    # Distinct error text vs file content: the wire excerpt must come from the FILE
    # (spec §3.2 "excerpt from output_file") — the error text must not leak into it.
    out = cron_env / "cron" / "output" / "zz-test-excerpt-source.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("zz-test file excerpt content\nsecond payload line\n")
    fid, _ = incidents.upsert_incident(
        "zz-test-excerpt", "zz-test error text must not leak", output_file=str(out))
    item = next(
        i for i in _rpc_ok(action="list_attention", open_only=True)["items"] if i["id"] == fid)
    assert "zz-test file excerpt content" in item["body_excerpt"]
    assert "zz-test error text must not leak" not in item["body_excerpt"]

    # Honest fallback: a missing output file yields the error-text excerpt.
    missing_id, _ = incidents.upsert_incident(
        "zz-test-excerpt", "zz-test missing file fallback text",
        output_file="/nonexistent-zz-test/never-written.md")
    missing = next(
        i for i in _rpc_ok(action="list_attention", open_only=True)["items"]
        if i["id"] == missing_id)
    assert "zz-test missing file fallback text" in missing["body_excerpt"]

    # Unreadable "file" (a directory path): same fallback, never an exception.
    dir_id, _ = incidents.upsert_incident(
        "zz-test-excerpt", "zz-test unreadable fallback text", output_file=str(cron_env))
    unreadable = next(
        i for i in _rpc_ok(action="list_attention", open_only=True)["items"]
        if i["id"] == dir_id)
    assert "zz-test unreadable fallback text" in unreadable["body_excerpt"]
