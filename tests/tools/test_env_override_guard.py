"""Tests for the guard hardening (incident t_0e0ffa24): environmental-override hijack
detection with tirith parity (R2 static rule; verdicts verified against the tirith 0.3.3
binary on 2026-09-15), denied-value tracking across executed-script content (R2
value-following), and re-route events (R3 ledger). Token-spliced spellings are DECLARED
NON-COVERAGE and asserted untracked (the card forbids chasing them with patterns)."""

import json
import os
import time
from unittest.mock import patch

import pytest

import tools.approval as approval_module
import tools.guard_events as guard_events
from gateway.session_context import reset_session_vars
from tools.approval import _Unattended, _unattended_deny
from tools.approval_context import reset_current_session_key, set_current_session_key
from tools.approval_detection import (
    ENV_OVERRIDE_HIJACK_DESCRIPTION,
    _env_override_hijack_findings,
    detect_dangerous_command,
    extract_env_override_assignments,
    extract_env_override_assignments_from_file,
    script_files_executed_by_command,
)

SESSION = "test-session"
DENIED_VAL = "/srv/personal/scratch/denied/value/path"


def _sq_ctx() -> _Unattended:
    return _Unattended(
        "single_query", "single_query_mode",
        "single-query mode (-q) runs without a user present to approve it",
        "in single-query mode", "this single-query run is intentionally trusted",
    )


@pytest.fixture(autouse=True)
def _clear_state(monkeypatch):
    """Isolate this module from AMBIENT session state.

    ``get_current_session_key()`` prefers the approval ContextVar over ``HERMES_SESSION_KEY``, so
    pinning only the env var is not isolation: a neighbouring test module that binds the ContextVar
    (and does not restore it) makes the guard record events under ITS session key, and the
    assertions here read an empty store. Bind the intended session on this fixture's context and
    restore the saved token in teardown.
    """
    session_token = set_current_session_key(SESSION)
    monkeypatch.setenv("HERMES_SESSION_KEY", SESSION)
    monkeypatch.delenv("HERMES_SINGLE_QUERY_SESSION", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
    monkeypatch.delenv("HERMES_CRON_SESSION", raising=False)
    monkeypatch.delenv("HERMES_YOLO_MODE", raising=False)
    monkeypatch.delenv("TIRITH_BIN", raising=False)
    monkeypatch.delenv("TIRITH_FAIL_OPEN", raising=False)
    approval_module._denied_env_overrides.clear()
    approval_module._permanent_approved.clear()
    reset_session_vars()
    yield
    approval_module._denied_env_overrides.clear()
    reset_session_vars()
    reset_current_session_key(session_token)


def _seed_denied(var="PYTHONPATH", value=DENIED_VAL):
    approval_module._denied_env_overrides[SESSION] = {(var, value): time.time()}


def _all_findings(command):
    return list(_env_override_hijack_findings(command))


# ---------------------------------------------------------------------------
# R2 static rule: tirith interpreter_hijack_env parity
# ---------------------------------------------------------------------------

class TestEnvOverrideHijackFindings:
    def test_export_word_form_found(self):
        assert _all_findings("export PYTHONPATH=/x") == [(ENV_OVERRIDE_HIJACK_DESCRIPTION, "PYTHONPATH")]

    def test_env_assign_word_form_found(self):
        assert _all_findings("env -u FOO PYTHONPATH=/p python3 -c x") == [
            (ENV_OVERRIDE_HIJACK_DESCRIPTION, "PYTHONPATH")]

    def test_compound_export_segment_found(self):
        assert _all_findings("set -u; export PYTHONPATH=/p && python3 -c x") == [
            (ENV_OVERRIDE_HIJACK_DESCRIPTION, "PYTHONPATH")]

    def test_spaced_form_not_flagged_tirith_parity(self):
        # tirith 0.3.3 allows this (verified against the binary): the spaced form is not a
        # POSIX assignment, so flagging it is a false positive.
        assert _all_findings("export PYTHONPATH = /p") == []

    def test_prefix_assignment_not_flagged_tirith_parity(self):
        # tirith 0.3.3 allows bare prefix assignments; the fallback mirrors that exactly.
        assert _all_findings("PYTHONPATH=/x python3 -c foo") == []

    def test_assignment_run_before_env_found_tirith_parity(self):
        # tirith 0.3.3 blocks this spelling; the fallback must too.
        assert _all_findings("FOO=1 env PYTHONPATH=/x cmd") == [
            (ENV_OVERRIDE_HIJACK_DESCRIPTION, "PYTHONPATH")]

    def test_mixed_export_assignments_found_tirith_parity(self):
        assert _all_findings("export FOO=1 PYTHONPATH=/x") == [
            (ENV_OVERRIDE_HIJACK_DESCRIPTION, "PYTHONPATH")]

    def test_prefix_after_assignment_run_not_flagged(self):
        assert _all_findings("FOO=1 PYTHONPATH=/x cmd") == []

    def test_other_variables_not_flagged(self):
        for cmd in ("export PATH=/x", "export PYTHONHOME=/y", "export LD_PRELOAD=/z",
                    "env -u X PATH=/p cmd"):
            assert _all_findings(cmd) == [], cmd

    def test_quoted_data_not_flagged(self):
        assert _all_findings('echo "PYTHONPATH=/x"') == []
        assert _all_findings("echo PYTHONPATH=/x") == []

    def test_detect_dangerous_command_integration(self):
        assert detect_dangerous_command("export PYTHONPATH=/x") == (
            True, ENV_OVERRIDE_HIJACK_DESCRIPTION, ENV_OVERRIDE_HIJACK_DESCRIPTION)
        # the -c form trips the pre-existing script-exec-flag rule, so use a clean prefix example
        assert detect_dangerous_command("PYTHONPATH=/x python3 script.py") == (False, None, None)


# ---------------------------------------------------------------------------
# Value extractors (any plain carrier form)
# ---------------------------------------------------------------------------

class TestEnvOverrideExtractors:
    def test_prefix_form_extracted(self):
        assert extract_env_override_assignments("PYTHONPATH=/a python3 -c x") == [("PYTHONPATH", "/a")]

    def test_multi_prefix_skips_untracked(self):
        assert extract_env_override_assignments("FOO=1 PYTHONPATH=/a python3 -c x") == [("PYTHONPATH", "/a")]

    def test_export_quoted_value_extracted(self):
        assert extract_env_override_assignments('export PYTHONPATH="/a b"') == [("PYTHONPATH", "/a b")]

    def test_env_word_extracted(self):
        assert extract_env_override_assignments("env -u X PYTHONPATH=/a cmd") == [("PYTHONPATH", "/a")]

    def test_compound_segments_extracted(self):
        assert extract_env_override_assignments("set -u; export PYTHONPATH=/a; echo hi") == [
            ("PYTHONPATH", "/a")]

    def test_spaced_form_not_extracted_tirith_parity(self):
        # Not an assignment in POSIX (tirith allows it): extracting it would track a phantom.
        assert extract_env_override_assignments("export PYTHONPATH = /a") == []

    def test_assignment_run_before_env_extracted(self):
        assert extract_env_override_assignments("FOO=1 env PYTHONPATH=/a cmd") == [("PYTHONPATH", "/a")]

    def test_prefix_value_after_other_assignment_extracted(self):
        assert extract_env_override_assignments("FOO=1 PYTHONPATH=/a cmd") == [("PYTHONPATH", "/a")]

    def test_quoted_data_not_extracted(self):
        assert extract_env_override_assignments('echo "PYTHONPATH=/a"') == []


class TestScriptFileScans:
    @pytest.fixture(autouse=True)
    def _script(self, tmp_path):
        self.tmp = tmp_path
        self.script = tmp_path / "run.sh"
        self.script.write_text(
            "#!/usr/bin/env bash\nset -u\nexport PYTHONPATH=%s\necho \"PYTHONPATH=/decoy\"\n" % DENIED_VAL,
            encoding="utf-8")
        return self.script

    def test_bash_absolute_path_found(self):
        assert script_files_executed_by_command(f"bash {self.script}") == [str(self.script)]

    def test_relative_path_resolved_against_cwd(self):
        assert script_files_executed_by_command("bash run.sh", cwd=str(self.tmp)) == [str(self.script)]

    def test_sh_with_options_found(self):
        assert script_files_executed_by_command("sh -eu run.sh", cwd=str(self.tmp)) == [str(self.script)]

    def test_dot_slash_found(self):
        assert script_files_executed_by_command("./run.sh", cwd=str(self.tmp)) == [str(self.script)]

    def test_pipeline_with_redirects_found(self):
        assert script_files_executed_by_command(
            "bash run.sh 2>&1 | tail -12 ; echo done", cwd=str(self.tmp)) == [str(self.script)]

    def test_inline_code_flag_yields_no_file(self):
        assert script_files_executed_by_command("bash -c 'export PYTHONPATH=/x'", cwd=str(self.tmp)) == []

    def test_missing_file_absent(self):
        assert script_files_executed_by_command("bash nope-missing.sh", cwd=str(self.tmp)) == []

    def test_oversized_file_not_scanned(self):
        big = self.tmp / "big.sh"
        big.write_bytes(b"#!/bin/sh\n" + b"#" * (300 * 1024))
        assert script_files_executed_by_command("bash big.sh", cwd=str(self.tmp)) == []

    def test_file_content_extraction(self):
        assert extract_env_override_assignments_from_file(str(self.script)) == [("PYTHONPATH", DENIED_VAL)]

    def test_file_content_skips_decoy_echo_and_comments(self):
        p = self.tmp / "clean.sh"
        p.write_text(
            "# export PYTHONPATH=/commented\necho \"PYTHONPATH=/echod\"\nexport PYTHONPATH=/real\n",
            encoding="utf-8")
        assert extract_env_override_assignments_from_file(str(p)) == [("PYTHONPATH", "/real")]

    def test_file_content_spaced_form_not_extracted(self):
        p = self.tmp / "spaced.sh"
        p.write_text("export PYTHONPATH = /spaced\n", encoding="utf-8")
        assert extract_env_override_assignments_from_file(str(p)) == []


# ---------------------------------------------------------------------------
# R2 denied-value tracking + R3 events
# ---------------------------------------------------------------------------

class TestDeniedValueTracking:
    @pytest.fixture(autouse=True)
    def _cfg_deny(self, monkeypatch):
        import hermes_cli.config as config_mod
        monkeypatch.setattr(config_mod, "load_config_readonly", lambda: {"approvals": {}})

    def test_recurrence_found_in_executed_script(self, tmp_path):
        script = tmp_path / "carry.sh"
        script.write_text(f"export PYTHONPATH={DENIED_VAL}\n", encoding="utf-8")
        _seed_denied()
        recurring = approval_module._reappearing_denied_overrides(
            "bash carry.sh", cwd=str(tmp_path))
        assert recurring == [("PYTHONPATH", DENIED_VAL, str(script))]

    def test_recurrence_found_in_command_text(self):
        _seed_denied()
        recurring = approval_module._reappearing_denied_overrides(
            f"env PYTHONPATH={DENIED_VAL} python3 -c x")
        assert recurring == [("PYTHONPATH", DENIED_VAL, "command")]

    def test_ttl_expiry_clears_denial(self):
        _seed_denied()
        approval_module._denied_env_overrides[SESSION][("PYTHONPATH", DENIED_VAL)] = time.time() - 4000
        assert approval_module._recently_denied_env_overrides(SESSION) == []

    def test_unattended_carryover_blocked(self, tmp_path):
        script = tmp_path / "carry.sh"
        script.write_text(f"export PYTHONPATH={DENIED_VAL}\n", encoding="utf-8")
        _seed_denied()
        result = _unattended_deny(f"bash {script}", _sq_ctx())
        assert result is not None and result["approved"] is False
        assert "denied earlier in this session" in result["message"]
        assert DENIED_VAL in result["message"]
        assert str(script) in result["message"]

    def test_no_prior_denial_no_carryover_block(self, tmp_path):
        script = tmp_path / "carry.sh"
        script.write_text(f"export PYTHONPATH={DENIED_VAL}\n", encoding="utf-8")
        assert _unattended_deny(f"bash {script}", _sq_ctx()) is None

    def test_token_spliced_spelling_declared_non_coverage(self, tmp_path):
        script = tmp_path / "spliced.sh"
        script.write_text("export PYTH\"+\"PATH=/x\n", encoding="utf-8")
        assert extract_env_override_assignments_from_file(str(script)) == []
        _seed_denied(value="/x")
        recurring = approval_module._reappearing_denied_overrides(
            "bash spliced.sh", cwd=str(tmp_path))
        assert recurring == []


class TestGuardEventLedger:
    def test_event_written_to_ledger(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        approval_module._record_guard_event(
            "denied", SESSION, var="PYTHONPATH", value="/v", outcome="blocked", command="cmd")
        ledger = tmp_path / "security" / "guard_events.jsonl"
        assert ledger.exists()
        rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
        row = rows[0]
        assert row["kind"] == "denied" and row["session"] == SESSION
        assert row["var"] == "PYTHONPATH"
        # D2 (David, 2026-09-15): the value and the command are identified by digest + length only.
        assert row["value_digest"] == guard_events._digest("/v") and row["value_len"] == 2
        assert row["command_digest"] == guard_events._digest("cmd") and row["command_len"] == 3
        assert "value" not in row and "command" not in row
        assert row["outcome"] == "blocked"

    def test_carryover_event_on_admitted_fast_path(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        script = tmp_path / "admit.sh"
        script.write_text(f"export PYTHONPATH={DENIED_VAL}\n", encoding="utf-8")
        _seed_denied()
        verdict = approval_module._approved_with_carryover_watch("bash admit.sh", str(tmp_path))
        assert verdict.get("approved") is True
        ledger = tmp_path / "security" / "guard_events.jsonl"
        rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
        carry = next(r for r in rows if r["kind"] == "carryover")
        assert carry["outcome"] == "admitted"
        assert carry["source"] == str(script)
        assert carry["value_digest"] == guard_events._digest(DENIED_VAL)
        assert carry["value_len"] == len(DENIED_VAL)

    def test_remember_denied_persists_and_emits(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        approval_module._remember_denied_env_override(f"env PYTHONPATH={DENIED_VAL} python3 -c x")
        assert ("PYTHONPATH", DENIED_VAL) in approval_module._recently_denied_env_overrides(SESSION)
        ledger = tmp_path / "security" / "guard_events.jsonl"
        assert ledger.exists()
        rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
        assert any(r["kind"] == "denied"
                   and r["value_digest"] == guard_events._digest(DENIED_VAL) for r in rows)


class TestFullGateIntegration:
    """check_all_command_guards end-to-end under single-query deny, scanner allow-mocked."""

    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch):
        import hermes_cli.config as config_mod
        import tools.tirith_security as tirith_mod
        monkeypatch.setattr(config_mod, "load_config_readonly", lambda: {"approvals": {}})
        monkeypatch.setattr(tirith_mod, "check_command_security",
                            lambda command: {"action": "allow", "findings": [], "summary": ""})
        monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")

    def test_static_pattern_blocks_export_form(self):
        result = approval_module.check_all_command_guards("export PYTHONPATH=/x", "local")
        assert result["approved"] is False
        assert ENV_OVERRIDE_HIJACK_DESCRIPTION in result["message"]

    def test_prefix_form_passes_without_prior_denial_tirith_parity(self):
        result = approval_module.check_all_command_guards("PYTHONPATH=/x python3 script.py", "local")
        assert result["approved"] is True

    def test_script_carrying_denied_value_blocked(self, tmp_path):
        script = tmp_path / "run_task.sh"
        script.write_text(f"export PYTHONPATH={DENIED_VAL}\n", encoding="utf-8")
        # deny the inline form first (exactly the incident sequence), then execute the script
        first = approval_module.check_all_command_guards(
            f"env PYTHONPATH={DENIED_VAL} python3 -m somepkg --flag", "local")
        assert first["approved"] is False
        second = approval_module.check_all_command_guards(
            "bash run_task.sh", "local", command_cwd=str(tmp_path))
        assert second["approved"] is False
        assert "denied earlier in this session" in second["message"]
        assert DENIED_VAL in second["message"] and str(script) in second["message"]


# ---------------------------------------------------------------------------
# F5 — parser precision AND coverage in the script heuristics (gate report 5400)
# ---------------------------------------------------------------------------

class TestScriptHeuristicPrecision:
    """The heuristic must not invent carriers (non-executing syntax checks, literal heredoc data)
    and must not miss ordinary shell forms (`;` separators, compound `set -eu; export …`)."""

    def test_bash_n_syntax_only_is_not_execution(self, tmp_path):
        script = tmp_path / "run.sh"
        script.write_text(f"export PYTHONPATH={DENIED_VAL}\n", encoding="utf-8")
        # `bash -n` PARSES only; real tirith 0.3.3 allows it (verified against the binary).
        assert script_files_executed_by_command(f"bash -n {script}") == []
        assert script_files_executed_by_command(f"sh --noexec {script}") == []
        # …while the same file really executed is still located.
        assert script_files_executed_by_command(f"bash {script}") == [str(script)]

    def test_sh_e_with_file_is_still_located(self, tmp_path):
        """`-e` is errexit, not inline code: `sh -e script.sh` runs the file."""
        script = tmp_path / "run.sh"
        script.write_text("echo hi\n", encoding="utf-8")
        assert script_files_executed_by_command(f"sh -e {script}") == [str(script)]

    def test_underscore_n_bundle_is_still_located(self, tmp_path):
        """`--norc` is a long option that contains an `n` but does NOT disable execution."""
        script = tmp_path / "run.sh"
        script.write_text("echo hi\n", encoding="utf-8")
        assert script_files_executed_by_command(f"bash --norc {script}") == [str(script)]

    def test_heredoc_body_is_literal_data_not_assignments(self, tmp_path):
        p = tmp_path / "doc.sh"
        p.write_text("cat <<'EOF'\nexport PYTHONPATH=/documented\nEOF\necho done\n", encoding="utf-8")
        assert extract_env_override_assignments_from_file(str(p)) == []

    def test_piped_heredoc_body_is_literal_data(self, tmp_path):
        p = tmp_path / "piped.sh"
        p.write_text("cat <<EOF | tail -2\nexport PYTHONPATH=/piped\nEOF\n", encoding="utf-8")
        assert extract_env_override_assignments_from_file(str(p)) == []

    def test_heredoc_data_does_not_trip_carryover(self, tmp_path):
        p = tmp_path / "doc.sh"
        p.write_text(f"cat <<'EOF'\nexport PYTHONPATH={DENIED_VAL}\nEOF\n", encoding="utf-8")
        _seed_denied()
        assert approval_module._reappearing_denied_overrides(
            "bash doc.sh", cwd=str(tmp_path)) == []

    def test_file_semicolon_does_not_pollute_the_value(self, tmp_path):
        p = tmp_path / "semi.sh"
        p.write_text("export PYTHONPATH=/real;\n", encoding="utf-8")
        assert extract_env_override_assignments_from_file(str(p)) == [("PYTHONPATH", "/real")]

    def test_file_compound_segment_assignment_found(self, tmp_path):
        p = tmp_path / "compound.sh"
        p.write_text("set -eu; export PYTHONPATH=/real\necho hi\n", encoding="utf-8")
        assert extract_env_override_assignments_from_file(str(p)) == [("PYTHONPATH", "/real")]

    def test_file_executed_value_is_detected_and_blocked(self, tmp_path):
        """The positive control: a plain semicolon form carrying a denied value IS caught."""
        p = tmp_path / "carry.sh"
        p.write_text(f"set -eu; export PYTHONPATH={DENIED_VAL}\n", encoding="utf-8")
        _seed_denied()
        recurring = approval_module._reappearing_denied_overrides("bash carry.sh", cwd=str(tmp_path))
        assert recurring == [("PYTHONPATH", DENIED_VAL, str(p))]

    def test_documented_variables_are_not_read_as_executed(self, tmp_path):
        """A doc line that MENTIONS the construct inside a quoted string is not an assignment."""
        p = tmp_path / "notes.sh"
        p.write_text('echo "PYTHONPATH=/decoy"\necho PYTHONPATH=/decoy\n', encoding="utf-8")
        assert extract_env_override_assignments_from_file(str(p)) == []


# ---------------------------------------------------------------------------
# F6 — the guard must inspect the file the command actually executes
# ---------------------------------------------------------------------------

class TestEffectiveCommandCwd:
    """Gate report 5400 F6: only the SESSION cwd reached the guard while the tool's ``workdir`` is
    per-command, so ``bash run.sh`` could scan A/run.sh and execute B/run.sh. The effective cwd must
    be resolved ONCE and given to both the guard and the execution."""

    @staticmethod
    def _patch_entry_point(monkeypatch, plan_cwd, captured):
        import tools.terminal_tool as tt
        plan = tt._ExecPlan(
            config={}, env_type="local", effective_task_id="t", image="",
            cwd=plan_cwd, host_cwd=None, effective_timeout=10,
        )
        monkeypatch.setattr(tt, "_plan_execution", lambda *a, **k: plan)
        monkeypatch.setattr(tt, "_acquire_env", lambda *a, **k: object())
        monkeypatch.setattr(tt, "_pre_exec_block", lambda *a, **k: None)

        def _guard(command, env_type, has_host_access=False, command_cwd=None):
            captured["guard_cwd"] = command_cwd
            return {"approved": True}

        monkeypatch.setattr(tt, "_check_all_guards", _guard)

        def _foreground(*a, **k):
            captured["exec_cwd"] = k.get("command_cwd")
            return "{}"

        monkeypatch.setattr(tt, "_run_foreground", _foreground)
        return tt

    def test_per_call_workdir_is_the_file_the_guard_scans(self, monkeypatch, tmp_path):
        captured = {}
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir(), b.mkdir()
        tt = self._patch_entry_point(monkeypatch, str(a), captured)
        tt.clear_session_cwd(SESSION)
        tt.record_session_cwd(SESSION, str(a))
        tt.terminal_tool("bash run.sh", workdir=str(b))
        assert captured["guard_cwd"] == str(b)
        assert captured["exec_cwd"] == captured["guard_cwd"] == str(b)

    def test_session_cwd_is_used_when_no_workdir(self, monkeypatch, tmp_path):
        captured = {}
        default, recorded = tmp_path / "default", tmp_path / "recorded"
        default.mkdir(), recorded.mkdir()
        tt = self._patch_entry_point(monkeypatch, str(default), captured)
        tt.clear_session_cwd(SESSION)
        tt.record_session_cwd(SESSION, str(recorded))
        tt.terminal_tool("bash run.sh")
        assert captured["guard_cwd"] == str(recorded) == captured["exec_cwd"]

    def test_no_session_record_falls_back_to_the_planned_cwd(self, monkeypatch, tmp_path):
        captured = {}
        config_cwd = tmp_path / "config-cwd"
        config_cwd.mkdir()
        tt = self._patch_entry_point(monkeypatch, str(config_cwd), captured)
        tt.clear_session_cwd(SESSION)
        tt.terminal_tool("bash run.sh")
        assert captured["guard_cwd"] == str(config_cwd) == captured["exec_cwd"]

    def test_remote_backend_does_not_read_a_same_named_local_file(self, tmp_path, monkeypatch):
        """A remote backend executes ITS `run.sh`; reading the local file of that name would block
        (or miss) on an unrelated carrier."""
        script = tmp_path / "carry.sh"
        script.write_text(f"export PYTHONPATH={DENIED_VAL}\n", encoding="utf-8")
        _seed_denied()
        monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")
        remote = approval_module.check_all_command_guards(
            "bash carry.sh", "ssh", command_cwd=str(tmp_path))
        assert remote.get("approved") is True          # local file NOT inspected for a remote run
        local = approval_module.check_all_command_guards(
            "bash carry.sh", "local", command_cwd=str(tmp_path))
        assert local["approved"] is False              # the local backend still inspects it


# ---------------------------------------------------------------------------
# F3/F4 — a degraded scanner is never auto-approved, always attributed
# ---------------------------------------------------------------------------

def _degradation_block(reason="spawn_failed", action="block"):
    return {"action": action, "findings": [], "summary": "tirith unavailable",
            "degradation": {"reason": reason, "attempted_path": "tirith", "resolved_path": "",
                            "breaker_open": False,
                            "acknowledgement_source": "config:security.tirith_fail_open",
                            "outcome": "blocked" if action == "block" else "allowed"}}


class TestDegradedScanConsent:
    """Gate report 5400 F3: with ``approvals.mode: smart`` an unavailable scanner's block became an
    ordinary approval warning and the AUXILIARY POLICY could approve it with no human at all."""

    @pytest.fixture(autouse=True)
    def _smart_mode(self, monkeypatch):
        import hermes_cli.config as config_mod
        monkeypatch.setattr(config_mod, "load_config_readonly",
                            lambda: {"approvals": {"mode": "smart"}})
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")
        monkeypatch.delenv("HERMES_SINGLE_QUERY_SESSION", raising=False)

    def test_guardian_cannot_approve_a_degraded_scan(self, monkeypatch, tmp_path):
        import tools.tirith_security as tirith_mod
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setattr(tirith_mod, "check_command_security", lambda command: _degradation_block())
        calls = []
        monkeypatch.setattr(approval_module, "_smart_verdict",
                            lambda *a, **k: calls.append(a) or "approve")
        asked = []

        def cb(command, description, **kw):
            asked.append(description)
            return "once"          # the human approved the degraded command for this one run

        result = approval_module.check_all_command_guards("echo hi", "local", approval_callback=cb)
        assert calls == []                                  # guardian LLM never consulted
        assert result["approved"] is True                   # the HUMAN's answer carried
        assert not result.get("smart_approved")
        assert asked and "DEGRADED" in asked[0]             # and the human was told why
        assert result["degradation"]["reason"] == "spawn_failed"

    def test_guardian_approval_never_reaches_a_degraded_scan(self, monkeypatch, tmp_path):
        """The same control flow with NO callback available: the auxiliary APPROVE cannot stand in."""
        import tools.tirith_security as tirith_mod
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setattr(tirith_mod, "check_command_security", lambda command: _degradation_block())
        monkeypatch.setattr(approval_module, "_smart_verdict", lambda *a, **k: "approve")
        result = approval_module.check_all_command_guards("echo hi", "local")
        assert result.get("approved") is not True
        assert "DEGRADED" in (result.get("message") or result.get("description") or "")

    def test_degraded_decision_is_never_persisted(self, monkeypatch, tmp_path):
        """Neither [s]ession nor [a]lways may be recorded from a degraded prompt: the only sanctioned
        acknowledgement is the operator's recorded opt-in."""
        import tools.tirith_security as tirith_mod
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setattr(tirith_mod, "check_command_security", lambda command: _degradation_block())
        monkeypatch.setattr(approval_module, "_smart_verdict", lambda *a, **k: "approve")
        seen_kwargs = {}

        def cb(command, description, **kw):
            seen_kwargs.update(kw)
            return "session"

        first = approval_module.check_all_command_guards("echo hi", "local", approval_callback=cb)
        assert first["approved"] is True
        assert seen_kwargs.get("allow_session") is False
        assert seen_kwargs.get("allow_permanent") is False
        assert approval_module.is_approved(SESSION, "tirith:degradation:spawn_failed") is False
        assert approval_module.is_approved(SESSION, "tirith:degradation:spawn_failed") is False

    def test_acknowledged_degradation_is_allowed_but_reported(self, monkeypatch, tmp_path):
        """The fail-open (acknowledged) path stays allowed — and is still loud at the boundary."""
        import tools.tirith_security as tirith_mod
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setattr(tirith_mod, "check_command_security",
                            lambda command: _degradation_block(action="allow"))
        monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")
        result = approval_module.check_all_command_guards("echo hi", "local")
        assert result["approved"] is True
        assert result["degradation"]["outcome"] == "allowed"

    def test_import_error_degradation_is_marked_and_loud(self, monkeypatch, tmp_path):
        import sys
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")
        monkeypatch.delenv("TIRITH_FAIL_OPEN", raising=False)
        with patch.dict(sys.modules, {"tools.tirith_security": None}):
            result = approval_module.check_all_command_guards("echo hi", "local")
        assert result["approved"] is False
        assert result["degradation"]["reason"] == "import_error"
        rows = [json.loads(line) for line in
                (tmp_path / "security" / "guard_events.jsonl").read_text(encoding="utf-8").splitlines()]
        assert [r["kind"] for r in rows] == ["degradation"]
        assert rows[0]["reason"] == "import_error"

    def test_unattended_execute_code_path_still_fails_closed_on_import_error(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "1")
        monkeypatch.delenv("TIRITH_FAIL_OPEN", raising=False)
        import sys
        with patch.dict(sys.modules, {"tools.tirith_security": None}):
            result = approval_module.check_all_command_guards("echo hi", "local")
        assert result["approved"] is False
        assert "scan" in result["message"].lower()


# ---------------------------------------------------------------------------
# F8 — approved replay and rejected scripted carryover are audited
# ---------------------------------------------------------------------------

class TestCarryoverAuditCompleteness:
    def test_owner_confirmed_replay_audits_the_carryover(self, tmp_path, monkeypatch):
        """terminal_tool returned for internal ``force=True`` BEFORE the carryover watch, so an
        approved/replayed gateway request could execute a carried value with no admitted-carryover
        event."""
        import tools.terminal_tool as tt
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        script = tmp_path / "carry.sh"
        script.write_text(f"export PYTHONPATH={DENIED_VAL}\n", encoding="utf-8")
        _seed_denied()
        verdict = tt._run_approval_guards("bash carry.sh", "local", {}, force=True,
                                          command_cwd=str(tmp_path))
        assert verdict.approved_run is True          # the owner's approval is preserved
        assert verdict.note and "denied earlier in this session" in verdict.note
        rows = [json.loads(line) for line in
                (tmp_path / "security" / "guard_events.jsonl").read_text(encoding="utf-8").splitlines()]
        carry = [r for r in rows if r["kind"] == "carryover"]
        assert len(carry) == 1
        assert carry[0]["outcome"] == "admitted"
        assert carry[0]["phase"] == "replay"         # distinct from the first-pass approval phase
        assert carry[0]["source"] == str(script)

    def test_rejected_scripted_carryover_records_a_denied_row(self, tmp_path, monkeypatch):
        """Interactive rejection of a carried SCRIPT recorded nothing: the command is just
        `bash file.sh`, so the extractor saw no override."""
        import hermes_cli.config as config_mod
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setattr(config_mod, "load_config_readonly", lambda: {"approvals": {}})
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")
        monkeypatch.delenv("HERMES_SINGLE_QUERY_SESSION", raising=False)
        script = tmp_path / "carry.sh"
        script.write_text(f"export PYTHONPATH={DENIED_VAL}\n", encoding="utf-8")
        _seed_denied()

        result = approval_module.check_all_command_guards(
            "bash carry.sh", "local", approval_callback=lambda c, d, **kw: "deny",
            command_cwd=str(tmp_path))
        assert result["approved"] is False
        rows = [json.loads(line) for line in
                (tmp_path / "security" / "guard_events.jsonl").read_text(encoding="utf-8").splitlines()]
        assert [r["kind"] for r in rows] == ["denied"]
        assert rows[0]["outcome"] == "blocked"
        assert rows[0]["source"] == str(script)
        # D2: the ledger identifies the carried value by digest, never by raw text.
        assert rows[0]["value_digest"] == guard_events._digest(DENIED_VAL)
        assert "value" not in rows[0]


# ---------------------------------------------------------------------------
# D2 (ruled by David 2026-09-15) — the guard ledger stores DIGESTS, not raw text,
# owner-only permissions, and a retention policy that is stated rather than implied.
# ---------------------------------------------------------------------------

class TestLedgerPrivacy:
    """The ledger and the log must carry no raw override value and no raw command text."""

    def test_no_raw_value_or_command_reaches_the_ledger_or_the_log(self, tmp_path, monkeypatch, caplog):
        secret = "s3cr3t-override-value-9f2a"
        command = f"env PYTHONPATH={secret} python3 -c x"
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        script = tmp_path / "carry.sh"
        script.write_text(f"export PYTHONPATH={secret}\n", encoding="utf-8")
        with caplog.at_level("WARNING", logger="tools.guard_events"):
            approval_module._remember_denied_env_override(command)   # a DENIAL
            _seed_denied(value=secret)
            approval_module._approved_with_carryover_watch(f"bash {script}", str(tmp_path))  # a CARRYOVER

        ledger = (tmp_path / "security" / "guard_events.jsonl").read_text(encoding="utf-8")
        logged = "\n".join(r.getMessage() for r in caplog.records)
        assert caplog.records, "the ledger writer must have logged its rows (non-vacuous control)"
        for blob, where in ((ledger, "ledger"), (logged, "log")):
            assert secret not in blob, f"raw value leaked into the {where}"
            assert command not in blob, f"raw command leaked into the {where}"

        rows = [json.loads(line) for line in ledger.splitlines()]
        denied = [r for r in rows if r["kind"] == "denied"]
        carry = [r for r in rows if r["kind"] == "carryover"]
        assert denied and carry
        # Correlation still works: the digest is stable and the length is kept.
        assert denied[0]["value_digest"] == guard_events._digest(secret)
        assert denied[0]["value_len"] == len(secret)
        assert denied[0]["command_digest"] == guard_events._digest(command)
        assert denied[0]["command_len"] == len(command)
        assert carry[0]["value_digest"] == guard_events._digest(secret)
        for row in rows:
            assert "value" not in row and "command" not in row

    def test_digest_is_stable_distinguishing_and_non_reversible(self):
        import hashlib
        assert guard_events._digest("abc") == guard_events._digest("abc")      # correlates repeats
        assert guard_events._digest("abc") != guard_events._digest("abd")      # distinguishes values
        assert guard_events._digest("abc") == hashlib.sha256(b"abc").hexdigest()
        assert "abc" not in guard_events._digest("abc")


class TestLedgerPermissions:
    """Owner-only 0700 dir / 0600 file, enforced on the write path."""

    def test_fresh_ledger_and_dir_are_owner_only(self, tmp_path, monkeypatch):
        import stat
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        approval_module._record_guard_event("denied", SESSION, var="V", value="x", outcome="blocked")
        d, f = tmp_path / "security", tmp_path / "security" / "guard_events.jsonl"
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert stat.S_IMODE(f.stat().st_mode) == 0o600

    def test_wider_existing_modes_are_repaired_and_reported(self, tmp_path, monkeypatch, caplog):
        import stat
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        d = tmp_path / "security"
        d.mkdir()
        os.chmod(d, 0o755)
        f = d / "guard_events.jsonl"
        f.write_text("", encoding="utf-8")
        os.chmod(f, 0o664)
        with caplog.at_level("WARNING", logger="tools.guard_events"):
            approval_module._record_guard_event("denied", SESSION, var="V", value="x", outcome="blocked")
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
        assert any("tightening" in r.getMessage() for r in caplog.records), \
            "repairing a wider mode must be reported, never silent"

    def test_owner_only_but_inexact_mode_is_normalised_never_widened(self, tmp_path, monkeypatch):
        import stat
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        d = tmp_path / "security"
        d.mkdir()
        os.chmod(d, 0o700)
        f = d / "guard_events.jsonl"
        f.write_text("", encoding="utf-8")
        os.chmod(f, 0o400)
        approval_module._record_guard_event("denied", SESSION, var="V", value="x", outcome="blocked")
        # Owner-only either way: normalised to the exact mode, and no group/other access appears.
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
        assert stat.S_IMODE(f.stat().st_mode) & 0o077 == 0
        # ... and the row was actually recorded: the write path is never a silent no-op.
        assert [json.loads(line)["kind"] for line in f.read_text(encoding="utf-8").splitlines()] == ["denied"]

    def test_group_readable_mode_is_repaired_and_never_left_mask_dependent(self, tmp_path, monkeypatch):
        """Creation must not depend on umask: the file is owner-only even under a permissive umask."""
        import stat
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        old = os.umask(0o000)
        try:
            approval_module._record_guard_event("denied", SESSION, var="V", value="x", outcome="blocked")
        finally:
            os.umask(old)
        d, f = tmp_path / "security", tmp_path / "security" / "guard_events.jsonl"
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        assert stat.S_IMODE(f.stat().st_mode) == 0o600


class TestLedgerRetention:
    """Size cap + ONE prior generation + a maximum age applied at rotation; the knob is stated."""

    def test_retention_window_reads_config_then_env(self, monkeypatch):
        import hermes_cli.config as config_mod
        monkeypatch.setattr(config_mod, "load_config_readonly",
                            lambda: {"security": {"guard_event_ledger_max_age_days": 7}})
        monkeypatch.delenv(guard_events.LEDGER_MAX_AGE_ENV, raising=False)
        assert guard_events._max_age_seconds() == 7 * 86400
        monkeypatch.setenv(guard_events.LEDGER_MAX_AGE_ENV, "2")
        assert guard_events._max_age_seconds() == 2 * 86400                  # env overrides config
        monkeypatch.setenv(guard_events.LEDGER_MAX_AGE_ENV, "not-a-number")
        assert guard_events._max_age_seconds() == 7 * 86400                  # malformed falls back

    def test_default_window_is_used_when_nothing_is_configured(self, monkeypatch):
        import hermes_cli.config as config_mod
        monkeypatch.setattr(config_mod, "load_config_readonly", lambda: {"security": {}})
        monkeypatch.delenv(guard_events.LEDGER_MAX_AGE_ENV, raising=False)
        assert guard_events._max_age_seconds() == guard_events.LEDGER_MAX_AGE_DAYS * 86400

    def test_rotation_keeps_one_generation_and_drops_a_stale_prev(self, tmp_path, monkeypatch):
        import stat
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv(guard_events.LEDGER_MAX_AGE_ENV, "1")
        d = tmp_path / "security"
        d.mkdir(mode=0o700)
        live, prev = d / "guard_events.jsonl", d / "guard_events.jsonl.prev"
        prev.write_text("STALE-GENERATION\n", encoding="utf-8")
        old = time.time() - 2 * 86400
        os.utime(prev, (old, old))
        oversized = "x" * (guard_events.LEDGER_MAX_BYTES + 1)
        live.write_text(oversized, encoding="utf-8")

        approval_module._record_guard_event("denied", SESSION, var="V", value="x", outcome="blocked")

        assert "STALE-GENERATION" not in prev.read_text(encoding="utf-8")
        assert prev.read_text(encoding="utf-8") == oversized      # one generation, replaced not appended
        assert stat.S_IMODE(prev.stat().st_mode) == 0o600
        assert [json.loads(l)["kind"] for l in live.read_text(encoding="utf-8").splitlines()] == ["denied"]

    def test_a_fresh_prev_is_overwritten_not_appended(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv(guard_events.LEDGER_MAX_AGE_ENV, "365")
        d = tmp_path / "security"
        d.mkdir(mode=0o700)
        live, prev = d / "guard_events.jsonl", d / "guard_events.jsonl.prev"
        prev.write_text("FIRST-ROTATION\n", encoding="utf-8")
        live.write_text("y" * (guard_events.LEDGER_MAX_BYTES + 1), encoding="utf-8")

        approval_module._record_guard_event("denied", SESSION, var="V", value="x", outcome="blocked")

        assert prev.read_text(encoding="utf-8").strip("\n") == "y" * (guard_events.LEDGER_MAX_BYTES + 1)
        assert "FIRST-ROTATION" not in prev.read_text(encoding="utf-8")