"""Tests for the tirith security scanning subprocess wrapper."""

import io
import json
import os
import subprocess
import tarfile
import time
from unittest.mock import MagicMock, patch

import pytest

import tools.tirith_security as _tirith_mod
from tools.tirith_security import check_command_security, ensure_installed


@pytest.fixture(autouse=True)
def _reset_resolved_path(tmp_path, monkeypatch):
    """Pre-set cached path to skip auto-install in scan tests.
    Tests that specifically test ensure_installed / resolve behavior
    reset this to None themselves.

    HERMES_HOME is redirected to a per-test tmp dir: every unavailability branch now appends a
    guard-ledger row, and a unit test must not write into the operator's real
    ``$HERMES_HOME/security/guard_events.jsonl``.
    """
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    _tirith_mod._resolved_path = "tirith"
    _tirith_mod._install_thread = None
    _tirith_mod._install_failure_reason = ""
    _tirith_mod.reset_circuit_breaker()

    yield
    _tirith_mod._resolved_path = None
    _tirith_mod._install_thread = None
    _tirith_mod._install_failure_reason = ""
    _tirith_mod.reset_circuit_breaker()



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_run(returncode=0, stdout="", stderr=""):
    """Build a mock subprocess.CompletedProcess."""
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.returncode = returncode
    cp.stdout = stdout
    cp.stderr = stderr
    return cp


def _json_stdout(findings=None, summary=""):
    return json.dumps({"findings": findings or [], "summary": summary})


# ---------------------------------------------------------------------------
# Exit code → action mapping
# ---------------------------------------------------------------------------

class TestExitCodeMapping:
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_exit_0_allow(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_run.return_value = _mock_run(0, _json_stdout())
        result = check_command_security("echo hello")
        assert result["action"] == "allow"
        assert result["findings"] == []

    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_exit_1_block_with_findings(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        findings = [{"rule_id": "homograph_url", "severity": "high"}]
        mock_run.return_value = _mock_run(1, _json_stdout(findings, "homograph detected"))
        result = check_command_security("curl http://gооgle.com")
        assert result["action"] == "block"
        assert len(result["findings"]) == 1
        assert result["summary"] == "homograph detected"

    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_exit_2_warn_with_findings(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        findings = [{"rule_id": "shortened_url", "severity": "medium"}]
        mock_run.return_value = _mock_run(2, _json_stdout(findings, "shortened URL"))
        result = check_command_security("curl https://bit.ly/abc")
        assert result["action"] == "warn"
        assert len(result["findings"]) == 1
        assert result["summary"] == "shortened URL"


# ---------------------------------------------------------------------------
# JSON parse failure (exit code still wins)
# ---------------------------------------------------------------------------

class TestJsonParseFailure:
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_exit_1_invalid_json_still_blocks(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_run.return_value = _mock_run(1, "NOT JSON")
        result = check_command_security("bad command")
        assert result["action"] == "block"
        assert "details unavailable" in result["summary"]

    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_exit_0_invalid_json_allows(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_run.return_value = _mock_run(0, "NOT JSON")
        result = check_command_security("safe command")
        assert result["action"] == "allow"


# ---------------------------------------------------------------------------
# Operational failures + fail_open
# ---------------------------------------------------------------------------

class TestOSErrorFailOpen:
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_file_not_found_fail_open(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_run.side_effect = FileNotFoundError("No such file: tirith")
        result = check_command_security("echo hi")
        assert result["action"] == "allow"
        assert "unavailable" in result["summary"]

    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_os_error_fail_closed(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        mock_run.side_effect = FileNotFoundError("No such file: tirith")
        result = check_command_security("echo hi")
        assert result["action"] == "block"
        assert "fail-closed" in result["summary"]


class TestSpawnFailureFailClosedDefault:
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_spawn_failure_blocks_when_fail_open_absent(self, mock_cfg, mock_run):
        """The hardened default: a cfg without an explicit fail_open key means fail-CLOSED —
        a missing/broken scanner blocks the command with the acknowledgement hint."""
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5}
        mock_run.side_effect = FileNotFoundError("No such file: tirith")
        result = check_command_security("echo hi")
        assert result["action"] == "block"
        assert "tirith_fail_open" in result["summary"]


class TestCircuitBreakerFailClosed:
    @patch("tools.tirith_security._load_security_config")
    def test_open_breaker_blocks_by_default(self, mock_cfg):
        """A circuit-breakered (repeatedly crashing) scanner used to silently allow every
        command; with the fail-closed default it blocks with the acknowledgement hint."""
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5}
        _tirith_mod._circuit_open = True
        result = check_command_security("echo hi")
        assert result["action"] == "block"
        assert "circuit breaker" in result["summary"]
        assert "tirith_fail_open" in result["summary"]

    @patch("tools.tirith_security._load_security_config")
    def test_open_breaker_allows_when_acknowledged(self, mock_cfg):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        _tirith_mod._circuit_open = True
        result = check_command_security("echo hi")
        assert result["action"] == "allow"
        assert "circuit breaker" in result["summary"]


class TestTimeoutFailOpen:
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_timeout_fail_closed(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="tirith", timeout=5)
        result = check_command_security("slow command")
        assert result["action"] == "block"
        assert "fail-closed" in result["summary"]


class TestUnknownExitCode:
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_unknown_exit_code_fail_closed(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        mock_run.return_value = _mock_run(99, "")
        result = check_command_security("cmd")
        assert result["action"] == "block"
        assert "exit code 99" in result["summary"]


# ---------------------------------------------------------------------------
# Circuit breaker: half-open recovery
# ---------------------------------------------------------------------------

def _open_breaker(age_s):
    """Put the breaker in the open state as if it tripped ``age_s`` seconds ago."""
    _tirith_mod._crash_count = _tirith_mod._CRASH_LIMIT
    _tirith_mod._circuit_open = True
    _tirith_mod._circuit_open_at = time.monotonic() - age_s


class TestCircuitBreakerHalfOpen:
    @pytest.mark.parametrize("returncode, action", [(0, "allow"), (1, "block"), (2, "warn")])
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_completed_probe_after_retry_window_closes_breaker(self, mock_cfg, mock_run, returncode, action):
        """Once the retry window has elapsed, one real scan runs; any verdict (allow/block/warn)
        proves the binary healthy and closes the breaker, so the next command is scanned again."""
        mock_cfg.return_value = _CFG
        _open_breaker(age_s=_tirith_mod._CIRCUIT_RETRY_S + 1)
        mock_run.return_value = _mock_run(returncode, _json_stdout())

        result = check_command_security("echo hi")

        assert result["action"] == action
        assert mock_run.call_count == 1
        assert (_tirith_mod._circuit_open, _tirith_mod._crash_count) == (False, 0)
        # Breaker closed: the following command is scanned rather than short-circuited.
        check_command_security("echo again")
        assert mock_run.call_count == 2

    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_open_breaker_probes_once_per_window_and_failed_probe_rearms(self, mock_cfg, mock_run):
        """Inside the window nothing spawns; after it exactly one probe runs, and a probe that
        fails re-arms the window so the next caller is fail-open without spawning again."""
        mock_cfg.return_value = _CFG
        _open_breaker(age_s=1)
        mock_run.side_effect = OSError("binary gone")

        assert check_command_security("echo hi")["summary"] == "tirith disabled (circuit breaker)"
        assert mock_run.call_count == 0

        _open_breaker(age_s=_tirith_mod._CIRCUIT_RETRY_S + 1)
        assert check_command_security("echo hi")["action"] == "allow"  # probe spawned and failed
        assert mock_run.call_count == 1
        assert _tirith_mod._circuit_open is True
        assert check_command_security("echo hi")["summary"] == "tirith disabled (circuit breaker)"
        assert mock_run.call_count == 1  # re-armed: no second probe inside the fresh window


# ---------------------------------------------------------------------------
# Disabled
# ---------------------------------------------------------------------------

class TestDisabled:
    @patch("tools.tirith_security._load_security_config")
    def test_disabled_returns_allow(self, mock_cfg):
        mock_cfg.return_value = {"tirith_enabled": False, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        result = check_command_security("rm -rf /")
        assert result["action"] == "allow"


# ---------------------------------------------------------------------------
# Findings cap + summary cap
# ---------------------------------------------------------------------------

class TestCaps:
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_findings_and_summary_capped(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        findings = [{"rule_id": f"rule_{i}"} for i in range(100)]
        mock_run.return_value = _mock_run(2, _json_stdout(findings, "x" * 1000))
        result = check_command_security("cmd")
        assert len(result["findings"]) == 50
        assert len(result["summary"]) == 500


# ---------------------------------------------------------------------------
# Programming errors propagate
# ---------------------------------------------------------------------------

class TestProgrammingErrors:
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_attribute_error_propagates(self, mock_cfg, mock_run):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        mock_run.side_effect = AttributeError("unexpected bug")
        with pytest.raises(AttributeError):
            check_command_security("cmd")


# ---------------------------------------------------------------------------
# ensure_installed
# ---------------------------------------------------------------------------

class TestEnsureInstalled:
    @patch("tools.tirith_security._load_security_config")
    def test_disabled_returns_none(self, mock_cfg):
        mock_cfg.return_value = {"tirith_enabled": False, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        _tirith_mod._resolved_path = None
        assert ensure_installed() is None

    @patch("tools.tirith_security.shutil.which", return_value="/usr/local/bin/tirith")
    @patch("tools.tirith_security._load_security_config")
    def test_found_on_path_returns_immediately(self, mock_cfg, mock_which):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        _tirith_mod._resolved_path = None
        with patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True):
            result = ensure_installed()
        assert result == "/usr/local/bin/tirith"
        _tirith_mod._resolved_path = None


# ---------------------------------------------------------------------------
# Unsupported platform (Windows etc.) — silent fast-path everywhere
# ---------------------------------------------------------------------------

class TestUnsupportedPlatform:
    """When _detect_target() returns None (no tirith binary for this OS+arch),
    the entire subsystem must stay silent: no PATH probes, no download thread,
    no disk failure marker, no spawn attempts, no CLI banner. Pattern-matching
    guards still cover the gap; tirith content scanning is just absent."""

    @pytest.mark.parametrize("system, machine, expected", [
        ("Linux", "x86_64", True),
        ("Windows", "AMD64", False),
        ("Linux", "riscv64", False),
    ])
    def test_is_platform_supported(self, system, machine, expected):
        # The patched (system, machine) pairs are table inputs, not a host
        # fake: is_platform_supported() is a pure string mapping that touches
        # no OS facility beneath the check, so there is nothing for a real
        # host to falsify. Two of the rows (Windows/AMD64, Linux/riscv64)
        # could never execute honestly anyway — the second has no CI runner
        # on any lane.
        with patch("tools.tirith_security.platform.system", return_value=system), \
             patch("tools.tirith_security.platform.machine", return_value=machine):
            assert _tirith_mod.is_platform_supported() is expected


    @patch("tools.tirith_security._load_security_config")
    def test_check_command_security_unsupported_allows_when_acknowledged(self, mock_cfg):
        """Windows with the operator's explicit acknowledgement (tirith_fail_open: true):
        the resolver and spawn are still skipped entirely, but the open verdict now carries
        an informative summary. That messaging cannot surface by accident — the default is
        fail-closed, so reaching it requires the recorded acknowledgement."""
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        with patch("tools.tirith_security.is_platform_supported", return_value=False), \
             patch("tools.tirith_security.subprocess.run") as mock_run, \
             patch("tools.tirith_security._resolve_tirith_path") as mock_resolve:
            result = check_command_security("rm -rf /")
            assert result["action"] == "allow"
            assert result["findings"] == []
            assert result["summary"] == "tirith has no build for this platform"
            mock_run.assert_not_called()
            mock_resolve.assert_not_called()

    @patch("tools.tirith_security._load_security_config")
    def test_check_command_security_unsupported_fail_closed_by_default(self, mock_cfg):
        """Windows WITHOUT an acknowledgement: no silent degradation — the command is
        blocked with the acknowledgement hint (tirith_fail_open now defaults to False)."""
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5}  # no fail_open key -> default False
        with patch("tools.tirith_security.is_platform_supported", return_value=False), \
             patch("tools.tirith_security.subprocess.run") as mock_run, \
             patch("tools.tirith_security._resolve_tirith_path") as mock_resolve:
            result = check_command_security("rm -rf /")
            assert result["action"] == "block"
            assert "tirith is not available for this platform" in result["summary"]
            assert "tirith_fail_open" in result["summary"]
            mock_run.assert_not_called()
            mock_resolve.assert_not_called()

    @patch("tools.tirith_security._load_security_config")
    def test_explicit_path_still_honored_on_unsupported_platform(self, mock_cfg):
        """If a user explicitly configured a tirith_path (e.g. they built it
        themselves under WSL), the unsupported-platform short-circuit must
        NOT override that — explicit config wins."""
        mock_cfg.return_value = {"tirith_enabled": True,
                                 "tirith_path": "/opt/custom/tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        _tirith_mod._resolved_path = None
        with patch("tools.tirith_security.is_platform_supported", return_value=False), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True):
            result = _tirith_mod._resolve_tirith_path("/opt/custom/tirith")
            assert result == "/opt/custom/tirith"
            assert _tirith_mod._resolved_path == "/opt/custom/tirith"


# ---------------------------------------------------------------------------
# Failed download caches the miss (Finding #1)
# ---------------------------------------------------------------------------

class TestFailedDownloadCaching:
    @patch("tools.tirith_security._mark_install_failed")
    @patch("tools.tirith_security._is_install_failed_on_disk", return_value=False)
    @patch("tools.tirith_security._install_tirith", return_value=(None, "download_failed"))
    @patch("tools.tirith_security.shutil.which", return_value=None)
    def test_failed_install_cached_no_retry(self, mock_which, mock_install,
                                             mock_disk_check, mock_mark):
        """After a failed download, subsequent resolves must not retry."""
        from tools.tirith_security import _resolve_tirith_path, _INSTALL_FAILED
        _tirith_mod._resolved_path = None

        # First call: tries install, fails
        _resolve_tirith_path("tirith")
        assert mock_install.call_count == 1
        assert _tirith_mod._resolved_path is _INSTALL_FAILED
        mock_mark.assert_called_once_with("download_failed")  # reason persisted

        # Second call: hits the cache, does NOT call _install_tirith again
        _resolve_tirith_path("tirith")
        assert mock_install.call_count == 1  # still 1, not 2

        _tirith_mod._resolved_path = None


# ---------------------------------------------------------------------------
# Explicit path must not auto-download (Finding #2)
# ---------------------------------------------------------------------------

class TestExplicitPathNoAutoDownload:
    @patch("tools.tirith_security._install_tirith")
    @patch("tools.tirith_security.shutil.which", return_value=None)
    def test_tilde_explicit_path_missing_no_download(self, mock_which, mock_install):
        """An explicit ~/path that doesn't exist must NOT trigger download."""
        from tools.tirith_security import _resolve_tirith_path, _INSTALL_FAILED
        _tirith_mod._resolved_path = None

        result = _resolve_tirith_path("~/bin/tirith")
        mock_install.assert_not_called()
        assert _tirith_mod._resolved_path is _INSTALL_FAILED
        assert "~" not in result  # tilde still expanded

        _tirith_mod._resolved_path = None

    @patch("tools.tirith_security._mark_install_failed")
    @patch("tools.tirith_security._is_install_failed_on_disk", return_value=False)
    @patch("tools.tirith_security._install_tirith", return_value=("/auto/tirith", ""))
    @patch("tools.tirith_security.shutil.which", return_value=None)
    def test_default_path_does_auto_download(self, mock_which, mock_install,
                                              mock_disk_check, mock_mark):
        """The default bare 'tirith' SHOULD trigger auto-download."""
        from tools.tirith_security import _resolve_tirith_path
        _tirith_mod._resolved_path = None

        result = _resolve_tirith_path("tirith")
        mock_install.assert_called_once()
        assert result == "/auto/tirith"

        _tirith_mod._resolved_path = None


# ---------------------------------------------------------------------------
# Cosign provenance verification (P1)
# ---------------------------------------------------------------------------

class TestCosignVerification:
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security.shutil.which", return_value="/usr/bin/cosign")
    def test_cosign_identity_pinned_to_release_workflow(self, mock_which, mock_run):
        """Identity regexp must pin to the release workflow, not the whole repo."""
        from tools.tirith_security import _verify_cosign
        mock_run.return_value = _mock_run(0, "Verified OK")
        _verify_cosign("/tmp/checksums.txt", "/tmp/sig", "/tmp/cert")
        args = mock_run.call_args[0][0]
        # Find the value after --certificate-identity-regexp
        idx = args.index("--certificate-identity-regexp")
        identity = args[idx + 1]
        # The identity contains regex-escaped dots
        assert "workflows/release" in identity
        assert "refs/tags/v" in identity


    @patch("tools.tirith_security.tarfile.open")
    @patch("tools.tirith_security._verify_checksum", return_value=True)
    @patch("tools.tirith_security.shutil.which", return_value=None)
    @patch("tools.tirith_security._download_file")
    @patch("tools.tirith_security._detect_target", return_value="aarch64-apple-darwin")
    def test_install_proceeds_without_cosign(self, mock_target, mock_dl,
                                              mock_which, mock_checksum,
                                              mock_tarfile):
        """_install_tirith proceeds with SHA-256 only when cosign is not on PATH."""
        from tools.tirith_security import _install_tirith
        mock_tar = MagicMock()
        mock_tar.__enter__ = MagicMock(return_value=mock_tar)
        mock_tar.__exit__ = MagicMock(return_value=False)
        mock_tar.getmembers.return_value = []
        mock_tarfile.return_value = mock_tar

        path, reason = _install_tirith()
        # Reaches extraction (no binary in mock archive), but got past cosign
        assert path is None
        assert reason == "binary_not_in_archive"
        assert mock_checksum.called  # SHA-256 verification ran


class TestInstallArchiveMemberValidation:
    def _write_archive(self, tmp_path, member: tarfile.TarInfo, data: bytes | None = None):
        archive = tmp_path / "tirith-aarch64-apple-darwin.tar.gz"
        checksums = tmp_path / "checksums.txt"
        with tarfile.open(archive, "w:gz") as tar:
            if data is None:
                tar.addfile(member)
            else:
                tar.addfile(member, io.BytesIO(data))
        checksums.write_text(
            "ignored  tirith-aarch64-apple-darwin.tar.gz\n",
            encoding="utf-8",
        )
        return archive, checksums

    def _download_side_effect(self, archive, checksums):
        def _download(url, dest, timeout=10):
            del timeout
            if url.endswith(".tar.gz"):
                with open(archive, "rb") as src, open(dest, "wb") as dst:
                    dst.write(src.read())
                return
            if url.endswith("checksums.txt"):
                with open(checksums, "rb") as src, open(dest, "wb") as dst:
                    dst.write(src.read())
                return
            raise AssertionError(f"unexpected download URL: {url}")

        return _download

    @patch("tools.tirith_security._verify_checksum", return_value=True)
    @patch("tools.tirith_security.shutil.which", return_value=None)
    @patch("tools.tirith_security._detect_target", return_value="aarch64-apple-darwin")
    def test_install_extracts_regular_tirith_member(self, mock_target, mock_which,
                                                    mock_checksum, tmp_path, monkeypatch):
        """A valid regular-file tirith member is installed as a plain file."""
        del mock_target, mock_which, mock_checksum
        from tools.tirith_security import _install_tirith

        payload = b"#!/bin/sh\nexit 0\n"
        member = tarfile.TarInfo("bin/tirith")
        member.mode = 0o755
        member.size = len(payload)
        archive, checksums = self._write_archive(tmp_path, member, payload)

        hermes_home = tmp_path / "hermes-home"
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        with patch("tools.tirith_security._download_file",
                   side_effect=self._download_side_effect(archive, checksums)):
            path, reason = _install_tirith(log_failures=False)

        assert reason == ""
        assert path == str(hermes_home / "bin" / "tirith")
        assert os.path.isfile(path)
        assert not os.path.islink(path)
        with open(path, "rb") as f:
            assert f.read() == payload

    @patch("tools.tirith_security._verify_checksum", return_value=True)
    @patch("tools.tirith_security.shutil.which", return_value=None)
    @patch("tools.tirith_security._detect_target", return_value="aarch64-apple-darwin")
    def test_install_rejects_non_regular_tirith_member(self, mock_target, mock_which,
                                                       mock_checksum, tmp_path, monkeypatch):
        """Symlink or hardlink tar members must not be installed as tirith."""
        del mock_target, mock_which, mock_checksum
        from tools.tirith_security import _install_tirith

        member = tarfile.TarInfo("bin/tirith")
        member.type = tarfile.SYMTYPE
        member.linkname = "/bin/sh"
        archive, checksums = self._write_archive(tmp_path, member)

        hermes_home = tmp_path / "hermes-home"
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        with patch("tools.tirith_security._download_file",
                   side_effect=self._download_side_effect(archive, checksums)):
            path, reason = _install_tirith(log_failures=False)

        assert path is None
        assert reason == "binary_not_regular_file"
        assert not os.path.lexists(hermes_home / "bin" / "tirith")


# ---------------------------------------------------------------------------
# Background install / non-blocking startup (P2)
# ---------------------------------------------------------------------------

class TestBackgroundInstall:
    def test_ensure_installed_non_blocking(self):
        """ensure_installed must return immediately when download needed."""
        _tirith_mod._resolved_path = None

        with patch("tools.tirith_security._load_security_config",
                   return_value={"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}), \
             patch("tools.tirith_security.shutil.which", return_value=None), \
             patch("tools.tirith_security._hermes_bin_dir", return_value="/nonexistent"), \
             patch("tools.tirith_security._is_install_failed_on_disk", return_value=False), \
             patch("tools.tirith_security.threading.Thread") as MockThread:
            mock_thread = MagicMock()
            mock_thread.is_alive.return_value = False
            MockThread.return_value = mock_thread

            result = ensure_installed()
            assert result is None  # not available yet
            MockThread.assert_called_once()
            mock_thread.start.assert_called_once()

        _tirith_mod._resolved_path = None

    def test_resolve_returns_default_when_thread_alive(self):
        """_resolve_tirith_path returns default while background thread runs."""
        from tools.tirith_security import _resolve_tirith_path
        _tirith_mod._resolved_path = None
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        _tirith_mod._install_thread = mock_thread

        with patch("tools.tirith_security.shutil.which", return_value=None), \
             patch("tools.tirith_security._hermes_bin_dir", return_value="/nonexistent"):
            result = _resolve_tirith_path("tirith")
            assert result == "tirith"  # returns configured default, doesn't block

        _tirith_mod._install_thread = None
        _tirith_mod._resolved_path = None


# ---------------------------------------------------------------------------
# Disk failure marker persistence (P2)
# ---------------------------------------------------------------------------

class TestDiskFailureMarker:
    def test_expired_marker_ignored(self):
        """Marker older than TTL should be ignored."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        marker = os.path.join(tmpdir, ".tirith-install-failed")
        with patch("tools.tirith_security._failure_marker_path", return_value=marker):
            from tools.tirith_security import _mark_install_failed, _is_install_failed_on_disk
            assert not _is_install_failed_on_disk()
            _mark_install_failed("download_failed")
            assert _is_install_failed_on_disk()
            # Backdate the file past 24h TTL
            old_time = time.time() - 90000  # 25 hours ago
            os.utime(marker, (old_time, old_time))
            assert not _is_install_failed_on_disk()


    def test_in_memory_cosign_exec_failed_not_retried(self):
        """In-memory _INSTALL_FAILED with cosign_exec_failed is NOT retried."""
        from tools.tirith_security import _resolve_tirith_path, _INSTALL_FAILED
        _tirith_mod._resolved_path = _INSTALL_FAILED
        _tirith_mod._install_failure_reason = "cosign_exec_failed"

        with patch("tools.tirith_security.shutil.which", return_value=None), \
             patch("tools.tirith_security._hermes_bin_dir", return_value="/nonexistent"), \
             patch("tools.tirith_security._install_tirith") as mock_install:
            result = _resolve_tirith_path("tirith")
            assert result == "tirith"  # fallback
            mock_install.assert_not_called()

        _tirith_mod._resolved_path = None


# ---------------------------------------------------------------------------
# HERMES_HOME isolation
# ---------------------------------------------------------------------------

class TestHermesHomeIsolation:
    def test_hermes_bin_dir_respects_hermes_home(self):
        """_hermes_bin_dir must use HERMES_HOME, not hardcoded ~/.hermes."""
        from tools.tirith_security import _hermes_bin_dir
        import tempfile
        tmpdir = tempfile.mkdtemp()
        with patch.dict(os.environ, {"HERMES_HOME": tmpdir}):
            result = _hermes_bin_dir()
        assert result == os.path.join(tmpdir, "bin")
        assert os.path.isdir(result)


# ---------------------------------------------------------------------------
# Warn-once dedupe (issue: tirith spawn failed spamming on Windows)
# ---------------------------------------------------------------------------

class TestSpawnWarningDedup:
    """When tirith isn't installed yet (background install in flight, or
    install marked failed), every terminal command spammed an identical
    ``tirith spawn failed: [WinError 2]`` warning to ``errors.log``. The
    dedupe set in ``_warn_once`` collapses repeats by ``(exc class, errno)``
    while still surfacing the first occurrence so users see the failure.
    """

    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_repeated_spawn_failure_logs_once(self, mock_cfg, mock_run, caplog):
        mock_cfg.return_value = {
            "tirith_enabled": True, "tirith_path": "tirith",
            "tirith_timeout": 5, "tirith_fail_open": True,
        }
        mock_run.side_effect = FileNotFoundError("[WinError 2]")
        # Fresh dedupe state — clear any keys left by other tests.
        _tirith_mod._warned_messages.clear()

        with caplog.at_level("WARNING", logger="tools.tirith_security"):
            for i in range(15):
                result = check_command_security("echo hi")
                # Behavior must remain the same on every call —
                # fail-open allow, with the exception captured in summary.
                assert result["action"] == "allow"
                if i < _tirith_mod._CRASH_LIMIT:
                    # Before circuit breaker opens, summary has the exception
                    assert "unavailable" in result["summary"]
                else:
                    # After circuit breaker opens, summary is generic
                    assert "circuit breaker" in result["summary"]

        spawn_warnings = [
            rec for rec in caplog.records
            if "tirith spawn failed" in rec.message
        ]
        assert len(spawn_warnings) == 1, (
            f"expected exactly 1 spawn-failed warning across 15 commands, "
            f"got {len(spawn_warnings)}: {[r.message for r in spawn_warnings]}"
        )


# ---------------------------------------------------------------------------
# .app TLD suppression (issue #24461)
# ---------------------------------------------------------------------------

_CFG = {"tirith_enabled": True, "tirith_path": "tirith",
        "tirith_timeout": 5, "tirith_fail_open": True}


class TestAppTldSuppression:
    """warn verdicts whose only finding is lookalike_tld/.app are downgraded to allow."""

    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_app_only_warn_downgraded_to_allow(self, mock_cfg, mock_run):
        mock_cfg.return_value = _CFG
        findings = [{"rule_id": "lookalike_tld", "value": ".app",
                     "message": "Domain uses '.app' TLD which can be confused with file extensions"}]
        mock_run.return_value = _mock_run(2, _json_stdout(findings, ".app TLD warning"))
        result = check_command_security("curl https://example.app")
        assert result["action"] == "allow"
        assert result["findings"] == []
        assert result["summary"] == ""

    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_mixed_findings_preserve_warn(self, mock_cfg, mock_run):
        """If .app finding is accompanied by another finding, warn is preserved."""
        mock_cfg.return_value = _CFG
        findings = [
            {"rule_id": "lookalike_tld", "value": ".app"},
            {"rule_id": "shortened_url", "severity": "medium"},
        ]
        mock_run.return_value = _mock_run(2, _json_stdout(findings, "mixed"))
        result = check_command_security("curl https://bit.ly/test.app")
        assert result["action"] == "warn"
        assert len(result["findings"]) == 2

    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_block_verdict_never_suppressed(self, mock_cfg, mock_run):
        """block exit code is never downgraded, even if finding looks like .app."""
        mock_cfg.return_value = _CFG
        findings = [{"rule_id": "lookalike_tld", "value": ".app"}]
        mock_run.return_value = _mock_run(1, _json_stdout(findings, "block"))
        result = check_command_security("curl https://example.app")
        assert result["action"] == "block"


class TestEmojiVariationSelectorSuppression:
    """VS16 after an emoji-capable base is presentation, not obfuscation: no approval prompt."""

    _VS = [{"rule_id": "variation_selector", "severity": "medium"}]

    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_emoji_only_variation_selector_warn_is_downgraded(self, mock_cfg, mock_run):
        mock_cfg.return_value = _CFG
        mock_run.return_value = _mock_run(2, _json_stdout(self._VS, "variation selector"))

        # SMP emoji, Dingbats/Misc Symbols, and BMP singletons outside those blocks (ℹ ▶).
        result = check_command_security('ls "🗞️ Journal/" "✅️ Projects/" "ℹ️ Info/" "▶️ Media/"')

        assert result == {"action": "allow", "findings": [], "summary": ""}

    @pytest.mark.parametrize("command, findings", [
        ("printf 'a️'", _VS),            # VS16 after a letter
        ("printf '0️'", _VS),            # VS16 after a digit (keycap base)
        ("printf 'x󠄀'", _VS),        # a non-VS16 selector
        ('curl https://bit.ly/x --output "🗞️ Journal/file"',  # emoji path + another finding
         _VS + [{"rule_id": "shortened_url", "severity": "medium"}]),
    ])
    @patch("tools.tirith_security.subprocess.run")
    @patch("tools.tirith_security._load_security_config")
    def test_other_selectors_or_mixed_findings_keep_warn(self, mock_cfg, mock_run, command, findings):
        mock_cfg.return_value = _CFG
        mock_run.return_value = _mock_run(2, _json_stdout(findings, "variation selector"))

        result = check_command_security(command)

        assert result["action"] == "warn"
        assert result["findings"] == findings


class TestIsAppTldFinding:
    """Unit tests for the _is_app_tld_finding helper."""

    @pytest.mark.parametrize("finding, expected", [
        ({"rule_id": "lookalike_tld", "value": ".APP"}, True),   # case-insensitive
        ({"rule_id": "lookalike_tld", "message": "Domain uses '.app' TLD"}, True),
        ({"rule_id": "shortened_url", "value": ".app"}, False),  # wrong rule_id
        ({"rule_id": "lookalike_tld", "value": ".zip"}, False),  # other TLD
    ])
    def test_app_tld_detection(self, finding, expected):
        from tools.tirith_security import _is_app_tld_finding
        assert _is_app_tld_finding(finding) is expected


# ---------------------------------------------------------------------------
# mkdtemp OSError → no_space (disk-full leak prevention)
# ---------------------------------------------------------------------------

class TestMkdtempOSErrorNoSpace:
    """When tempfile.mkdtemp raises OSError (e.g. disk full), _install_tirith
    must return (None, "no_space") instead of propagating the exception.
    This prevents the unbounded retry + temp-dir leak described in #51826.
    """

    def test_mkdtemp_oserror_returns_no_space(self):
        from tools.tirith_security import _install_tirith

        with patch("tools.tirith_security.tempfile.mkdtemp",
                   side_effect=OSError(28, "No space left on device")):
            result, reason = _install_tirith(log_failures=False)
            assert result is None
            assert reason == "no_space"

    def test_mkdtemp_oserror_does_not_leak_tempdir(self):
        """No temp directory should remain after a mkdtemp failure."""
        import glob
        from tools.tirith_security import _install_tirith

        before = set(glob.glob("/tmp/tirith-install-*"))
        with patch("tools.tirith_security.tempfile.mkdtemp",
                   side_effect=OSError(28, "No space left on device")):
            _install_tirith(log_failures=False)
        after = set(glob.glob("/tmp/tirith-install-*"))
        assert after - before == set()


# ---------------------------------------------------------------------------
# F7 — the breaker must RECOVER (gate report 5400: it used to be un-healable)
# ---------------------------------------------------------------------------

def _ledger_rows(home):
    import json
    path = os.path.join(str(home), "security", "guard_events.jsonl")
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class TestCircuitBreakerRecovery:
    """An open breaker used to return before resolution/spawn on EVERY later call: a completed
    install (or a restored binary) never resumed scanning, and the failure count was global to the
    process, so one profile's broken scanner blocked its siblings."""

    @patch("tools.tirith_security._load_security_config")
    def test_bounded_reprobe_recovers_after_the_scanner_returns(self, mock_cfg, tmp_path):
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith", "tirith_timeout": 5}
        with patch("tools.tirith_security._resolve_tirith_path", return_value="/missing/tirith"), \
             patch("tools.tirith_security.subprocess.run", side_effect=FileNotFoundError("gone")):
            for _ in range(_tirith_mod._CRASH_LIMIT):
                assert check_command_security("echo hi")["action"] == "block"
        assert _tirith_mod._circuit_open is True
        # Still closed to new commands before the interval elapses.
        assert check_command_security("echo hi")["action"] == "block"
        # Age the trip past the re-probe interval and give it a working scanner.
        _tirith_mod._breaker_opened_at = time.monotonic() - (_tirith_mod._BREAKER_REPROBE_INTERVAL_S + 1)
        _tirith_mod._last_reprobe_at = 0.0
        with patch("tools.tirith_security._resolve_tirith_path", return_value="/restored/tirith"), \
             patch("tools.tirith_security.subprocess.run", return_value=_mock_run(0, _json_stdout())):
            result = check_command_security("echo hi")
        assert result["action"] == "allow"
        assert "degradation" not in result          # a real scan, not a degraded decision
        assert _tirith_mod._circuit_open is False    # healed without a restart
        assert _tirith_mod._crash_count == 0

    @patch("tools.tirith_security._load_security_config")
    def test_resolution_success_clears_the_breaker(self, mock_cfg):
        """A completed install / resolved binary closes the breaker immediately."""
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith", "tirith_timeout": 5}
        _tirith_mod._circuit_open = True
        _tirith_mod._crash_count = _tirith_mod._CRASH_LIMIT
        _tirith_mod._breaker_opened_at = time.monotonic()
        _tirith_mod._set_resolved("/now/available/tirith")
        assert _tirith_mod._circuit_open is False
        assert _tirith_mod._crash_count == 0

    def test_explicit_reset_action_closes_every_scope(self):
        _tirith_mod._circuit_open = True
        _tirith_mod._crash_count = 99
        _tirith_mod._breaker_opened_at = time.monotonic()
        _tirith_mod._circuit_open_by_home["/some/profile/home"] = True
        _tirith_mod.reset_circuit_breaker()
        assert _tirith_mod._circuit_open is False
        assert _tirith_mod._crash_count == 0
        assert _tirith_mod._circuit_open_by_home == {}

    @patch("tools.tirith_security._load_security_config")
    def test_breaker_is_scoped_per_hermes_home(self, mock_cfg, tmp_path):
        """One routed profile's failures must not stop scanning for a sibling profile."""
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith", "tirith_timeout": 5}
        scope_a, scope_b = "/profiles/a", "/profiles/b"
        with patch("tools.tirith_security._breaker_scope", return_value=scope_a):
            with patch("tools.tirith_security._resolve_tirith_path", return_value="/missing/tirith"), \
                 patch("tools.tirith_security.subprocess.run", side_effect=FileNotFoundError("gone")):
                for _ in range(_tirith_mod._CRASH_LIMIT):
                    check_command_security("echo hi")
            assert _tirith_mod._breaker_open() is True
        with patch("tools.tirith_security._breaker_scope", return_value=scope_b):
            assert _tirith_mod._breaker_open() is False   # sibling scope unaffected
            with patch("tools.tirith_security._resolve_tirith_path", return_value="/profiles/b/tirith"), \
                 patch("tools.tirith_security.subprocess.run", return_value=_mock_run(0, _json_stdout())):
                assert check_command_security("echo hi")["action"] == "allow"


# ---------------------------------------------------------------------------
# F4 — every degraded command is loud AND attributable (gate report 5400)
# ---------------------------------------------------------------------------

class TestDegradationAttribution:
    @patch("tools.tirith_security._load_security_config")
    def test_every_affected_command_gets_its_own_row(self, mock_cfg, tmp_path, monkeypatch):
        """The old warnings were process-deduplicated: the ledger must fire per command."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        with patch("tools.tirith_security._resolve_tirith_path", return_value="/missing/tirith"), \
             patch("tools.tirith_security.subprocess.run", side_effect=FileNotFoundError("gone")):
            first = check_command_security("echo one")
            second = check_command_security("echo two")
        rows = [r for r in _ledger_rows(tmp_path) if r["kind"] == "degradation"]
        assert len(rows) == 2
        assert rows[0]["reason"] == "spawn_failed"
        assert rows[0]["outcome"] == "allowed"          # the ACKNOWLEDGED (fail-open) path too
        assert rows[0]["attempted_path"] == "tirith"
        assert rows[0]["breaker_open"] is False
        assert rows[0]["acknowledgement_source"] == "config:security.tirith_fail_open"
        assert first["degradation"]["reason"] == second["degradation"]["reason"] == "spawn_failed"

    @patch("tools.tirith_security._load_security_config")
    def test_fail_closed_row_records_the_blocked_outcome(self, mock_cfg, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5}    # no acknowledgement -> fail closed
        with patch("tools.tirith_security._resolve_tirith_path", return_value="/missing/tirith"), \
             patch("tools.tirith_security.subprocess.run", side_effect=FileNotFoundError("gone")):
            result = check_command_security("echo hi")
        assert result["action"] == "block"
        assert result["degradation"]["outcome"] == "blocked"
        assert [r["outcome"] for r in _ledger_rows(tmp_path) if r["kind"] == "degradation"] == ["blocked"]

    @patch("tools.tirith_security._load_security_config")
    def test_env_override_is_recorded_as_the_actual_source(self, mock_cfg, tmp_path, monkeypatch):
        """TIRITH_FAIL_OPEN overrides config, so 'recorded in config.yaml' is not universally
        true — the effective source must be recorded."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("TIRITH_FAIL_OPEN", "1")
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": False}
        with patch("tools.tirith_security._resolve_tirith_path", return_value="/missing/tirith"), \
             patch("tools.tirith_security.subprocess.run", side_effect=FileNotFoundError("gone")):
            result = check_command_security("echo hi")
        assert result["degradation"]["acknowledgement_source"] == "env:TIRITH_FAIL_OPEN"

    @patch("tools.tirith_security._load_security_config")
    def test_unsupported_platform_branch_is_attributed(self, mock_cfg, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith",
                                 "tirith_timeout": 5, "tirith_fail_open": True}
        with patch("tools.tirith_security.is_platform_supported", return_value=False):
            result = check_command_security("echo hi")
        assert result["action"] == "allow"
        assert result["degradation"]["reason"] == "unsupported_platform"
        rows = [r for r in _ledger_rows(tmp_path) if r["kind"] == "degradation"]
        assert rows and rows[-1]["reason"] == "unsupported_platform"

    @patch("tools.tirith_security._load_security_config")
    def test_breaker_branch_is_attributed_with_breaker_state(self, mock_cfg, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        mock_cfg.return_value = {"tirith_enabled": True, "tirith_path": "tirith", "tirith_timeout": 5}
        _tirith_mod._circuit_open = True
        _tirith_mod._breaker_opened_at = time.monotonic()
        result = check_command_security("echo hi")
        assert result["action"] == "block"
        assert result["degradation"]["reason"] == "circuit_breaker"
        assert result["degradation"]["breaker_open"] is True
