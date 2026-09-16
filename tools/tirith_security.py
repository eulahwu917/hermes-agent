"""Tirith pre-exec security scanning wrapper: runs the tirith binary as a subprocess to scan
commands for content-level threats (homograph URLs, pipe-to-interpreter, terminal injection).
The exit code is the verdict source of truth (0 allow, 1 block, 2 warn); JSON stdout only
enriches findings. Operational failures and any form of scanner unavailability (spawn error, timeout,
unknown exit, circuit breaker, no platform build) follow ``security.tirith_fail_open``,
which DEFAULTS TO FAIL-CLOSED: the command is blocked with a clear reason instead of
silently proceeding with pattern matching only. Setting ``tirith_fail_open: true`` is the
operator's explicit, recorded acknowledgement of degraded operation (the ``TIRITH_FAIL_OPEN``
env var overrides it, and the source that actually took effect is recorded on every degraded
decision). Both the opt-in and ``tirith_enabled: false`` are reachable from OUTSIDE the terminal
gate (``hermes config set``), so a blocked host is a policy state, never a brick.

A degraded decision is never silent and never mistakable for an ordinary threat finding: the
verdict carries a structured ``degradation`` record and each affected command appends a
``degradation`` row (reason, attempted/resolved path, breaker state, session/profile,
acknowledgement source, outcome) to the shared guard event ledger (``tools.guard_events``).

The circuit breaker is per Hermes home and recovers without a process restart: a bounded re-probe
re-runs resolution + spawn (one attempt per ``_BREAKER_REPROBE_INTERVAL_S``), a successful scan or a
resolved binary closes it, and :func:`reset_circuit_breaker` is the explicit supported reset.
Programming errors propagate. Auto-install: a missing tirith is downloaded from
GitHub releases to $HERMES_HOME/bin/tirith in a background thread -- SHA-256 always verified,
cosign provenance when cosign is on PATH."""

import hashlib
import json
import logging
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
from contextlib import suppress

from hermes_constants import get_hermes_home, get_hermes_home_override, hermes_home_key
from tools.guard_events import (
    KIND_DEGRADATION, OUTCOME_ALLOWED, OUTCOME_BLOCKED, record_guard_event,
)

logger = logging.getLogger(__name__)
_REPO = "sheeki03/tirith"
# Cosign provenance pinned to the release workflow, not the whole repo.
_COSIGN_IDENTITY_REGEXP = f"^https://github.com/{_REPO}/\\.github/workflows/release\\.yml@refs/tags/v"
_COSIGN_ISSUER = "https://token.actions.githubusercontent.com"

# --- Config helpers ---
def _env_bool(key: str, default: bool) -> bool:
    val = os.getenv(key)
    return default if val is None else val.lower() in {"1", "true", "yes"}


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ[key])
    except (KeyError, ValueError):
        return default


def _load_security_config() -> dict:
    """Security settings from config.yaml, with env var overrides."""
    try:
        from hermes_cli.config import load_config_readonly
        cfg = load_config_readonly().get("security", {}) or {}
    except Exception:
        cfg = {}
    return {
        "tirith_enabled": _env_bool("TIRITH_ENABLED", cfg.get("tirith_enabled", True)),
        "tirith_path": os.getenv("TIRITH_BIN", cfg.get("tirith_path", "tirith")),
        "tirith_timeout": _env_int("TIRITH_TIMEOUT", cfg.get("tirith_timeout", 5)),
        "tirith_fail_open": _env_bool("TIRITH_FAIL_OPEN", cfg.get("tirith_fail_open", False))}


# --- Module state ---
# Cached path after first resolution. _INSTALL_FAILED means "tried and failed" (distinct
# from None = "not yet tried") so a failed install is not retried per command.
_resolved_path: str | None | bool = None
_INSTALL_FAILED = False
_install_failure_reason: str = ""  # reason tag when _resolved_path is _INSTALL_FAILED
# Routed profiles (multiplexed gateway) resolve their own binary: ``security.tirith_path`` and
# ``<home>/bin/tirith`` are per profile, so the launch profile's slot above must not answer for them.
_resolved_path_by_home: dict[str, str] = {}

# Circuit breaker: after _CRASH_LIMIT consecutive spawn/execution failures tirith is disabled
# for the rest of the process so a broken binary can't turn every tool call into a fail-open
# retry loop. The breaker RECOVERS without a restart: a bounded re-probe (one attempt per
# _BREAKER_REPROBE_INTERVAL_S) re-runs resolution + spawn, a successful scan or a completed
# resolution clears it, and reset_circuit_breaker() is the explicit supported reset. Failure is
# counted per Hermes home so one routed profile's broken binary cannot stop scanning for every
# other profile sharing the process. The counters stay lock-free (see the thread-safety note below).

_CRASH_LIMIT = 3
_CIRCUIT_RETRY_S = 300  # half-open probe interval (seconds)
_crash_count: int = 0
_circuit_open: bool = False
# Same state for routed multiplex profiles, keyed by Hermes home (see _breaker_scope): the default
# home keeps using the module globals above so the historical surface is unchanged.
_crash_count_by_home: dict[str, int] = {}
_circuit_open_by_home: dict[str, bool] = {}
_breaker_opened_at: float = 0.0        # monotonic ts the default-scope breaker opened (0 = unknown)
_breaker_opened_at_by_home: dict[str, float] = {}
_last_reprobe_at: float = 0.0          # monotonic ts of the last bounded re-probe attempt
_breaker_lock = threading.Lock()
# One re-probe per interval: bounded (a hot loop cannot hammer a broken binary) and enough for a
# restored scanner to be picked up automatically.
_BREAKER_REPROBE_INTERVAL_S = 60.0


_install_lock = threading.Lock()
_install_thread: threading.Thread | None = None

# Warn-once: spawn/path warnings sit in the hot path and would otherwise repeat once per
# terminal command while tirith is unavailable (e.g. install thread still running).
_warned_messages: set[str] = set()
_warned_lock = threading.Lock()

_MARKER_TTL = 86400  # disk failure marker validity (24h) -- avoids retry across restarts


def _breaker_scope() -> str:
    """Hermes home this call belongs to (``""`` = the process-global default scope).

    A routed multiplex profile resolves its own binary, so it owns its own breaker: one profile's
    broken scanner must not stop scanning for a sibling profile sharing the process.
    """
    return hermes_home_key() if get_hermes_home_override() is not None else ""


def _breaker_open() -> bool:
    scope = _breaker_scope()
    if scope:
        return bool(_circuit_open_by_home.get(scope))
    return _circuit_open


def _record_tirith_crash() -> None:
    """Count one consecutive scanner failure and open this scope's breaker at the limit."""
    global _crash_count, _circuit_open, _breaker_opened_at
    scope = _breaker_scope()
    if scope:
        count = _crash_count_by_home.get(scope, 0) + 1
        _crash_count_by_home[scope] = count
        just_opened = count == _CRASH_LIMIT
        if count >= _CRASH_LIMIT:
            _circuit_open_by_home[scope] = True
            _breaker_opened_at_by_home.setdefault(scope, time.monotonic())
    else:
        _crash_count += 1
        just_opened = _crash_count == _CRASH_LIMIT
        if _crash_count >= _CRASH_LIMIT:
            _circuit_open = True
            if not _breaker_opened_at:
                _breaker_opened_at = time.monotonic()
    if just_opened:
        logger.warning("tirith circuit breaker opened after %d consecutive failures; scanning "
                       "unavailable until the scanner is restored (bounded automatic re-probe "
                       "every %ds)", _CRASH_LIMIT, int(_BREAKER_REPROBE_INTERVAL_S))


def _reset_breaker() -> None:
    """Close this scope's breaker and clear its failure count.

    Called on a successful scan AND whenever resolution succeeds (a completed install, or a
    manually restored binary), so restoring the scanner does resume scanning.
    """
    global _crash_count, _circuit_open, _breaker_opened_at, _last_reprobe_at
    scope = _breaker_scope()
    if scope:
        _crash_count_by_home.pop(scope, None)
        _circuit_open_by_home.pop(scope, None)
        _breaker_opened_at_by_home.pop(scope, None)
        return
    _crash_count, _breaker_opened_at, _last_reprobe_at = 0, 0.0, 0.0
    _circuit_open = False


def reset_circuit_breaker() -> None:
    """Explicit supported reset: close the breaker for EVERY scope and clear all counters.

    The operator-facing recovery action (and the test seam). Restoring the scanner alone may not
    be enough while a re-probe is still waiting out its interval.
    """
    global _crash_count, _circuit_open, _breaker_opened_at, _last_reprobe_at
    _crash_count, _breaker_opened_at, _last_reprobe_at = 0, 0.0, 0.0
    _circuit_open = False
    _crash_count_by_home.clear()
    _circuit_open_by_home.clear()
    _breaker_opened_at_by_home.clear()


def _breaker_reprobe_allowed() -> bool:
    """True at most once per ``_BREAKER_REPROBE_INTERVAL_S``, process-wide.

    The bounded recovery path: an open breaker still re-runs resolution + spawn occasionally, so a
    scanner restored after the trip resumes scanning without a process restart. A breaker whose
    open time was never recorded (legacy/test state) is NOT eligible — fail closed.
    """
    global _last_reprobe_at, _breaker_opened_at
    scope = _breaker_scope()
    opened_at = _breaker_opened_at_by_home.get(scope, 0.0) if scope else _breaker_opened_at
    if not opened_at:
        return False
    with _breaker_lock:
        now = time.monotonic()
        if now - opened_at < _BREAKER_REPROBE_INTERVAL_S:
            return False
        if now - _last_reprobe_at < _BREAKER_REPROBE_INTERVAL_S:
            return False
        _last_reprobe_at = now
        return True



def _warn_once(key: str, message: str, *args) -> None:
    """``logger.warning`` at most once per ``key`` for the process lifetime."""
    with _warned_lock:
        if key in _warned_messages:
            return
        _warned_messages.add(key)
    logger.warning(message, *args)


def _cached_path() -> str | None:
    """The path resolved on a previous call, or None if unresolved (None) / failed (_INSTALL_FAILED)."""
    if get_hermes_home_override() is not None:
        return _resolved_path_by_home.get(hermes_home_key())
    return _resolved_path or None


def _store_resolved(path: str) -> None:
    global _resolved_path
    if get_hermes_home_override() is not None:
        _resolved_path_by_home[hermes_home_key()] = path
    else:
        _resolved_path = path


def _set_resolved(path: str) -> None:
    global _install_failure_reason
    _store_resolved(path)
    _install_failure_reason = ""
    # A resolved binary means the scanner is usable again: close this scope's breaker so a completed
    # install (or a manually restored tirith) resumes scanning without waiting for a re-probe.
    _reset_breaker()


def _set_failed(reason: str) -> None:
    global _resolved_path, _install_failure_reason
    _resolved_path, _install_failure_reason = _INSTALL_FAILED, reason


# --- Disk failure marker ---
def _failure_marker_path() -> str:
    return os.path.join(str(get_hermes_home()), ".tirith-install-failed")


def _read_failure_reason() -> str | None:
    """The marker's reason, or None if absent or older than _MARKER_TTL."""
    try:
        p = _failure_marker_path()
        if (time.time() - os.path.getmtime(p)) >= _MARKER_TTL:
            return None
        with open(p, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def _is_install_failed_on_disk() -> bool:
    """True if a recent install failure was persisted and is still non-retryable.
    A 'cosign_missing' marker is auto-cleared once cosign appears on PATH."""
    reason = _read_failure_reason()
    if reason == "cosign_missing" and shutil.which("cosign"):
        _clear_install_failed()
        return False
    return reason is not None


def _mark_install_failed(reason: str = ""):
    """Persist install failure to disk; ``reason`` is a short retryability tag."""
    with suppress(OSError):
        p = _failure_marker_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(reason)


def _clear_install_failed():
    """Remove the failure marker and reset warn-once state (so a failure after a reinstall surfaces again)."""
    with _warned_lock:
        _warned_messages.clear()
    with suppress(OSError):
        os.unlink(_failure_marker_path())


def _disk_marker_blocks_install() -> bool:
    """Apply a still-valid disk marker to module state; True if install must be skipped.
    Keeps the marker's real reason so in-process retry can detect cosign_missing."""
    if (disk_reason := _read_failure_reason()) is None or not _is_install_failed_on_disk():
        return False
    _set_failed(disk_reason)
    return True


# --- Auto-install ---
def _hermes_bin_dir() -> str:
    """$HERMES_HOME/bin, created if needed."""
    os.makedirs(d := os.path.join(str(get_hermes_home()), "bin"), exist_ok=True)
    return d


# Rust target triple components. Android (Termux) is ABI-compatible with Linux. Windows is
# absent on purpose (no tirith build): None = "never available here", pattern guards still run.
_TARGET_PLATFORMS = {"Darwin": "apple-darwin", "Linux": "unknown-linux-gnu", "Android": "unknown-linux-gnu"}
_TARGET_ARCHES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


def _detect_target() -> str | None:
    """Rust target triple for this platform, or None if tirith has no build for it."""
    plat = _TARGET_PLATFORMS.get(platform.system())
    arch = _TARGET_ARCHES.get(platform.machine().lower())
    return f"{arch}-{plat}" if plat and arch else None


def is_platform_supported() -> bool:
    """True when tirith ships a prebuilt binary for this OS+arch (CLI banner uses this)."""
    return _detect_target() is not None


def _download_file(url: str, dest: str, timeout: int = 10):
    from agent.secret_scope import get_secret
    req = urllib.request.Request(url)
    if token := get_secret("GITHUB_TOKEN"):
        req.add_header("Authorization", f"token {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)


def _verify_cosign(checksums_path: str, sig_path: str, cert_path: str) -> bool | None:
    """Cosign provenance of checksums.txt: True verified, False rejected, None if cosign absent/failed."""
    if not (cosign := shutil.which("cosign")):
        logger.info("cosign not found on PATH")
        return None
    try:
        result = subprocess.run(
            [cosign, "verify-blob", "--certificate", cert_path, "--signature", sig_path,
             "--certificate-identity-regexp", _COSIGN_IDENTITY_REGEXP,
             "--certificate-oidc-issuer", _COSIGN_ISSUER, checksums_path],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("cosign execution failed: %s", exc)
        return None
    if result.returncode:
        logger.warning("cosign verification failed (exit %d): %s", result.returncode, result.stderr.strip())
        return False
    logger.info("cosign provenance verification passed")
    return True


def _verify_release_provenance(base_url: str, tmpdir: str, checksums_path: str, log) -> tuple[bool, str]:
    """Cosign step of the install -> ``(cosign_verified, failure_reason)``. Only an explicit
    cosign rejection aborts; missing/broken cosign or artifacts fall back to SHA-256 only."""
    if not shutil.which("cosign"):
        logger.info("cosign not on PATH — installing tirith with SHA-256 verification only "
                    "(install cosign for full supply chain verification)")
        return False, ""
    sig_path, cert_path = os.path.join(tmpdir, "checksums.txt.sig"), os.path.join(tmpdir, "checksums.txt.pem")
    try:
        _download_file(f"{base_url}/checksums.txt.sig", sig_path)
        _download_file(f"{base_url}/checksums.txt.pem", cert_path)
    except Exception as exc:
        logger.info("cosign artifacts unavailable (%s), proceeding with SHA-256 only", exc)
        return False, ""
    verified = _verify_cosign(checksums_path, sig_path, cert_path)
    if verified is False:
        log("tirith install aborted: cosign provenance verification failed")
        return False, "cosign_verification_failed"
    if verified is None:
        logger.info("cosign execution failed, proceeding with SHA-256 only")
    return verified is True, ""


def _verify_checksum(archive_path: str, checksums_path: str, archive_name: str) -> bool:
    """Verify SHA-256 of the archive against checksums.txt ("<hash>  <filename>" lines)."""
    with open(checksums_path, encoding="utf-8") as f:
        parsed = (line.strip().split("  ", 1) for line in f)
        expected = next((h for h, *n in parsed if n == [archive_name]), None)
    if not expected:
        logger.warning("No checksum entry for %s", archive_name)
        return False
    sha = hashlib.sha256()
    with open(archive_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    actual = sha.hexdigest()
    if actual != expected:
        logger.warning("Checksum mismatch: expected %s, got %s", expected, actual)
    return actual == expected


def _extract_tirith_binary(tar: tarfile.TarFile, dest_dir: str, log) -> tuple[str | None, str]:
    """Extract the tirith binary from a release archive into dest_dir -> ``(path, reason)``."""
    for member in tar.getmembers():
        if member.name.rsplit("/", 1)[-1] != "tirith" or ".." in member.name:
            continue
        if not member.isfile():
            log("tirith archive member is not a regular file: %s", member.name)
            return None, "binary_not_regular_file"
        if (src_file := tar.extractfile(member)) is None:
            log("tirith binary could not be read from archive")
            return None, "binary_extract_failed"
        dest_path = os.path.join(dest_dir, "tirith")
        with src_file, open(dest_path, "wb") as out:
            shutil.copyfileobj(src_file, out)
        return dest_path, ""
    log("tirith binary not found in archive")
    return None, "binary_not_in_archive"


def _install_tirith(*, log_failures: bool = True) -> tuple[str | None, str]:
    """Download and install tirith to $HERMES_HOME/bin/tirith -> ``(installed_path,
    failure_reason)``; the reason ("" on success) is the disk marker's retryability tag."""
    log = logger.warning if log_failures else logger.debug
    if not (target := _detect_target()):
        logger.info("tirith auto-install: unsupported platform %s/%s", platform.system(), platform.machine())
        return None, "unsupported_platform"
    archive_name = f"tirith-{target}.tar.gz"
    base_url = f"https://github.com/{_REPO}/releases/latest/download"
    try:
        tmpdir = tempfile.mkdtemp(prefix="tirith-install-")
    except OSError as exc:
        log("tirith install failed: cannot create temp dir: %s", exc)
        return None, "no_space"
    try:
        archive_path, checksums_path = os.path.join(tmpdir, archive_name), os.path.join(tmpdir, "checksums.txt")
        logger.info("tirith not found — downloading latest release for %s...", target)
        try:
            _download_file(f"{base_url}/{archive_name}", archive_path)
            _download_file(f"{base_url}/checksums.txt", checksums_path)
        except Exception as exc:
            log("tirith download failed: %s", exc)
            return None, "download_failed"
        cosign_verified, reason = _verify_release_provenance(base_url, tmpdir, checksums_path, log)
        if reason:
            return None, reason
        if not _verify_checksum(archive_path, checksums_path, archive_name):
            return None, "checksum_failed"
        with tarfile.open(archive_path, "r:gz") as tar:
            src, reason = _extract_tirith_binary(tar, tmpdir, log)
        if src is None:
            return None, reason
        dest = os.path.join(_hermes_bin_dir(), "tirith")
        try:
            shutil.move(src, dest)
        except OSError:
            # Cross-device move (Docker, NFS): copy2's metadata step can raise PermissionError,
            # so fall back to plain copy + chmod; a partial dest is removed to avoid a
            # non-executable retry loop.
            try:
                shutil.copy(src, dest)
            except OSError:
                with suppress(OSError):
                    os.unlink(dest)
                return None, "cross_device_copy_failed"
        os.chmod(dest, os.stat(dest).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        logger.info("tirith installed to %s (%s)", dest, "cosign + SHA-256" if cosign_verified else "SHA-256 only")
        return dest, ""
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# --- Path resolution ---
def _is_executable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _find_local_tirith() -> str | None:
    """Cheap local lookup for the default "tirith": PATH, then $HERMES_HOME/bin."""
    hermes_bin = os.path.join(_hermes_bin_dir(), "tirith")
    return shutil.which("tirith") or (hermes_bin if _is_executable(hermes_bin) else None)


def _resolve_locally(configured_path: str, *, warn_missing: bool) -> tuple[str | None, bool]:
    """Network-free resolution -> ``(path, may_install)``: ``path`` set = resolved (module state
    updated); else ``may_install`` False = terminal miss (explicit path missing, cached non-retryable
    failure), True = the disk marker / install step may proceed."""
    global _resolved_path, _install_failure_reason
    expanded = os.path.expanduser(configured_path)
    # An explicit (non-"tirith") path is authoritative: never auto-download a replacement.
    if configured_path != "tirith":
        if found := (expanded if _is_executable(expanded) else shutil.which(expanded)):
            _store_resolved(found)
            return found, False
        if warn_missing:
            logger.warning("Configured tirith path %r not found; scanning disabled", configured_path)
        _set_failed("explicit_path_missing")
        return None, False
    # Always re-run the cheap local checks so a manual install is picked up even after a
    # previous network failure (a long-lived gateway recovers without restart).
    if found := _find_local_tirith():
        _set_resolved(found)
        _clear_install_failed()
        return found, False
    # Previous install failed: skip the network retry unless the retryable cosign_missing
    # cause has been resolved in-process.
    if _resolved_path is _INSTALL_FAILED:
        if _install_failure_reason != "cosign_missing" or not shutil.which("cosign"):
            return None, False
        _resolved_path, _install_failure_reason = None, ""
        _clear_install_failed()
    return None, True


def _record_install_result(installed: str | None, reason: str) -> str | None:
    """Cache an install outcome in module state + disk marker; returns *installed*."""
    if installed:
        _set_resolved(installed)
        _clear_install_failed()
    else:
        _set_failed(reason)
        _mark_install_failed(reason)
    return installed


def _resolve_tirith_path(configured_path: str) -> str:
    """Resolve the tirith path, auto-installing synchronously if needed (default "tirith": PATH →
    $HERMES_HOME/bin/tirith → install; failures cached in-process and on disk for 24h). On a miss
    the expanded configured path is returned so the spawn fails open via the dedupe'd OSError."""
    if cached := _cached_path():
        return cached
    expanded = os.path.expanduser(configured_path)
    # No tirith build for this platform: cache the verdict; the spawn fails open once, then
    # the fast path above short-circuits.
    if configured_path == "tirith" and not is_platform_supported():
        _set_failed("unsupported_platform")
        return expanded
    found, may_install = _resolve_locally(configured_path, warn_missing=True)
    if found or not may_install:
        return found or expanded
    # A background install is running: don't start a parallel one; the spawn path stays unresolved
    # until it finishes, and the fail-open/fail-closed policy then applies as usual.
    if _install_running() or _disk_marker_blocks_install():
        return expanded
    installed = _record_install_result(*_install_tirith())
    return installed or expanded


def _install_running() -> bool:
    return _install_thread is not None and _install_thread.is_alive()


def _background_install(*, log_failures: bool = True):
    """Background thread target: download and install tirith."""
    with _install_lock:
        if _resolved_path is not None:  # another thread resolved meanwhile
            return
        if found := _find_local_tirith():  # may have been installed by another process
            _set_resolved(found)
            return
        _record_install_result(*_install_tirith(log_failures=log_failures))


def ensure_installed(*, log_failures: bool = True):
    """Resolved path if available now, else None after kicking off a daemon-thread download (local
    checks are synchronous; the download never blocks startup). Safe to call repeatedly."""
    global _install_thread
    cfg = _load_security_config()
    if not cfg["tirith_enabled"]:
        return None
    if cached := _cached_path():
        return cached if _is_executable(cached) else None
    # No tirith build here (e.g. Windows): stay silent -- no PATH probe, no download thread,
    # no disk marker. Pattern-matching guards still run.
    if not is_platform_supported():
        _set_failed("unsupported_platform")
        return None
    found, may_install = _resolve_locally(cfg["tirith_path"], warn_missing=False)
    if found or not may_install or _disk_marker_blocks_install():
        return found
    if not _install_running():
        _install_thread = threading.Thread(target=_background_install, daemon=True,
                                           kwargs={"log_failures": log_failures})
        _install_thread.start()
    return None  # not available yet; the fail-open/fail-closed policy (default: closed) applies


# --- Main API ---
_MAX_FINDINGS = 50
_MAX_SUMMARY_LEN = 500
_EXIT_ACTIONS = {0: "allow", 1: "block", 2: "warn"}
# Summary when tirith's JSON is unparseable and only the exit code is known.
_NO_DETAILS_SUMMARY = {
    "block": "security issue detected (details unavailable)",
    "warn": "security warning detected (details unavailable)"}
_VARIATION_SELECTOR_16 = "\ufe0f"
# Code points that carry the Unicode ``Emoji`` property and take VS16 for emoji presentation: the
# Miscellaneous Symbols / Dingbats blocks, the SMP emoji planes, and the BMP singletons outside them
# (©️ ®️ ‼️ ⁉️ ™️ ℹ️ arrows, ⌚ ⌨️ ⏏️ media keys, Ⓜ️ ▪️ ▶️ ◀️ ◻️ ⤴️ ⬅️ ⬛ ⭐ ⭕ 〰️ 〽️ ㊗️ ㊙️).
# Digits, ``#`` and ``*`` also carry the property (keycap bases) but are deliberately absent: VS16
# after a letter or digit is exactly the steganography signal the rule exists for.
_EMOJI_PRESENTATION_BASE_RANGES = (
    (0x00A9, 0x00A9), (0x00AE, 0x00AE), (0x203C, 0x203C), (0x2049, 0x2049), (0x2122, 0x2122),
    (0x2139, 0x2139), (0x2194, 0x2199), (0x21A9, 0x21AA), (0x231A, 0x231B), (0x2328, 0x2328),
    (0x23CF, 0x23CF), (0x23E9, 0x23F3), (0x23F8, 0x23FA), (0x24C2, 0x24C2), (0x25AA, 0x25AB),
    (0x25B6, 0x25B6), (0x25C0, 0x25C0), (0x25FB, 0x25FE), (0x2600, 0x27BF), (0x2934, 0x2935),
    (0x2B05, 0x2B07), (0x2B1B, 0x2B1C), (0x2B50, 0x2B50), (0x2B55, 0x2B55), (0x3030, 0x3030),
    (0x303D, 0x303D), (0x3297, 0x3297), (0x3299, 0x3299), (0x1F000, 0x1FAFF))


def _verdict(action: str, summary: str = "", findings: list | None = None) -> dict:
    return {"action": action, "findings": [] if findings is None else findings, "summary": summary}


# Degradation reasons: WHY the scanner could not be used. Recorded structurally on EVERY affected
# command, and the marker that distinguishes a degraded decision from an ordinary threat finding —
# a degraded verdict has NOT scanned the command, so it must never be auto-approved by another
# layer (see ``tools.approval``: the guardian LLM is skipped and the decision is never persisted).
REASON_SPAWN_FAILED = "spawn_failed"
REASON_TIMEOUT = "timeout"
REASON_UNKNOWN_EXIT = "unknown_exit"
REASON_CIRCUIT_BREAKER = "circuit_breaker"
REASON_UNSUPPORTED_PLATFORM = "unsupported_platform"
REASON_PATH_UNAVAILABLE = "path_unavailable"
REASON_IMPORT_ERROR = "import_error"  # raised by the approval consumers when this module won't import


def _session_key_for_events() -> str:
    try:
        from tools.approval_context import get_current_session_key
        return get_current_session_key(default="")
    except Exception:
        return ""


def _acknowledgement_source() -> str:
    """Where the fail-open acknowledgement actually lives (env var overrides config.yaml)."""
    try:
        from tools.approval_context import tirith_fail_open_source
        return tirith_fail_open_source()
    except Exception:
        return "unknown"


def _degraded(action: str, summary: str, *, reason: str, attempted_path: str = "",
              resolved_path: str = "", breaker_open: bool = False,
              findings: list | None = None) -> dict:
    """A decision taken WITHOUT the scanner: loud and attributable at the command boundary.

    Every affected command gets its OWN ledger row — not one process-deduplicated warning — carrying
    the reason, the attempted/resolved scanner path, the breaker state, the session/profile, the
    acknowledgement source and the outcome. The verdict also carries the same structured record so
    the consumers can preserve it through the terminal result surface instead of discarding it.
    """
    verdict = _verdict(action, summary, findings)
    record = {
        "reason": reason,
        "attempted_path": attempted_path,
        "resolved_path": resolved_path,
        "breaker_open": bool(breaker_open),
        "acknowledgement_source": _acknowledgement_source(),
        "outcome": OUTCOME_BLOCKED if action == "block" else OUTCOME_ALLOWED,
    }
    verdict["degradation"] = record
    record_guard_event(KIND_DEGRADATION, _session_key_for_events(), outcome=record["outcome"],
                       extra={k: v for k, v in record.items() if k != "outcome"})
    return verdict


def _fail(fail_open: bool, open_summary: str, closed_summary: str, *, reason: str,
          attempted_path: str = "", resolved_path: str = "", breaker_open: bool = False) -> dict:
    """Scanner unavailability: fail open (acknowledged) or closed (default) — never silent."""
    action, summary = ("allow", open_summary) if fail_open else ("block", closed_summary)
    return _degraded(action, summary, reason=reason, attempted_path=attempted_path,
                     resolved_path=resolved_path, breaker_open=breaker_open)


def _crash(fail_open: bool, open_summary: str, closed_summary: str, *, reason: str,
           attempted_path: str = "", resolved_path: str = "") -> dict:
    """An operational failure: count it toward the circuit breaker, then fail open/closed."""
    _record_tirith_crash()
    return _fail(fail_open, open_summary, closed_summary, reason=reason,
                 attempted_path=attempted_path, resolved_path=resolved_path,
                 breaker_open=_breaker_open())


# Remediation tail for fail-closed blocks: the fix direction plus the recorded-acknowledgement
# escape hatch (security.tirith_fail_open: true). Kept OUT of the verdict when failing open.
_ACK_HINT = ("Three supported recovery routes, none of which needs hand-editing config: (1) restore "
             "the scanner (tirith auto-installs to $HERMES_HOME/bin/tirith); (2) set "
             "security.tirith_enabled: false to disable scanning; (3) explicitly acknowledge degraded "
             "(pattern-matching-only) operation with security.tirith_fail_open: true. Routes 2 and 3 "
             "are reachable from OUTSIDE this gate with `hermes config set ...` (or by hand-editing "
             "config.yaml), so a blocked host is never a brick. The TIRITH_FAIL_OPEN env var overrides "
             "route 3; the source that actually took effect is recorded on every degraded decision.")


def check_command_security(command: str) -> dict:
    """Run the tirith scan on a command -> ``{"action": allow|warn|block, "findings", "summary"}``.
    Exit code determines the action; JSON enriches. Every form of scanner unavailability honours
    ``security.tirith_fail_open`` — fail-CLOSED by default (no silent degradation to pattern matching).

    An unavailable scanner adds a structured ``degradation`` record to the verdict and one ledger
    event per affected command, so a degraded decision is never silent and never mistakable for an
    ordinary threat finding.
    """


    cfg = _load_security_config()
    fail_open = bool(cfg.get("tirith_fail_open", False))  # absent key == the fail-closed default
    if not cfg["tirith_enabled"]:
        return _verdict("allow")
    # Circuit breaker: if tirith has crashed _CRASH_LIMIT times in a row in this scope, stop trying
    # for a while. Without this, a corrupted or missing binary causes every tool call to hit the same
    # spawn failure → agent retry loop, hanging the user for 20+ minutes (issue #41400). Fail-closed
    # default: the open breaker BLOCKS instead of silently allowing un-scanned commands. Recovery is
    # bounded, not impossible: one re-probe per interval re-runs resolution + spawn, so a scanner
    # restored after the trip resumes scanning without a process restart.
    if _breaker_open():
        if not _breaker_reprobe_allowed():
            return _fail(fail_open, "tirith disabled (circuit breaker)",
                         "tirith unavailable: circuit breaker opened after repeated scanner "
                         "failures. Restore the scanner — scanning resumes automatically on the "
                         "next re-probe — or use the supported reset. " + _ACK_HINT,
                         reason=REASON_CIRCUIT_BREAKER, breaker_open=True)

    # No binary for this platform, ever: skip the resolver so we never spawn.
    if not is_platform_supported():
        return _fail(fail_open, "tirith has no build for this platform",
                     "tirith is not available for this platform, so the command cannot be scanned. "
                     + _ACK_HINT, reason=REASON_UNSUPPORTED_PLATFORM)
    tirith_path = _resolve_tirith_path(cfg["tirith_path"])
    timeout = cfg["tirith_timeout"]
    if tirith_path is None:
        _warn_once("tirith_path_none", "tirith path resolved to None; scanning disabled")
        return _fail(fail_open, "tirith path unavailable",
                     "tirith path unavailable (fail-closed). " + _ACK_HINT,
                     reason=REASON_PATH_UNAVAILABLE, attempted_path=cfg["tirith_path"])
    try:
        result = subprocess.run(
            [tirith_path, "check", "--json", "--non-interactive", "--shell", "posix", "--", command],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout,
            stdin=subprocess.DEVNULL)
    except OSError as exc:
        # FileNotFoundError / PermissionError / exec format error: dedupe the LOGGER line by
        # (class, errno) so each failure mode is not repeated per command — the degradation EVENT is
        # still emitted per affected command by _degraded().
        _warn_once(f"tirith_spawn_failed:{type(exc).__name__}:{getattr(exc, 'errno', '')}",
                   "tirith spawn failed: %s", exc)
        return _crash(fail_open, f"tirith unavailable: {exc}",
                      f"tirith spawn failed (fail-closed): {exc}. " + _ACK_HINT,
                      reason=REASON_SPAWN_FAILED, attempted_path=cfg["tirith_path"],
                      resolved_path=tirith_path)
    except subprocess.TimeoutExpired:
        _warn_once(f"tirith_timeout:{timeout}", "tirith timed out after %ds", timeout)
        return _crash(fail_open, f"tirith timed out ({timeout}s)",
                      f"tirith timed out after {timeout}s (fail-closed). " + _ACK_HINT,
                      reason=REASON_TIMEOUT, attempted_path=cfg["tirith_path"],
                      resolved_path=tirith_path)
    exit_code = result.returncode
    if (action := _EXIT_ACTIONS.get(exit_code)) is None:
        # Unknown exit code (includes signal-killed, e.g. -11): respect fail_open.
        logger.warning("tirith returned unexpected exit code %d", exit_code)
        return _crash(fail_open, f"tirith exit code {exit_code} (fail-open)",
                      f"tirith exit code {exit_code} (fail-closed). " + _ACK_HINT,
                      reason=REASON_UNKNOWN_EXIT, attempted_path=cfg["tirith_path"],
                      resolved_path=tirith_path)
    # A recognized exit code means the scanner RAN: any verdict (allow/block/warn) is a successful
    # execution, so the breaker closes here and the failure count clears.
    _reset_breaker()

    # JSON enriches findings/summary; a parse failure never changes the verdict.
    findings, summary = [], ""
    try:
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        findings = data.get("findings", [])[:_MAX_FINDINGS]
        summary = (data.get("summary", "") or "")[:_MAX_SUMMARY_LEN]
    except (json.JSONDecodeError, AttributeError):
        logger.debug("tirith JSON parse failed, using exit code only")
        summary = _NO_DETAILS_SUMMARY.get(action, "")
    # .app is a legitimate gTLD: a warn consisting solely of lookalike_tld findings for .app is a
    # known false positive and is downgraded to allow. Any other finding keeps the warn.
    if action == "warn" and findings and all(_is_app_tld_finding(f) for f in findings):
        return _verdict("allow")
    # VS16 follows ordinary emoji-capable code points in standard emoji-presentation sequences.
    # Preserve warnings for every other selector, including VS16 after text, because those can
    # carry the steganographic payload that Tirith is intended to detect.
    if action == "warn" and findings and all(_is_emoji_variation_selector_finding(f) for f in findings) \
            and _has_only_emoji_presentation_selectors(command):
        return _verdict("allow")
    return _verdict(action, summary, findings)


def _is_app_tld_finding(finding: dict) -> bool:
    """True if this finding is a lookalike_tld warning for the .app TLD only."""
    if not isinstance(finding, dict) or finding.get("rule_id") != "lookalike_tld":
        return False
    return any(
        val is not None and ".app" in str(val).lower()
        for val in (finding.get(k) for k in ("value", "tld", "detail", "description", "message")))


def _is_emoji_variation_selector_finding(finding: dict) -> bool:
    """True only for the Tirith rule that reports variation selectors."""
    return isinstance(finding, dict) and finding.get("rule_id") == "variation_selector"


def _has_only_emoji_presentation_selectors(command: str) -> bool:
    """Whether every variation selector is VS16 immediately after an emoji-capable base."""
    selectors = ("\ufe00", "\U000e0100")
    saw_selector = False
    for idx, char in enumerate(command):
        if not selectors[0] <= char <= "\ufe0f" and not selectors[1] <= char <= "\U000e01ef":
            continue
        saw_selector = True
        if char != _VARIATION_SELECTOR_16 or idx == 0:
            return False
        base = ord(command[idx - 1])
        if not any(start <= base <= end for start, end in _EMOJI_PRESENTATION_BASE_RANGES):
            return False
    return saw_selector
