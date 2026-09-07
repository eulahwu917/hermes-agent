"""OpenAI Codex OAuth: token store, refresh, quota probe, device-code login.

Tokens live in ~/.hermes/auth.json, NOT ~/.codex/: Hermes keeps its own Codex OAuth session
separate from the Codex CLI / VS Code extension so one app's refresh-token rotation cannot
invalidate the other's session.

Split out of ``hermes_cli/auth.py``; origin helpers are imported lazily inside each function
so ``hermes_cli.auth.<name>`` patches still intercept (and no import cycle).
"""

from __future__ import annotations

import logging
import hashlib
import json
import os
import threading
import time
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Tuple
from hermes_cli.auth_constants import (
    _decode_jwt_claims, AUTH_LOCK_TIMEOUT_SECONDS, AuthError,
    CODEX_ACCESS_TOKEN_REFRESH_SKEW_SECONDS, CODEX_OAUTH_CLIENT_ID, CODEX_OAUTH_TOKEN_URL,
    CODEX_OAUTH_USER_AGENT, CODEX_RATE_LIMITED_CODE, DEFAULT_CODEX_BASE_URL, _codex_err, httpx)
from utils import env_float

if TYPE_CHECKING:  # annotation-only; the runtime import would be a cycle
    from hermes_cli.auth import ProviderConfig

# Log-record parity with the origin module (caplog tests pin "hermes_cli.auth").
logger = logging.getLogger("hermes_cli.auth")

_MISSING_ACCESS_TOKEN_MSG = (
    "Codex auth is missing access_token. Run `hermes auth` to re-authenticate.")
_MISSING_REFRESH_TOKEN_MSG = (
    "Codex auth is missing refresh_token. Run `hermes auth` to re-authenticate.")
_NO_CREDENTIALS_MSG = "No Codex credentials stored. Run `hermes auth` to authenticate."


def _parse_retry_after_seconds(headers: Any) -> Optional[int]:
    """Best-effort parse of a ``Retry-After`` header into whole seconds."""
    from agent.retry_utils import parse_retry_after_seconds
    seconds = parse_retry_after_seconds(headers)
    return None if seconds is None else int(seconds)


def _stripped(value: Any) -> str:
    return str(value or "").strip()


def _clear_pool_entry_status(entry: Dict[str, Any]) -> None:
    """Reset a pool entry's cooldown / last-error metadata to healthy."""
    from hermes_cli.auth import _POOL_STATUS_FIELDS
    for status_field in _POOL_STATUS_FIELDS:
        entry[status_field] = None


def _codex_access_token_is_expiring(access_token: Any, skew_seconds: int) -> bool:
    exp = _decode_jwt_claims(access_token).get("exp")
    return isinstance(exp, (int, float)) and float(exp) <= (time.time() + max(0, int(skew_seconds)))


def _codex_base_url() -> str:
    return os.getenv("HERMES_CODEX_BASE_URL", "").strip().rstrip("/") or DEFAULT_CODEX_BASE_URL


def _codex_runtime_result(
    api_key: str, *, source: str, last_refresh: Optional[str]) -> Dict[str, Any]:
    return {
        "provider": "openai-codex", "base_url": _codex_base_url(), "api_key": api_key,
        "source": source, "last_refresh": last_refresh, "auth_mode": "chatgpt"}


def _load_auth_store_maybe_locked(lock: bool) -> Dict[str, Any]:
    """Load the auth store, taking the cross-process lock unless the caller already holds it."""
    from hermes_cli.auth import _auth_store_lock, _load_auth_store
    if lock:
        with _auth_store_lock():
            return _load_auth_store()
    return _load_auth_store()


def _read_codex_tokens(*, _lock: bool = True) -> Dict[str, Any]:
    """Read Codex OAuth tokens from Hermes auth store (~/.hermes/auth.json)."""
    from hermes_cli.auth import _load_provider_state, _nonempty_str
    auth_store = _load_auth_store_maybe_locked(_lock)
    state = _load_provider_state(auth_store, "openai-codex")
    if not state:
        raise _codex_err(_NO_CREDENTIALS_MSG, "codex_auth_missing", relogin=True)
    tokens = state.get("tokens")
    if not isinstance(tokens, dict):
        raise _codex_err(
            "Codex auth state is missing tokens. Run `hermes auth` to re-authenticate.",
            "codex_auth_invalid_shape", relogin=True)
    if not _nonempty_str(tokens.get("access_token")):
        raise _codex_err(_MISSING_ACCESS_TOKEN_MSG, "codex_auth_missing_access_token", relogin=True)
    if not _nonempty_str(tokens.get("refresh_token")):
        raise _codex_err(
            _MISSING_REFRESH_TOKEN_MSG, "codex_auth_missing_refresh_token", relogin=True)
    return {"tokens": tokens, "last_refresh": state.get("last_refresh")}


def _sync_codex_pool_entries(
    auth_store: Dict[str, Any], tokens: Dict[str, str], last_refresh: Optional[str],
    previous_singleton_tokens: Optional[Dict[str, str]] = None) -> None:
    """Mirror a fresh Codex re-auth into the credential_pool OAuth entries.

    ``device_code`` (the singleton-seeded entry from ``hermes setup`` / the model picker) is always
    synced. ``manual:device_code`` (``hermes auth add openai-codex``) is synced only when its
    access_token equals the PREVIOUS singleton token — a legacy alias of the singleton; an entry
    with its own token material is an independent account and must be left alone. ``manual:api_key``
    and any other source are independent credentials and are never overwritten by a re-auth.

    See #33000, #39236.
    The original #33538 fix refreshed every ``manual:device_code`` entry unconditionally. That worked when
    ``manual:device_code`` only meant "legacy alias of the singleton", but the same source string is now
    also produced by independent-account additions, and the broad sync silently clobbered distinct accounts
    with the latest-authenticated token pair. The access_token-match check distinguishes the two cases
    without changing the source-string contract.
    """
    access_token = tokens.get("access_token")
    if not access_token:
        return
    refresh_token = tokens.get("refresh_token")
    entries = _pool_entries(auth_store, "openai-codex")
    if entries is None:
        return
    # None/empty prev_at → no manual entry can be an alias (right default for a first-ever save).
    prev_at = (previous_singleton_tokens or {}).get("access_token") or None
    for entry in _codex_pool_dicts(entries):
        source = entry.get("source")
        is_alias = source == "manual:device_code" and bool(
            prev_at and entry.get("access_token") == prev_at)
        if not (source == "device_code" or is_alias):
            continue
        entry["access_token"] = access_token
        if refresh_token:
            entry["refresh_token"] = refresh_token
        if last_refresh:
            entry["last_refresh"] = last_refresh
        _clear_pool_entry_status(entry)


_CODEX_OAUTH_ISSUER = "https://auth.openai.com"
# CLASS-N persistence retry cardinality: exactly 3 total writes, 2 intervening
# fixed backoffs. These are policy (asserted as constants by tests, stated in
# CHANGELOG), so bumping them is a deliberate product decision, not a code edit.
_CODEX_ROOT_PERSIST_ATTEMPTS = 3
_CODEX_ROOT_PERSIST_BACKOFF_SECONDS = (0.5, 1.0)

# Dead-token tuples (access_token, refresh_token) already rescue-attempted in
# this process lifetime. One rescue attempt per dead tuple per process; the
# exported reset hook below exists only so tests can simulate a fresh process.
_codex_root_rescue_seen: set = set()


def _reset_codex_root_rescue_seen() -> None:
    """Clear the process-lifetime root-rescue seen-set (test hook)."""
    _codex_root_rescue_seen.clear()


def _codex_token_identity(access_token: Any) -> Optional[str]:
    """Derive the account identity of a Codex access token (D-id).

    Returns the JWT ``sub`` claim when ``access_token`` is a well-formed
    three-segment base64url JWT issued by ``https://auth.openai.com`` carrying a
    non-empty ``sub``; returns ``None`` otherwise. An undecodable, opaque, or
    foreign-issuer token has no identity we may act on, so callers must
    conservatively skip (or populate-empty-only).

    Nothing is persisted; the identity is derived live from the in-hand token
    and used only to gate cross-store writes.
    """
    claims = _decode_jwt_claims(access_token)
    if not claims:
        return None
    if claims.get("iss") != _CODEX_OAUTH_ISSUER:
        return None
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        return None
    return sub.strip()


def _write_through_codex_to_global_root(
    tokens: Dict[str, str],
    last_refresh: Optional[str] = None,
    label: Optional[str] = None,
) -> Optional[bool]:
    """Identity-gated best-effort write of a Codex chain to the global root.

    Mirrors the full field set the just-completed save wrote to the active
    store — ``tokens``, ``last_refresh``, ``auth_mode="chatgpt"``, ``label`` —
    onto the root ``providers.openai-codex`` state, preserving root-only fields
    and leaving ``active_provider`` untouched. Alias/independent pool entries
    are re-classified against ROOT's pre-save snapshot and updated in place only
    (labels/ids/priorities/suppressed_sources untouched).

    Return tri-state so the caller can distinguish the three outcome classes:

    * ``True``  — the root store now durably holds the chain (written now);
    * ``False`` — a distinct root exists and the write was attempted but failed
      (the caller decides the log level: CLASS-D warning or CLASS-N critical);
    * ``None``  — not applicable: classic / same-path, the pytest seat belt, or
      the D-id identity gate refused the write (a conservative silent skip).

    Never raises.
    """
    # Late-bind origin helpers so ``hermes_cli.auth.<name>`` patches intercept
    # (module-split convention, see this file's docstring).
    from hermes_cli.auth import (_auth_file_path, _auth_store_lock, _global_auth_file_path,
                                 _load_auth_store, _same_path, _save_auth_store,
                                 _sync_codex_pool_entries)
    root_path = _global_auth_file_path()
    if root_path is None:
        return None
    if _same_path(root_path, _auth_file_path()):
        return None
    # pytest seat belt: refuse to write the real user's $HOME/.hermes/auth.json
    # (mirrors _load_global_auth_store and the xAI write-through guard).
    if os.environ.get("PYTEST_CURRENT_TEST"):
        real_home_env = os.environ.get("HOME", "")
        if real_home_env:
            real_root = Path(real_home_env) / ".hermes" / "auth.json"
            try:
                if root_path.resolve(strict=False) == real_root.resolve(strict=False):
                    return None
            except Exception:
                return None
    try:
        with _auth_store_lock(target_path=root_path):
            root_store = _load_auth_store(root_path)
            providers = root_store.setdefault("providers", {})
            if not isinstance(providers, dict):
                providers = {}
                root_store["providers"] = providers
            root_state = providers.get("openai-codex")
            root_state = dict(root_state) if isinstance(root_state, dict) else {}
            root_tokens = root_state.get("tokens")
            root_tokens = dict(root_tokens) if isinstance(root_tokens, dict) else {}
            root_has_credentials = bool(
                str(root_tokens.get("access_token", "") or "").strip()
                or str(root_tokens.get("refresh_token", "") or "").strip()
            )
            if root_has_credentials:
                our_identity = _codex_token_identity(tokens.get("access_token"))
                root_identity = _codex_token_identity(root_tokens.get("access_token"))
                if our_identity is None or root_identity is None or our_identity != root_identity:
                    # D-id gate: different (or undecodable) account — leave root
                    # untouched rather than clobber a foreign login.
                    return None
            previous_singleton_tokens = dict(root_tokens) if root_tokens else None
            mirrored = dict(root_state)  # preserve root-only fields
            mirrored["tokens"] = dict(tokens)
            mirrored["last_refresh"] = last_refresh or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            mirrored["auth_mode"] = "chatgpt"
            if label and str(label).strip():
                mirrored["label"] = str(label).strip()
            providers["openai-codex"] = mirrored
            _sync_codex_pool_entries(
                root_store,
                tokens,
                mirrored["last_refresh"],
                previous_singleton_tokens=previous_singleton_tokens,
            )
            _save_auth_store(root_store, target_path=root_path)
        return True
    except Exception as exc:
        logger.debug("Codex OAuth: root write-through failed: %s", exc)
        return False


def _save_codex_tokens(tokens: Dict[str, str], last_refresh: str = None, label: str = None) -> None:
    """Save Codex OAuth tokens to Hermes auth store (~/.hermes/auth.json)."""
    from hermes_cli.auth import (
        _auth_store_lock, _load_auth_store, _load_provider_state, _save_auth_store,
        _save_provider_state, _sync_codex_pool_entries, _utc_now_z)
    if last_refresh is None:
        last_refresh = _utc_now_z()
    with _auth_store_lock():
        auth_store = _load_auth_store()
        state = _load_provider_state(auth_store, "openai-codex") or {}
        # Capture the previous singleton tokens BEFORE overwriting: the pool sync uses them to
        # tell legacy singleton-aliases (refresh) from independent ``auth add`` accounts (keep).
        previous_singleton_tokens = (
            state.get("tokens") if isinstance(state.get("tokens"), dict) else None)
        state.update(tokens=tokens, last_refresh=last_refresh, auth_mode="chatgpt")
        if label and str(label).strip():
            state["label"] = str(label).strip()
        _save_provider_state(auth_store, "openai-codex", state)
        _sync_codex_pool_entries(
            auth_store, tokens, last_refresh, previous_singleton_tokens=previous_singleton_tokens)
        _save_auth_store(auth_store)
    # C1 — root write-through (best-effort). The active store already durably
    # holds the chain, so a root-sync failure here is CLASS-D (self-healing):
    # log a WARNING and let the next save resync root.
    from hermes_cli.auth import _auth_file_path, _global_auth_file_path, _same_path
    root_path = _global_auth_file_path()
    if root_path is not None and not _same_path(root_path, _auth_file_path()):
        if _write_through_codex_to_global_root(tokens, last_refresh, label) is False:
            logger.warning(
                "Codex OAuth: rotated chain saved to the profile store but the "
                "global-root write-through failed; the next save will retry the "
                "root sync (self-healing)."
            )


def _recover_codex_tokens_from_cli(reason: str) -> Optional[Dict[str, str]]:
    """Adopt a valid Codex CLI token pair into Hermes auth, if available."""
    from hermes_cli.auth import _import_codex_cli_tokens, _save_codex_tokens
    imported = _import_codex_cli_tokens()
    # Require BOTH tokens before adopting: persisting a payload without a usable refresh_token
    # would only break the next refresh cycle.
    if not (imported and _stripped(imported.get("access_token"))
            and _stripped(imported.get("refresh_token"))):
        return None
    logger.info("Codex auth recovered from Codex CLI auth.json (%s).", reason)
    _save_codex_tokens(imported)
    return dict(imported)


def _refresh_payload_access_token(
    response: "httpx.Response", *, provider: str, invalid_json: Tuple[str, str],
    invalid_response: Optional[Tuple[str, str]], missing_access: Tuple[str, str],
    relogin_required: bool = True, invalid_json_relogin: Optional[bool] = None,
    strict_str: bool = True) -> Tuple[Dict[str, Any], str]:
    """Parse a 200 token-refresh response; return ``(payload, stripped access_token)``.

    Each ``(message, code)`` pair keeps the provider's historical wording; ``{exc}`` in
    *invalid_json*'s message is formatted with the JSON error. *strict_str* rejects non-string
    access tokens; otherwise they are ``str()``-coerced.
    """
    def _err(message: str, code: str, relogin: bool = relogin_required) -> AuthError:
        return AuthError(message, provider=provider, code=code, relogin_required=relogin)

    try:
        payload = response.json()
    except Exception as exc:
        relogin = relogin_required if invalid_json_relogin is None else invalid_json_relogin
        raise _err(invalid_json[0].format(exc=exc), invalid_json[1], relogin) from exc
    if not isinstance(payload, dict):
        if invalid_response is not None:
            raise _err(*invalid_response)
        payload = {}
    access = payload.get("access_token")
    if strict_str:
        access = access.strip() if isinstance(access, str) else ""
    else:
        access = _stripped(access)
    if not access:
        raise _err(*missing_access)
    return payload, access


def _codex_login_post(url: str, *, failure: Tuple[str, str], **kwargs: Any) -> "httpx.Response":
    """One 15s POST for the device-login flow; transport errors become ``_codex_err(*failure)``."""
    try:
        with _codex_http_client(timeout=httpx.Timeout(15.0)) as client:
            return client.post(url, **kwargs)
    except Exception as exc:
        raise _codex_err(f"{failure[0]}: {exc}", failure[1])


def _codex_http_client(**kwargs: Any) -> "httpx.Client":
    """Build an ``httpx.Client`` for Codex OAuth/probe endpoints with Happy-Eyeballs racing.

    A host advertising AAAA records but blackholing IPv6 makes each serial connect eat the full
    timeout before IPv4 is tried (same failure mode as the chat transport). Best-effort: if the
    racing backend can't be installed (mocked client in tests), serial connect behavior remains.

    Same broken-IPv6 failure mode as the chat transport (#13834): a host that advertises AAAA records but
    blackholes IPv6 makes each serial connect attempt eat the full connect timeout before IPv4 is tried, so
    token refresh / device login / usage probes time out where the official Codex CLI (which races families
    per RFC 8305) works.
    """
    client = httpx.Client(**kwargs)
    with suppress(Exception):
        from agent.process_bootstrap import enable_happy_eyeballs_on_client
        enable_happy_eyeballs_on_client(client)
    return client


def _codex_quota_exhausted_error(retry_after: Optional[int]) -> AuthError:
    message = (
        f"Codex provider quota exhausted (429); retry after {retry_after}s. "
        "Credentials are still valid."
        if retry_after is not None else
        "Codex provider quota exhausted (429). Credentials are still valid; "
        "retry after the usage limit resets.")
    return _codex_err(message, CODEX_RATE_LIMITED_CODE, relogin=False)


def _codex_refresh_failure_error(response: "httpx.Response") -> AuthError:
    """Decode a non-200 Codex token-refresh response into a shaped AuthError."""
    from hermes_cli.auth import _nonempty_str
    code = "codex_refresh_failed"
    message = f"Codex token refresh failed with status {response.status_code}."
    try:
        err = response.json()
        if isinstance(err, dict):
            err_obj = err.get("error")
            # OpenAI shape: {"error": {"code": "...", "message": "...", "type": "..."}}
            if isinstance(err_obj, dict):
                nested_code = err_obj.get("code") or err_obj.get("type")
                if _nonempty_str(nested_code):
                    code = nested_code.strip()
                nested_msg = err_obj.get("message")
                if _nonempty_str(nested_msg):
                    message = f"Codex token refresh failed: {nested_msg.strip()}"
            # OAuth spec shape: {"error": "code_str", "error_description": "..."}
            elif _nonempty_str(err_obj):
                code = err_obj.strip()
                err_desc = err.get("error_description") or err.get("message")
                if _nonempty_str(err_desc):
                    message = f"Codex token refresh failed: {err_desc.strip()}"
    except Exception:
        pass
    if code == "refresh_token_reused":
        message = (
            "Codex refresh token was already consumed by another client "
            "(e.g. Codex CLI or VS Code extension). "
            "Run `codex` in your terminal to generate fresh tokens, "
            "then run `hermes auth` to re-authenticate.")
    # A 401/403 from the token endpoint always means the refresh token is invalid/expired —
    # force relogin even if the body error code wasn't one of the known strings.
    relogin_required = (
        code in {"invalid_grant", "invalid_token", "invalid_request", "refresh_token_reused"}
        or response.status_code in {401, 403})
    return _codex_err(message, code, relogin=relogin_required)


def refresh_codex_oauth_pure(
    access_token: str, refresh_token: str, *, timeout_seconds: float = 20.0) -> Dict[str, Any]:
    """Refresh Codex OAuth tokens without mutating Hermes auth state."""
    from hermes_cli.auth import _nonempty_str, _utc_now_z
    del access_token  # Access token is only used by callers to decide whether to refresh.
    if not _nonempty_str(refresh_token):
        raise _codex_err(
            _MISSING_REFRESH_TOKEN_MSG, "codex_auth_missing_refresh_token", relogin=True)
    with _codex_http_client(
        timeout=httpx.Timeout(max(5.0, float(timeout_seconds))),
        headers={"Accept": "application/json", "User-Agent": CODEX_OAUTH_USER_AGENT}) as client:
        response = client.post(
            CODEX_OAUTH_TOKEN_URL, headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "refresh_token", "refresh_token": refresh_token,
                "client_id": CODEX_OAUTH_CLIENT_ID})
    if response.status_code == 429:
        # Quota exhaustion on the token endpoint: the refresh token is still valid and re-auth
        # cannot lift a quota cap, so classify distinctly from auth failures ("retry later").
        raise _codex_quota_exhausted_error(
            _parse_retry_after_seconds(getattr(response, "headers", None)))
    if response.status_code != 200:
        raise _codex_refresh_failure_error(response)
    refresh_payload, refreshed_access = _refresh_payload_access_token(
        response, provider="openai-codex", invalid_response=None,
        invalid_json=("Codex token refresh returned invalid JSON.", "codex_refresh_invalid_json"),
        missing_access=(
            "Codex token refresh response was missing access_token.",
            "codex_refresh_missing_access_token"))
    updated = {
        "access_token": refreshed_access, "refresh_token": refresh_token.strip(),
        "last_refresh": _utc_now_z()}
    next_refresh = refresh_payload.get("refresh_token")
    if _nonempty_str(next_refresh):
        updated["refresh_token"] = next_refresh.strip()
    return updated


def _refresh_codex_auth_tokens(
    tokens: Dict[str, str],
    timeout_seconds: float,
) -> Dict[str, str]:
    """Refresh Codex access token using the refresh token.

    Saves the new tokens to Hermes auth store automatically.
    """
    # Late-bind origin helpers so ``hermes_cli.auth.<name>`` patches intercept
    # (module-split convention, see this file's docstring).
    from hermes_cli.auth import (_auth_file_path, _auth_store_lock, _global_auth_file_path,
                                 _load_auth_store, _load_provider_state_with_source,
                                 _recover_codex_tokens_from_cli, _same_path, _save_codex_tokens,
                                 _write_through_codex_to_global_root, refresh_codex_oauth_pure)
    # C2 — resolve the caller's token source ONCE at entry (a single read,
    # before any HTTP work). A root-resolved reader must persist its rotation
    # directly to root (never seeding a shadowing profile block); an owned-block
    # caller keeps the ordinary ``_save_codex_tokens`` path (C1 write-throughs).
    auth_store = _load_auth_store()
    _state, source_path = _load_provider_state_with_source(auth_store, "openai-codex")
    global_root = _global_auth_file_path()
    is_from_root = bool(
        source_path is not None
        and global_root is not None
        and _same_path(source_path, global_root)
    )
    # Top-level mode: the active store IS the global root (a single file). A
    # root-resolved reader here must persist directly to that same store —
    # never through the distinct-store write-through helper, which no-ops on a
    # same-path root and would fall into CLASS-N retries (F1).
    top_level_root = bool(
        global_root is not None
        and _same_path(global_root, _auth_file_path())
    )

    def _persist_class_n(persist_fn, what: str) -> None:
        # CLASS-N durability (shared by the C2 direct-root and C3-owned
        # persistence steps — see A1v10): no durable copy of the rotated chain
        # exists yet, so retry ``persist_fn`` (truthy on a durable write;
        # raising or falsy on failure) with bounded fixed backoff; on
        # persistent failure log CRITICAL naming a manual re-auth (the
        # refreshed tokens are still handed to the caller — loud, not silent).
        for attempt in range(_CODEX_ROOT_PERSIST_ATTEMPTS):
            try:
                if persist_fn():
                    return  # OUTCOME-SUCCESS (silent)
            except Exception as exc:
                logger.debug(
                    "Codex OAuth %s persistence attempt %d failed: %s",
                    what, attempt + 1, exc,
                )
            if attempt < _CODEX_ROOT_PERSIST_ATTEMPTS - 1:
                time.sleep(_CODEX_ROOT_PERSIST_BACKOFF_SECONDS[attempt])
        logger.critical(
            "Codex OAuth: could not persist the rotated token chain %s after "
            "%d attempts — no durable copy exists. Run `hermes model` to "
            "re-authenticate manually.",
            what, _CODEX_ROOT_PERSIST_ATTEMPTS,
        )

    try:
        refreshed = refresh_codex_oauth_pure(
            str(tokens.get("access_token", "") or ""),
            str(tokens.get("refresh_token", "") or ""),
            timeout_seconds=timeout_seconds,
        )
    except AuthError as exc:
        # Self-heal cross-store refresh_token rotation. Hermes keeps its OWN
        # Codex OAuth token (per profile + top-level), separate from the Codex
        # CLI's ~/.codex/auth.json. OAuth refresh_tokens are single-use, so when
        # the Codex CLI (or another Hermes process) rotates the shared token,
        # this frozen copy's refresh_token goes stale and the refresh fails with
        # a relogin-required error (invalid_grant / refresh_token_reused / 401).
        # Before surfacing that as a hard 401 to the turn, recover automatically
        # instead of 401'ing until a manual re-auth. Transient failures (e.g.
        # 429 quota) keep relogin_required=False — the stored token is still
        # valid there, so we never self-heal those and re-raise unchanged.
        if not getattr(exc, "relogin_required", False):
            raise
        # C3 — root reuse-rescue: before falling back to ~/.codex CLI recovery,
        # adopt a fresher sibling chain held by the global root (another profile
        # already rotated the shared token) so this caller self-heals silently.
        dead_tuple = (
            str(tokens.get("access_token", "") or ""),
            str(tokens.get("refresh_token", "") or ""),
        )
        rescued: Optional[Dict[str, str]] = None
        root_path = _global_auth_file_path()
        if root_path is not None and not _same_path(root_path, _auth_file_path()):
            # pytest seat belt: never read/write the real user's root store.
            seat_belted = False
            if os.environ.get("PYTEST_CURRENT_TEST"):
                real_home_env = os.environ.get("HOME", "")
                if real_home_env:
                    real_root = Path(real_home_env) / ".hermes" / "auth.json"
                    try:
                        seat_belted = root_path.resolve(strict=False) == real_root.resolve(strict=False)
                    except Exception:
                        seat_belted = True
            our_identity = _codex_token_identity(tokens.get("access_token"))
            if not seat_belted and our_identity is not None:
                try:
                    with _auth_store_lock(target_path=root_path):
                        # Atomic seen-set check-and-mark INSIDE the held lock.
                        if dead_tuple not in _codex_root_rescue_seen:
                            root_store = _load_auth_store(root_path)
                            root_state = (root_store.get("providers") or {}).get("openai-codex")
                            root_state = dict(root_state) if isinstance(root_state, dict) else {}
                            root_tokens = root_state.get("tokens")
                            root_tokens = dict(root_tokens) if isinstance(root_tokens, dict) else {}
                            root_refresh = str(root_tokens.get("refresh_token", "") or "").strip()
                            root_identity = _codex_token_identity(root_tokens.get("access_token"))
                            eligible = bool(
                                root_refresh
                                and root_refresh != str(tokens.get("refresh_token", "") or "").strip()
                                and root_identity == our_identity
                            )
                            if eligible:
                                # Mark attempted BEFORE the adoption POST
                                # (regardless of its outcome).
                                _codex_root_rescue_seen.add(dead_tuple)
                                try:
                                    adopted_refresh = refresh_codex_oauth_pure(
                                        str(root_tokens.get("access_token", "") or ""),
                                        root_refresh,
                                        timeout_seconds=timeout_seconds,
                                    )
                                except Exception:
                                    adopted_refresh = None
                                if adopted_refresh is not None:
                                    adopted = dict(root_tokens)
                                    adopted["access_token"] = adopted_refresh["access_token"]
                                    adopted["refresh_token"] = adopted_refresh["refresh_token"]
                                    if is_from_root:
                                        _persist_class_n(
                                            lambda: _write_through_codex_to_global_root(adopted, None, None) is True,
                                            "to the global root",
                                        )
                                    else:
                                        # CLASS-N (owned): the local save after a
                                        # successful rescue POST is the only durable
                                        # copy — retry it through the shared backoff
                                        # loop before CRITICAL (A1v10: 3 attempts /
                                        # 2 backoffs).
                                        _persist_class_n(
                                            lambda: (_save_codex_tokens(adopted) or True),
                                            "to the profile store",
                                        )
                                    rescued = adopted
                except Exception:
                    rescued = None
        if rescued is not None:
            return rescued
        imported = _recover_codex_tokens_from_cli(
            f"refresh_token rejected: {getattr(exc, 'code', None) or 'auth_error'}"
        )
        if not imported:
            raise
        return imported

    updated_tokens = dict(tokens)
    updated_tokens["access_token"] = refreshed["access_token"]
    updated_tokens["refresh_token"] = refreshed["refresh_token"]

    if is_from_root and not top_level_root:
        # C2 — persist the rotation directly to the distinct root; do NOT seed
        # a shadowing profile block (C1 write-through covers only owned-block
        # callers).
        _persist_class_n(
            lambda: _write_through_codex_to_global_root(updated_tokens, None, None) is True,
            "to the global root",
        )
    else:
        # Owned-block caller, or top-level mode (the active store IS the root):
        # ``_save_codex_tokens`` persists to the active store, and its C1
        # write-through already skips a same-path root.
        _save_codex_tokens(updated_tokens)
    return updated_tokens


def _import_codex_cli_tokens() -> Optional[Dict[str, str]]:
    """Read ~/.codex/auth.json (Codex CLI file) tokens if valid and not expired; never writes."""
    from hermes_cli.auth import _codex_access_token_is_expiring
    codex_home = os.getenv("CODEX_HOME", "").strip() or str(Path.home() / ".codex")
    auth_path = Path(codex_home).expanduser() / "auth.json"
    if not auth_path.is_file():
        return None
    try:
        tokens = json.loads(auth_path.read_text(encoding="utf-8-sig")).get("tokens")
        if not (isinstance(tokens, dict) and tokens.get("access_token")
                and tokens.get("refresh_token")):
            return None
        # Importing stale tokens that can't be refreshed would leave the user with
        # "Login successful!" but no working credentials.
        if _codex_access_token_is_expiring(tokens["access_token"], 0):
            logger.debug("Codex CLI tokens at %s are expired — skipping import.", auth_path)
            return None
        return dict(tokens)
    except Exception:
        return None


def resolve_codex_runtime_credentials(
    *, force_refresh: bool = False, refresh_if_expiring: bool = True,
    refresh_skew_seconds: int = CODEX_ACCESS_TOKEN_REFRESH_SKEW_SECONDS) -> Dict[str, Any]:
    """Resolve runtime credentials from Hermes's own Codex token store.

    Falls back to the credential pool when the singleton (``providers.openai-codex.tokens``) has no
    usable access_token but the pool (``credential_pool.openai-codex``) does.

    This closes the divergence between the chat path (singleton-only via this function) and the auxiliary
    path (pool-first via ``_read_codex_access_token``). Without this fallback, a user whose tokens live only
    in the pool — for example after a manual pool seed, a partial re-auth, or pool-only restoration from a
    backup — gets a bare HTTP 401 ``Missing Authentication header`` from the wire instead of a usable
    credential. See issue #32992.
    """
    from hermes_cli.auth import (
        _auth_store_lock, _codex_access_token_is_expiring, _probe_codex_quota_restored,
        _read_codex_tokens)
    read_error: Optional[AuthError] = None
    data = None
    try:
        data = _read_codex_tokens()
    except AuthError as exc:
        read_error = exc
        if exc.relogin_required and exc.code in {
            "codex_auth_missing_access_token", "codex_auth_missing_refresh_token",
            "codex_auth_invalid_shape"}:
            imported = _recover_codex_tokens_from_cli(str(exc.code or "auth_error"))
            if imported:
                data = {"tokens": imported, "last_refresh": imported.get("last_refresh")}
    if data is None:
        pool_token = _pool_codex_access_token()
        if pool_token:
            return _codex_runtime_result(pool_token, source="credential_pool", last_refresh=None)
        pool_rate_limit = _codex_pool_rate_limit_status()
        if pool_rate_limit:
            # Before surfacing the persisted cooldown, ask the usage endpoint whether the quota
            # reset early (banked reset redeemed, plan upgraded): ``last_error_reset_at`` can be
            # days in the future while the account is already usable again.
            stale_token = _stripped(pool_rate_limit.get("access_token"))
            if stale_token and _probe_codex_quota_restored(
                stale_token, base_url=pool_rate_limit.get("base_url")):
                logger.info("Codex quota restored upstream — clearing stale pool cooldown(s).")
                clear_codex_pool_quota_cooldowns()
                pool_token = _pool_codex_access_token()
                if pool_token:
                    return _codex_runtime_result(
                        pool_token, source="credential_pool", last_refresh=None)
            reset_at = pool_rate_limit.get("reset_at")
            in_future = isinstance(reset_at, (int, float)) and reset_at > time.time()
            raise _codex_quota_exhausted_error(int(reset_at - time.time()) if in_future else None)
        if read_error is not None:
            raise read_error
        raise _codex_err(_NO_CREDENTIALS_MSG, "codex_auth_missing", relogin=True)
    tokens = dict(data["tokens"])
    access_token = _stripped(tokens.get("access_token"))
    refresh_timeout_seconds = env_float("HERMES_CODEX_REFRESH_TIMEOUT_SECONDS", 20)

    def _should_refresh(token: str) -> bool:
        return bool(force_refresh) or (
            refresh_if_expiring and _codex_access_token_is_expiring(token, refresh_skew_seconds))

    if _should_refresh(access_token):
        # Re-read under lock to avoid racing with other Hermes processes
        lock_timeout = max(float(AUTH_LOCK_TIMEOUT_SECONDS), refresh_timeout_seconds + 5.0)
        with _auth_store_lock(timeout_seconds=lock_timeout):
            data = _read_codex_tokens(_lock=False)
            tokens = dict(data["tokens"])
            if _should_refresh(_stripped(tokens.get("access_token"))):
                tokens = _refresh_codex_auth_tokens(tokens, refresh_timeout_seconds)
            access_token = _stripped(tokens.get("access_token"))
    return _codex_runtime_result(
        access_token, source="hermes-auth-store", last_refresh=data.get("last_refresh"))


def _is_codex_rate_limit_shaped(code: Any, reason: Any, message: Any) -> bool:
    """True when persisted pool-entry error metadata describes a 429/quota stop."""
    reason_l, message_l = str(reason or "").lower(), str(message or "").lower()
    return (
        code == 429
        or any(k in reason_l for k in ("rate_limit", "usage_limit", "quota"))
        or any(k in message_l for k in ("rate limit", "usage limit", "quota")))


def _entry_is_rate_limit_exhausted(entry: Dict[str, Any]) -> bool:
    """Pool entry frozen by a 429/quota stop (as opposed to an auth failure)."""
    return entry.get("last_status") == "exhausted" and _is_codex_rate_limit_shaped(
        entry.get("last_error_code"), entry.get("last_error_reason"),
        entry.get("last_error_message"))


# Throttle for the live Codex quota probe. It runs on the hot credential-selection path while the
# pool is exhausted, so without a floor a busy gateway would hammer the usage endpoint per call.
CODEX_QUOTA_PROBE_MIN_INTERVAL_SECONDS = 300  # 5 minutes
_codex_quota_probe_cache: Dict[str, Tuple[float, Optional[bool]]] = {}
_codex_quota_probe_lock = threading.Lock()


def _codex_usage_probe_url(base_url: Optional[str]) -> str:
    """Resolve the Codex usage endpoint for a probe.

    Mirrors the Codex CLI's PathStyle split: base URLs containing ``/backend-api`` use the ChatGPT
    ``/wham/usage`` path, everything else ``/api/codex/usage``. Kept local so this low-level auth
    module does not import the auxiliary account-usage module.
    """
    normalized = _stripped(base_url).rstrip("/") or _codex_base_url()
    if normalized.endswith("/codex"):
        normalized = normalized[: -len("/codex")]
    prefix = normalized + ("/wham" if "/backend-api" in normalized else "/api/codex")
    return prefix + "/usage"


def _probe_codex_quota_restored(
    access_token: Any, *, base_url: Optional[str] = None,
    min_interval_seconds: float = CODEX_QUOTA_PROBE_MIN_INTERVAL_SECONDS) -> Optional[bool]:
    """Ask the Codex usage endpoint whether this account's quota is usable again.

    Probes are throttled per access token (module-local cache) so the hot selection path can fire
    this freely.
    """
    from hermes_cli.auth import _codex_quota_probe_cache, _nonempty_str
    token = _stripped(access_token)
    # Real Codex access tokens are JWTs. Refusing to probe non-JWT tokens avoids pointless
    # network calls for corrupt/placeholder entries (and keeps hermetic test fixtures offline).
    if not token or not _decode_jwt_claims(token):
        return None
    cache_key = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
    now = time.monotonic()
    with _codex_quota_probe_lock:
        cached = _codex_quota_probe_cache.get(cache_key)
        if cached is not None and (now - cached[0]) < min_interval_seconds:
            return cached[1]
        # Reserve the slot immediately so concurrent selectors don't stampede the endpoint.
        _codex_quota_probe_cache[cache_key] = (now, None)
    result: Optional[bool] = None
    try:
        headers = {
            "Authorization": f"Bearer {token}", "Accept": "application/json",
            "User-Agent": "codex-cli"}
        # Best-effort ChatGPT-Account-Id from the JWT (required for some account shapes).
        auth_claims = _decode_jwt_claims(token).get("https://api.openai.com/auth")
        account_id = (
            auth_claims.get("chatgpt_account_id") if isinstance(auth_claims, dict) else None)
        if _nonempty_str(account_id):
            headers["ChatGPT-Account-Id"] = account_id.strip()
        with _codex_http_client(timeout=10.0) as client:
            response = client.get(_codex_usage_probe_url(base_url), headers=headers)
        if response.status_code == 200:
            rate_limit = (response.json() or {}).get("rate_limit") or {}
            worst_used: Optional[float] = None
            for key in ("primary_window", "secondary_window"):
                used = (rate_limit.get(key) or {}).get("used_percent")
                if isinstance(used, (int, float)):
                    worst_used = max(worst_used or 0.0, float(used))
            if worst_used is not None:
                result = worst_used < 100.0
        elif response.status_code == 429:
            result = False
    except Exception:
        logger.debug("Codex quota probe failed", exc_info=True)
        result = None
    with _codex_quota_probe_lock:
        _codex_quota_probe_cache[cache_key] = (now, result)
    return result


def clear_codex_pool_quota_cooldowns(access_token: Optional[str] = None) -> int:
    """Clear rate-limit cooldowns on persisted openai-codex pool entries.

    Called after the upstream quota is KNOWN to be restored (a ``/usage reset`` redemption or a
    positive live probe) so auth.json stops freezing credentials behind a stale
    ``last_error_reset_at``. With *access_token* only the matching entry clears; otherwise every
    rate-limited entry does (a redeemed banked reset restores the whole account; a still-exhausted
    entry just re-freezes with fresh metadata on its next 429).
    """
    from hermes_cli.auth import _auth_store_lock, _load_auth_store, _save_auth_store
    cleared = 0
    try:
        with _auth_store_lock():
            auth_store = _load_auth_store()
            entries = _pool_entries(auth_store, "openai-codex")
            if entries is None:
                return 0
            for entry in _codex_pool_dicts(entries):
                if access_token and str(entry.get("access_token") or "") != access_token:
                    continue
                if _entry_is_rate_limit_exhausted(entry):
                    _clear_pool_entry_status(entry)
                    cleared += 1
            if cleared:
                _save_auth_store(auth_store)
    except Exception:
        logger.debug("Failed to clear Codex pool quota cooldowns", exc_info=True)
    return cleared


def _codex_pool_dicts(entries: Optional[List[Any]]) -> Iterator[Dict[str, Any]]:
    for entry in entries or ():
        if isinstance(entry, dict):
            yield entry


def _read_codex_pool_entries() -> Optional[List[Any]]:
    """Locked read of ``credential_pool.openai-codex`` from auth.json (None when absent)."""
    from hermes_cli.auth import _auth_store_lock, _load_auth_store
    with _auth_store_lock():
        auth_store = _load_auth_store()
    return _pool_entries(auth_store, "openai-codex")


def _codex_pool_rate_limit_status() -> Optional[Dict[str, Any]]:
    """Return metadata for a pool-only Codex credential in quota cooldown."""
    from hermes_cli.auth import _nonempty_str
    from agent.credential_pool import _parse_absolute_timestamp
    try:
        now = time.time()
        for entry in _codex_pool_dicts(_read_codex_pool_entries()):
            token = entry.get("access_token")
            if not _nonempty_str(token) or not _entry_is_rate_limit_exhausted(entry):
                continue
            reset_at = _parse_absolute_timestamp(entry.get("last_error_reset_at"))
            if reset_at is None or reset_at > now:
                return {
                    "label": entry.get("label"), "last_refresh": entry.get("last_refresh"),
                    "reset_at": reset_at, "reason": entry.get("last_error_reason"),
                    "message": entry.get("last_error_message"), "access_token": token.strip(),
                    "base_url": entry.get("base_url")}
    except Exception:
        logger.debug("Codex pool rate-limit lookup failed", exc_info=True)
    return None


def _pool_entries(auth_store: Dict[str, Any], provider_id: str) -> Optional[List[Any]]:
    """``auth_store["credential_pool"][provider_id]`` when it is a list, else None."""
    pool = auth_store.get("credential_pool")
    entries = pool.get(provider_id) if isinstance(pool, dict) else None
    return entries if isinstance(entries, list) else None


def _pool_codex_access_token() -> str:
    """First non-empty pool access_token not in an exhaustion cooldown window, else "".

    Fallback for ``resolve_codex_runtime_credentials`` when the singleton has no creds.
    """
    from hermes_cli.auth import _nonempty_str
    try:
        for entry in _codex_pool_dicts(_read_codex_pool_entries()):
            token, reset_at = entry.get("access_token"), entry.get("last_error_reset_at")
            in_cooldown = isinstance(reset_at, (int, float)) and reset_at > time.time()
            if _nonempty_str(token) and not in_cooldown:
                return token.strip()
    except Exception:
        logger.debug("Codex pool fallback lookup failed", exc_info=True)
    return ""


def _login_openai_codex(args, pconfig: ProviderConfig, *, force_new_login: bool = False) -> None:
    """OpenAI Codex login via device code flow. Tokens stored in ~/.hermes/auth.json."""
    from hermes_cli.auth import (
        _codex_access_token_is_expiring, _codex_device_code_login, _import_codex_cli_tokens,
        _offer_existing_oauth_credentials, _print_login_success, _prompt_yes_no, _save_codex_tokens,
        _update_config_for_provider, resolve_codex_runtime_credentials)
    del args, pconfig  # kept for parity with other provider login helpers
    if not force_new_login:
        if _offer_existing_oauth_credentials(
            "openai-codex", resolve=resolve_codex_runtime_credentials,
            is_expiring=_codex_access_token_is_expiring, display_name="Codex",
            default_base_url=DEFAULT_CODEX_BASE_URL,
            expired_notice="Existing Codex credentials are expired. Starting fresh login..."):
            return
        cli_tokens = _import_codex_cli_tokens()
        if cli_tokens:
            print("Found existing Codex CLI credentials at ~/.codex/auth.json")
            print("Hermes will create its own session to avoid conflicts with Codex CLI / VS Code.")
            if _prompt_yes_no(
                "Import these credentials? (a separate login is recommended) [y/N]: ", default="n"):
                _save_codex_tokens(cli_tokens)
                config_path = _update_config_for_provider("openai-codex", _codex_base_url())
                print()
                print("Credentials imported. Note: if Codex CLI refreshes its token,")
                print("Hermes will keep working independently with its own session.")
                print(f"  Config updated: {config_path} (model.provider=openai-codex)")
                return

    # Run a fresh device code flow — Hermes gets its own OAuth session
    print()
    print("Signing in to OpenAI Codex...")
    print("(Hermes creates its own session — won't affect Codex CLI or VS Code)")
    print()
    creds = _codex_device_code_login()
    _save_codex_tokens(creds["tokens"], creds.get("last_refresh"))
    config_path = _update_config_for_provider(
        "openai-codex", creds.get("base_url", DEFAULT_CODEX_BASE_URL))
    _print_login_success("openai-codex", config_path, show_auth_state=True)


def _codex_login_rate_limited_error(response: "httpx.Response", *, during: str = "") -> AuthError:
    """AuthError for a 429 from OpenAI's device-auth endpoints (throttle, not credential fault)."""
    # Upstream rate-limit / usage-quota exhaustion on the token endpoint. The stored refresh token is still
    # valid here — re-authenticating cannot lift a quota cap. Classify distinctly from auth failures so
    # callers surface a "retry later" notice instead of a misleading "run hermes auth" prompt (see issue
    # #32790).
    retry_after = _parse_retry_after_seconds(getattr(response, "headers", None))
    wait_hint = (
        f" Try again in about {retry_after}s." if retry_after is not None
        else " Wait a minute and run the login again.")
    return _codex_err(
        f"OpenAI is rate-limiting Codex login requests (HTTP 429){during}. "
        f"This is a temporary throttle on OpenAI's side, not a credential problem.{wait_hint}",
        CODEX_RATE_LIMITED_CODE)


def _codex_request_device_code(issuer: str, client_id: str) -> Dict[str, Any]:
    """Step 1 of the Codex device flow: request a user code, retrying capped on HTTP 429.

    OpenAI rate-limits this request when login is attempted too often from one IP/account — retry
    with capped backoff (honoring ``Retry-After``) before surfacing an actionable message.
    """
    max_attempts = 4
    for attempt in range(1, max_attempts + 1):
        resp = _codex_login_post(
            f"{issuer}/api/accounts/deviceauth/usercode", json={"client_id": client_id},
            headers={"Content-Type": "application/json"},
            failure=("Failed to request device code", "device_code_request_failed"))
        if resp.status_code != 429:
            break
        if attempt < max_attempts:
            # Exponential backoff (2s, 4s, 8s) capped, preferring the server's Retry-After.
            retry_after = _parse_retry_after_seconds(getattr(resp, "headers", None))
            delay = max(1, min(int(retry_after if retry_after is not None else 2 ** attempt), 60))
            print(f"OpenAI is rate-limiting login requests (429); retrying in {delay}s...")
            time.sleep(delay)
    if resp.status_code == 429:
        raise _codex_login_rate_limited_error(resp)
    if resp.status_code != 200:
        raise _codex_err(
            f"Device code request returned status {resp.status_code}.", "device_code_request_error")
    device_data = resp.json()
    device_data["interval"] = max(3, int(device_data.get("interval", "5")))
    if not device_data.get("user_code", "") or not device_data.get("device_auth_id", ""):
        raise _codex_err("Device code response missing required fields.", "device_code_incomplete")
    return device_data


def _codex_poll_authorization_code(
    issuer: str, *, device_auth_id: str, user_code: str, poll_interval: int) -> Dict[str, Any]:
    """Step 3 of the Codex device flow: poll until sign-in completes (403/404 = still pending)."""
    max_wait = 15 * 60  # 15 minutes
    start = time.monotonic()
    code_resp = None
    try:
        with _codex_http_client(timeout=httpx.Timeout(15.0)) as client:
            while time.monotonic() - start < max_wait:
                time.sleep(poll_interval)
                poll_resp = client.post(
                    f"{issuer}/api/accounts/deviceauth/token",
                    json={"device_auth_id": device_auth_id, "user_code": user_code},
                    headers={"Content-Type": "application/json"})
                if poll_resp.status_code == 200:
                    code_resp = poll_resp.json()
                    break
                if poll_resp.status_code not in {403, 404}:  # 403/404 = user hasn't finished yet
                    raise _codex_err(
                        f"Device auth polling returned status {poll_resp.status_code}.",
                        "device_code_poll_error")
    except KeyboardInterrupt:
        print("\nLogin cancelled.")
        raise SystemExit(130)
    if code_resp is None:
        raise _codex_err("Login timed out after 15 minutes.", "device_code_timeout")
    return code_resp


def _codex_exchange_authorization_code(
    issuer: str, client_id: str, code_resp: Dict[str, Any]) -> Dict[str, Any]:
    """Step 4 of the Codex device flow: swap the authorization code for tokens."""
    authorization_code = code_resp.get("authorization_code", "")
    code_verifier = code_resp.get("code_verifier", "")
    if not authorization_code or not code_verifier:
        raise _codex_err(
            "Device auth response missing authorization_code or code_verifier.",
            "device_code_incomplete_exchange")
    token_resp = _codex_login_post(
        CODEX_OAUTH_TOKEN_URL,
        data={
            "grant_type": "authorization_code", "code": authorization_code,
            "redirect_uri": f"{issuer}/deviceauth/callback", "client_id": client_id,
            "code_verifier": code_verifier},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        failure=("Token exchange failed", "token_exchange_failed"))
    if token_resp.status_code == 429:
        raise _codex_login_rate_limited_error(token_resp, during=" during token exchange")
    if token_resp.status_code != 200:
        raise _codex_err(
            f"Token exchange returned status {token_resp.status_code}.", "token_exchange_error")
    tokens = token_resp.json()
    if not tokens.get("access_token", ""):
        raise _codex_err(
            "Token exchange did not return an access_token.", "token_exchange_no_access_token")
    return tokens


def _codex_device_code_login() -> Dict[str, Any]:
    """Run the OpenAI device code login flow and return credentials dict."""
    from hermes_cli.auth import _utc_now_z
    issuer, client_id = "https://auth.openai.com", CODEX_OAUTH_CLIENT_ID
    device_data = _codex_request_device_code(issuer, client_id)
    user_code = device_data["user_code"]

    # Step 2: Show user the code
    print("To continue, follow these steps:\n")
    print("  1. Open this URL in your browser:")
    print(f"     \033[94m{issuer}/codex/device\033[0m\n")
    print("  2. Enter this code:")
    print(f"     \033[94m{user_code}\033[0m\n")
    print("Waiting for sign-in... (press Ctrl+C to cancel)")
    code_resp = _codex_poll_authorization_code(
        issuer, device_auth_id=device_data["device_auth_id"], user_code=user_code,
        poll_interval=device_data["interval"])
    tokens = _codex_exchange_authorization_code(issuer, client_id, code_resp)
    # Return tokens for the caller to persist (never writes to ~/.codex/)
    return {
        "tokens": {
            "access_token": tokens.get("access_token", ""),
            "refresh_token": tokens.get("refresh_token", "")},
        "base_url": _codex_base_url(), "last_refresh": _utc_now_z(), "auth_mode": "chatgpt",
        "source": "device-code"}
