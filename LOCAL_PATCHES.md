# Locally-carried patches on `main`

This file tracks every commit we carry locally on top of `origin/main` that
isn't (yet) merged upstream. **Check this file — and re-verify each entry's
merge status — before running `hermes update`.** A plain `git pull --ff-only`
will fail cleanly if any of these are still unmerged (it won't silently drop
them), but the update won't proceed until you rebase, so know what you're
carrying before you start.

## Update procedure when entries exist below

1. Read this file. For each entry, run `gh pr view <PR#> --repo NousResearch/hermes-agent --json state,mergedAt`.
2. **If merged:** drop the local commit — `git rebase` will skip/fail-empty on it
   once the equivalent content is in `origin/main`; remove its row from this file.
3. **If still open:** `git fetch origin main && git rebase origin/main` — this
   replays the commit on top of the new tip. Re-run whatever test suite the
   commit's own description calls for (see "Verify" column) before trusting the
   rebase succeeded silently — a clean rebase doesn't guarantee the patch's tests
   still pass against new upstream code.
4. Update this file's "Last verified" date after any check, even if nothing changed.

## Currently carried

| Commit (short) | What it does | Upstream PR | PR status (last checked) | Verify before trusting | Last verified |
|---|---|---|---|---|---|
| `8b8aa83726` (2026-09-06 rebase of `dabfce2275` onto `origin/main`@`693641aa8b`) + `e187c1bbc5` (pyproject.toml pin bump) | Hindsight plugin: `recall_min_scores` relevance floor + `prefer_observations` flag (dormant). Combines our PR #71122 with `prefer_observations` cherry-picked from #64914. Full design history: `/srv/personal/vault/90-system/2026-07-25--hindsight-client-upgrade-runbook.md`. **2026-09-06 re-home (0.21.0):** upstream moved constants/normalizers into `plugins/memory/hindsight/settings.py` and compacted the tool handlers into `_tool_*` + a generic dispatch — `_normalize_min_scores`/`_VALID_MIN_SCORE_KEYS` now live in `settings.py`; recall wiring sits in `_recall()` (single arecall site); thread-routing override re-homed to the end of `_apply_recall_settings()`. | [#71122](https://github.com/NousResearch/hermes-agent/pull/71122) (ours) + [#64914](https://github.com/NousResearch/hermes-agent/pull/64914) (prefer_observations only) | OPEN (re-verified 2026-09-06) — teknium1 left changes-requested review (version pin leak, non-finite float acceptance, stale README). Comment posted acknowledging all 3, supporting consolidation on #64914 as canonical. All three fixes already applied locally. | `pytest tests/plugins/memory/test_hindsight_provider.py` — **107/107 passing (2026-09-06, post-0.21.0 rebase**; count dropped because upstream split/rewrote many tests, not coverage loss). Test imports re-homed to the settings module. | 2026-09-06 (rebase + full suite); gateway restart + live recall verified 2026-07-26; PR status re-verified 2026-09-06. **Gateway restart pending again for this 0.21.0 rebase.** |
| `53803419ba` | Hindsight plugin: error formatting fix — 3 tool error handlers now include `{type(e).__name__}: {e}` instead of bare `{e}` (which produced blank messages for TimeoutError). Retain handler adds TimeoutError-specific guidance to verify via recall before retrying. `_DEFAULT_TIMEOUT` comment updated to reference config.json override path. Also: `"timeout": 300` set in `~/.hermes/hindsight/config.json` (profile-scoped, no code change). **2026-09-06 re-home (0.21.0):** the three tool error handlers collapsed into the generic `handle_tool_call` dispatch — the `type(e).__name__` prefix + TimeoutError retain-guidance now live there (one site covers all three tools); the `_DEFAULT_TIMEOUT` comment moved to `settings.py`. Full design history: `/srv/personal/vault/90-system/runbooks/2026-08-17--vault-hindsight-improvement-runbook.md` | Local custom patch (not for upstream) | N/A — local only | `py_compile plugins/memory/hindsight/__init__.py` — passes. `grep -n "type(e).__name__" hermes_cli/../plugins/memory/hindsight/__init__.py` — 1 match (generic dispatch). Suite green. | 2026-09-06 (rebase); original verification 2026-08-18. |
| UPSTREAM CANDIDATE → **CARRIED 2026-08-27**: PR [#95984](https://github.com/NousResearch/hermes-agent/pull/95984) (ours) fixes #87503 — Codex OAuth singleton root write-through + root-resolved direct-write + reuse-rescue (C1/C2/C3), closing the weekly multi-profile refresh_token_reused family-death cycle diagnosed 2026-08-26/27. Carried as THREE commits (`768ce70431` + `955df99641` + `2282d7f634` = 2026-09-06 rebase of the f9fb9b812+9bedf6211+918590a3c chain onto `origin/main`@`693641aa8b`) on local main; **2026-09-06 re-home (0.21.0): upstream split auth.py (~9.5k lines) into auth_codex.py/auth_constants.py/etc. — the implementation now lives in `hermes_cli/auth_codex.py` with late-bound `from hermes_cli.auth import ...` inside each function (module convention, so `monkeypatch.setattr(A, ...)` still intercepts); `hermes_cli/auth.py` gained the re-export lines; T18's structural pin + test file re-homed to `auth_codex.py`**; 27/27 module tests + full codex/auth sweep green on live checkout (with `HERMES_T18_EXTRA_NONPROD` env listing sibling-patch files for T18's budget pin). Built from spec v11 (11 Reviewer rounds, APPROVED t_1d6b461e); source branch preserved in `/srv/repos/hermes-agent-codexoauth`. **GATEWAY RESTART: CONFIRMED LIVE 2026-08-30** — restart happened 2026-08-27 20:23 (after the Aug 26 patch commits landed on local main); process ancestry + zero `refresh_token_reused` errors in all gateway logs since Aug 27 verified. Earlier "restart still pending" note was stale (missed the Aug 27 restart). Upstream merge will retire this row per standard procedure. | [#95984](https://github.com/NousResearch/hermes-agent/pull/95984) | OPEN (re-verified 2026-09-06; PR includes remediation + test-hardening commits) | `pytest tests/agent/test_codex_singleton_write_through.py` — **27/27 (2026-09-06)** w/ HERMES_T18_EXTRA_NONPROD set to the full carried-file list; `pytest tests/agent/ -k "codex or auth"` — 721 passed / 2 skipped (2 optional-SDK failures fixed by installing pinned `anthropic==0.87.0` extra; then 54/54). | 2026-09-06 |
| `303550f5dc` (2026-09-06 rebase of `f0a0e67281`) | T19 ghost-cwd local-backend guard: `_resolve_command_cwd()` ignores a recorded session cwd whose directory no longer exists (env_type == "local" only) and falls back to default_cwd — sessions self-heal instead of dying with exit 126 on every bare terminal call after their Kanban worktree is deleted. Container backends stay under `_is_unusable_container_cwd`; remote backends deliberately not probed locally. +6 tests (`test_ghost_cwd_fallback.py`), `test_terminal_task_cwd.py` fixture made physically real. Diagnosed 2026-09-01 (6+ affected sessions Aug 31–Sep 1, 3 deleted worktrees); Reviewer APPROVED t_446a36c8 (mutation A+B probes corrected per review); upstream comment posted on [#62169](https://github.com/NousResearch/hermes-agent/issues/62169#issuecomment-5503371494) (complementary to stalled #62189). | [#100823](https://github.com/NousResearch/hermes-agent/pull/100823) (ours) | OPEN (opened 2026-09-01, awaiting upstream review) | `HERMES_PYTHON=venv/bin/python scripts/run_tests.sh tests/tools/test_ghost_cwd_fallback.py tests/tools/test_terminal_task_cwd.py tests/tools/test_session_cwd_store.py tests/tools/test_container_cwd_sanitize.py tests/tools/test_interrupted_command_cwd.py -q` → **44/44 (2026-09-06**; was 42/42 — upstream added 2 cases to the same files); `grep -c 'and env_type == "local"' tools/terminal_tool.py` → 1 | 2026-09-06 (rebase); original diagnosis/verification 2026-09-01. **GATEWAY RESTART PENDING** — the running gateway still has the pre-fix code in memory (ghost-cwd sessions self-heal via the workaround in kanban-dispatch-and-polling references/polling-details.md until then); restart off-hours per T18 precedent. |

## 2026-09-06 rebase notes (0.20.5 → 0.21.0, +7,564 upstream commits)

- **Architecture changes that forced re-homes:** hindsight constants/normalizers →
  `plugins/memory/hindsight/settings.py`; tool handlers → compact `_tool_*` methods +
  generic `handle_tool_call` dispatch; single `_recall()`/`_reflect()` helpers (one arecall
  site, not two); `hermes_cli/auth.py` (~9.5k lines) → split into `auth_codex.py`,
  `auth_constants.py`, `auth_xai.py`, etc., with `auth.py` keeping lazy re-exports.
- **Updater trap unchanged:** `update_cmd.py` still executes `git reset --hard origin/main`
  when the checkout is on the update-target branch and ff-only fails (same-branch divergence
  = our permanent state). Manual rebase per this file's procedure remains REQUIRED; never
  run bare `hermes update` while carrying commits.
- All four upstream PRs re-verified OPEN 2026-09-06 via `gh pr view`.
- Pre-update safety artifacts: branch `backup/pre-update-20260906` +
  `/srv/personal/scratch/hermes-agent-pre-update-20260906.bundle` (534MB full bundle).
- Config migrated 38 → 41 (`hermes config migrate`); update-check caches cleared.

## Retired (for history — merged upstream, no longer carried)

_(none yet)_

## Note on the shallow-clone artifact — RESOLVED 2026-07-26

Our local checkout of `~/.hermes/hermes-agent` **was** a shallow clone (repeated
`--depth 1` fetches had left `.git/shallow` with multiple synthetic boundary commits,
including `4281151ae`). This caused `git merge-base main origin/main` to return nothing
and made a routine 2-file rebase surface as hundreds of add/add conflicts across the
entire tree. Fixed via `git fetch --unshallow origin` (2026-07-26) — `merge-base` now
correctly resolves to `4281151ae` as expected. If a future `merge-base`/`is-ancestor`
check against `origin/main` fails unexpectedly again, check `git rev-parse
--is-shallow-repository` first before assuming real history divergence — nothing
currently re-shallows this clone, but a `--depth` fetch by a future script or fresh
clone could reintroduce this.
