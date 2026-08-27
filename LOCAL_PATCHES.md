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
| `2ebeff608` (rebase of `99d7adcae` onto `origin/main`@`48bdde1de`) + `4af9b13ed` (pyproject.toml pin bump, separate commit) | Hindsight plugin: `recall_min_scores` relevance floor + `prefer_observations` flag (dormant). Combines our PR #71122 with `prefer_observations` cherry-picked from #64914. Full design history: `/srv/personal/vault/90-system/2026-07-25--hindsight-client-upgrade-runbook.md` | [#71122](https://github.com/NousResearch/hermes-agent/pull/71122) (ours) + [#64914](https://github.com/NousResearch/hermes-agent/pull/64914) (prefer_observations only) | OPEN (2026-07-30) — teknium1 left changes-requested review (version pin leak, non-finite float acceptance, stale README). Comment posted acknowledging all 3, supporting consolidation on #64914 as canonical. All three fixes already applied locally. | `pytest tests/plugins/memory/test_hindsight_provider.py` — should show 141+ passing (was 137 pre-rebase; upstream added its own BOM/.env-encoding test classes in the same file, hence the higher floor now) | 2026-07-26 (rebase); **gateway restart + live recall verification COMPLETE 2026-07-26** — restarted (PID 902326), fresh logs clean (no hindsight errors/version-guard warnings), live positive/negative recall control against hermes-default bank confirmed working end-to-end. PR status re-verified 2026-07-30. |
| `c114011ca` | Hindsight plugin: error formatting fix — 3 tool error handlers now include `{type(e).__name__}: {e}` instead of bare `{e}` (which produced blank messages for TimeoutError). Retain handler adds TimeoutError-specific guidance to verify via recall before retrying. `_DEFAULT_TIMEOUT` comment updated to reference config.json override path. Also: `"timeout": 300` set in `~/.hermes/hindsight/config.json` (profile-scoped, no code change). Full design history: `/srv/personal/vault/90-system/runbooks/2026-08-17--vault-hindsight-improvement-runbook.md` | Local custom patch (not for upstream) | N/A — local only | `py_compile plugins/memory/hindsight/__init__.py` — passes. `grep -n "type(e).__name__"` — 3 matches. | 2026-08-18 — live checkout patched, config.json timeout:300 active. Gateway restart needed for full effect (timeout read at init). |
| UPSTREAM CANDIDATE → **CARRIED 2026-08-27**: PR [#95984](https://github.com/NousResearch/hermes-agent/pull/95984) (ours) fixes #87503 — Codex OAuth singleton root write-through + root-resolved direct-write + reuse-rescue (C1/C2/C3), closing the weekly multi-profile refresh_token_reused family-death cycle diagnosed 2026-08-26/27. Carried as THREE cherry-picked commits (`22dfbc3dc` = rebase of f9fb9b812+9bedf6211+918590a3c chain) on local main; 27/27 module tests + full codex/auth sweep green on live checkout (with `HERMES_T18_EXTRA_NONPROD` env listing sibling-patch files for T18's budget pin). Built from spec v11 (11 Reviewer rounds, APPROVED t_1d6b461e); source branch preserved in `/srv/repos/hermes-agent-codexoauth`. **GATEWAY RESTART STILL PENDING** — runtime uses the new code only after hermes-gateway restart (kills active sessions; schedule off-hours). Upstream merge will retire this row per standard procedure. | [#95984](https://github.com/NousResearch/hermes-agent/pull/95984) | OPEN (PR includes remediation + test-hardening commits) | pytest tests/agent/test_codex_singleton_write_through.py (27/27 w/ HERMES_T18_EXTRA_NONPROD set); full codex/auth sweep | 2026-08-27 |

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
