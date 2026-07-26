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
| `2ebeff608` (rebase of `99d7adcae` onto `origin/main`@`48bdde1de`) + `4af9b13ed` (pyproject.toml pin bump, separate commit) | Hindsight plugin: `recall_min_scores` relevance floor + `prefer_observations` flag (dormant). Combines our PR #71122 with `prefer_observations` cherry-picked from #64914. Full design history: `/srv/personal/vault/90-system/2026-07-25--hindsight-client-upgrade-runbook.md` | [#71122](https://github.com/NousResearch/hermes-agent/pull/71122) (ours) + [#64914](https://github.com/NousResearch/hermes-agent/pull/64914) (prefer_observations only) | OPEN (2026-07-26) | `pytest tests/plugins/memory/test_hindsight_provider.py` — should show 141+ passing (was 137 pre-rebase; upstream added its own BOM/.env-encoding test classes in the same file, hence the higher floor now) | 2026-07-26 (rebase); **gateway restart + live recall verification COMPLETE 2026-07-26** — restarted (PID 902326), fresh logs clean (no hindsight errors/version-guard warnings), live positive/negative recall control against hermes-default bank confirmed working end-to-end. |

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
