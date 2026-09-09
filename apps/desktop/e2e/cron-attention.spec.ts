/**
 * Spec §3.4 cases 8–11 — Cron Attention in the Desktop UI (E2), against the REAL
 * `hermes serve` backend (mock LLM, real tui_gateway → cron.attention code path).
 *
 *  case 8: Attention section renders a seeded incident (name/sig/timestamps/excerpt);
 *          [View output] opens the exact output_file in the right rail; [Ack] removes
 *          the row within one refresh cycle.
 *  case 9: nav badge derived from the LIVE list — visible with ≥1 open item, absent
 *          after ack (never a stale cache).
 *  case 10: cross-process refresh — `hermes cron incidents ack <id>` from a separate
 *          process while the app is open; the app reflects the closure ≤ one backstop
 *          period, driven by the attention.changed sentinel.
 *  case 11: RPC unavailable (serve killed) → explicit stale/error state; never an
 *          empty list; the nav badge is not silently green.
 */

import { spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'

import {
  type MockBackendFixture,
  setupMockBackend,
  waitForAppReady
} from './fixtures'
import { allowErrorBanners, expect, test } from './test'

const DESKTOP_ROOT = path.resolve(import.meta.dirname, '..')
const REPO_ROOT = path.resolve(DESKTOP_ROOT, '..', '..')

// The attention backstop the UI polls on (use-background-sync.ts). Case 10 must
// converge within one backstop period of a cross-process CLI ack.
const ATTENTION_BACKSTOP_MS = 30_000

// Case 8: file-only content seeded beyond the bounded row excerpt — visible ONLY in
// the [View output] preview rail.
const PREVIEW_ONLY_MARKER = 'zz-test-e2e preview-only payload beyond excerpt'

let fixture: MockBackendFixture | null = null

test.beforeAll(async () => {
  fixture = await setupMockBackend()
  await waitForAppReady(fixture!, 120_000)
})

test.afterAll(async () => {
  await fixture?.cleanup()
  fixture = null
})

// ─── Python/CLI helpers (mirror the desktop's own runtime resolution ladder) ─────

function resolvePython(): string {
  const candidates = [
    path.join(REPO_ROOT, 'venv', 'bin', 'python'),
    path.join(REPO_ROOT, '.venv', 'bin', 'python'),
    path.join(os.homedir(), '.hermes', 'hermes-agent', 'venv', 'bin', 'python'),
  ]
  const found = candidates.find(candidate => fs.existsSync(candidate))
  return found ?? 'python3'
}

function hermesHomeEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    HERMES_HOME: fixture!.sandbox.hermesHome,
    PYTHONPATH: REPO_ROOT,
  }
}

function runHermesPython(script: string, args: string[] = []): { status: number; stdout: string; stderr: string } {
  const result = spawnSync(resolvePython(), ['-c', script, ...args], {
    cwd: REPO_ROOT,
    env: hermesHomeEnv(),
    encoding: 'utf8',
    timeout: 60_000,
  })
  return { status: result.status ?? -1, stdout: String(result.stdout ?? ''), stderr: String(result.stderr ?? '') }
}

const SEED_SCRIPT = `
import sys
from pathlib import Path

from cron import jobs as cron_jobs
from cron.incidents import upsert_incident

output_file = Path(sys.argv[1])
output_file.parent.mkdir(parents=True, exist_ok=True)
# The marker sits BEYOND the 201-char excerpt bound the row renders: it is the
# file-only payload that proves the [View output] rail rendered the exact file
# (a no-op View handler can never surface it).
output_file.write_text(
    "zz-test-e2e payload line one\\npayload line two\\n"
    + ("padding " * 40)
    + "\\nzz-test-e2e preview-only payload beyond excerpt\\n")

job_id = "zz-test-e2e-job"
cron_jobs.save_jobs(cron_jobs.load_jobs() + [{
    "id": job_id,
    "name": "zz-test-e2e watchdog",
    "prompt": None,
    "no_agent": True,
    "script": "/nonexistent-zz-test",
    "schedule": {"kind": "interval", "minutes": 5, "display": "every 5m"},
    "enabled": True,
    "state": "scheduled",
    "deliver": "local",
}])
incident_id, is_new = upsert_incident(
    job_id, "zz-test-e2e unique error text", job_name="zz-test-e2e watchdog",
    output_file=str(output_file))
print(incident_id)
assert is_new
`

/** Seed one isolated zz-test incident + its output file inside the sandbox home. */
function seedAttention(outputName: string): { incidentId: string; outputPath: string } {
  const outputPath = path.join(fixture!.sandbox.hermesHome, 'cron', 'output', 'zz-test-e2e', outputName)
  const result = runHermesPython(SEED_SCRIPT, [outputPath])
  expect(result.status, `seed failed: ${result.stderr}`).toBe(0)
  const incidentId = result.stdout.trim().split('\n').pop()?.trim() ?? ''
  expect(incidentId.length).toBeGreaterThan(0)
  return { incidentId, outputPath }
}

function runCliAck(incidentId: string): { status: number; stdout: string; stderr: string } {
  const result = spawnSync(resolvePython(), ['-m', 'hermes_cli.main', 'cron', 'incidents', 'ack', incidentId], {
    cwd: REPO_ROOT,
    env: hermesHomeEnv(),
    encoding: 'utf8',
    timeout: 60_000,
  })
  return { status: result.status ?? -1, stdout: String(result.stdout ?? ''), stderr: String(result.stderr ?? '') }
}

async function openScheduledJobsPage() {
  const page = fixture!.page
  // The cron page is a full-window overlay that intercepts pointer events over the
  // sidebar nav — close it first when a previous test left it open.
  const closeButton = page.getByRole('button', { name: 'Close cron' }).first()
  if (await closeButton.isVisible().catch(() => false)) {
    await closeButton.click()
  }
  // The sidebar "Scheduled jobs" nav item (nav.cron).
  await page.getByRole('button', { name: /Scheduled jobs/ }).first().click()
  // The Attention section header is the proof the cron page mounted.
  await page.getByText('Attention', { exact: true }).first().waitFor({ state: 'visible', timeout: 30_000 })
}

// ─── case 8 — UI renders + ack ─────────────────────────────────────────────────

test('case8: Attention section renders seeded incident; View output opens the file; Ack removes the row', async () => {
  const page = fixture!.page
  seedAttention('case8-output.md')

  await openScheduledJobsPage()

  // Row: job name, error signature, timestamps, excerpt. The excerpt's required
  // source is the OUTPUT FILE — distinct file content vs the inserted error text,
  // so the payload line (file-only) must appear in the row and the error text
  // (DB-only, seeded distinctly) must NOT.
  const row = page.locator('[data-attention-row]').filter({ hasText: 'zz-test-e2e watchdog' }).first()
  await row.waitFor({ state: 'visible', timeout: 30_000 })
  await expect(row).toContainText('zz-test-e2e watchdog')
  await expect(row).toContainText('zz-test-e2e payload line one')
  await expect(row).not.toContainText('zz-test-e2e unique error text')
  await expect(row).toContainText('First seen')
  await expect(row).toContainText('Last seen')

  // The excerpt is BOUNDED: the file-only marker beyond the excerpt bound must NOT
  // appear in the row — any later sighting of it can only come from the preview rail.
  await expect(row).not.toContainText(PREVIEW_ONLY_MARKER)
  // And the marker is nowhere on the page yet: the click is what must surface it.
  await expect(page.getByText(PREVIEW_ONLY_MARKER).first()).toBeHidden()

  // [View output] opens the EXACT output file in the right rail: the preview tab is
  // labelled with the file's basename, and the pane renders the file content — the
  // beyond-excerpt marker is the file-only proof a disabled/no-op View handler cannot
  // fake (the old assertion searched text already visible IN the row).
  await row.getByRole('button', { name: 'View output' }).click()
  await expect(page.getByRole('tab', { name: 'case8-output.md' })).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText(PREVIEW_ONLY_MARKER).first()).toBeVisible({ timeout: 30_000 })

  // [Ack] removes the row within one refresh cycle.
  await row.getByRole('button', { name: 'Ack' }).click()
  await expect(
    page.locator('[data-attention-row]').filter({ hasText: 'zz-test-e2e watchdog' }).first()
  ).toBeHidden({ timeout: ATTENTION_BACKSTOP_MS + 10_000 })
})

// ─── case 9 — badge derived from the live list ─────────────────────────────────

test('case9: nav badge visible with an open item, absent after ack', async () => {
  const page = fixture!.page
  const { incidentId } = seedAttention('case9-output.md')

  await openScheduledJobsPage()
  await page
    .locator('[data-attention-row]')
    .filter({ hasText: 'zz-test-e2e watchdog' })
    .first()
    .waitFor({ state: 'visible', timeout: 30_000 })

  // The badge derives from the LIVE attention list (the store commit behind this
  // page's fetch), not a stale cache.
  const cronNav = page.getByRole('button', { name: /Scheduled jobs/ }).first()
  const badge = cronNav.locator('[data-attention-nav-badge]').filter({ hasText: '1' }).first()
  await badge.waitFor({ state: 'visible', timeout: 10_000 })

  // Ack from a fresh process (the CLI path — same as case 10's channel), then the
  // badge must clear within one refresh cycle via attention.changed — no page
  // interaction, no cached value.
  const ack = runCliAck(incidentId)
  expect(ack.status, `cli ack failed: ${ack.stderr}`).toBe(0)
  await expect(
    cronNav.locator('[data-attention-nav-badge]').filter({ hasText: '1' }).first()
  ).toBeHidden({ timeout: ATTENTION_BACKSTOP_MS + 10_000 })
  // And the stale marker must not appear — this is the healthy all-clear.
  await expect(page.locator('[data-stale-attention-indicator]')).toHaveCount(0)
})

// ─── case 10 — cross-process refresh within one backstop period ────────────────

test('case10: CLI ack while the app is open reflects the closure ≤ one backstop period', async () => {
  const page = fixture!.page
  const { incidentId } = seedAttention('case10-output.md')

  await openScheduledJobsPage()
  const row = page.locator('[data-attention-row]').filter({ hasText: 'zz-test-e2e watchdog' }).first()
  await row.waitFor({ state: 'visible', timeout: 30_000 })

  const startedAt = Date.now()
  const ack = runCliAck(incidentId)
  expect(ack.status, `cli ack failed: ${ack.stderr}`).toBe(0)

  // No restart, no click: the app reflects the cross-process closure via
  // attention.changed (sentinel) with the interval backstop as the worst case.
  // The oracle IS the declared backstop period — a +10s allowance would let a
  // contract violation pass.
  await expect(row).toBeHidden({ timeout: ATTENTION_BACKSTOP_MS })
  const elapsed = Date.now() - startedAt
  expect(elapsed).toBeLessThanOrEqual(ATTENTION_BACKSTOP_MS)

  // The sentinel itself moved — that is the cross-process signal the change
  // watcher broadcast.
  const sentinel = path.join(fixture!.sandbox.hermesHome, 'cron', 'attention.changed')
  expect(fs.existsSync(sentinel), 'CLI ack must touch cron/attention.changed').toBe(true)
})

// ─── case 11 — stale-not-empty on failure (run LAST: it kills the serve) ───────

test('case11: RPC unavailable shows explicit stale state, never an empty healthy list', async () => {
  // Deliberate backend kill → expected error banners (backend-stopped toast + the
  // stale-state alert itself). The guard must not treat the state under test as a bug.
  allowErrorBanners()

  const page = fixture!.page
  seedAttention('case11-output.md')

  await openScheduledJobsPage()
  await page
    .locator('[data-attention-row]')
    .filter({ hasText: 'zz-test-e2e watchdog' })
    .first()
    .waitFor({ state: 'visible', timeout: 30_000 })

  // Kill the serve the app talks to (resolve its ephemeral port from the live
  // connection, then terminate the listener).
  const wsUrl = await page.evaluate(async () => {
    const desktop = (window as unknown as { hermesDesktop?: { getConnection: (profile?: string | null) => Promise<{ wsUrl?: string }> } })
      .hermesDesktop
    if (!desktop) {
      return null
    }
    const conn = await desktop.getConnection(null)
    return conn?.wsUrl ?? null
  })
  expect(wsUrl).toBeTruthy()
  const port = new URL(wsUrl as string).port
  const killed = spawnSync('fuser', ['-k', '-TERM', `${port}/tcp`], { encoding: 'utf8' })
  // fuser exit 1 = no process found; anything else with output means a signal went out.
  expect(killed.status === 0 || killed.stdout.trim().length > 0).toBe(true)

  // NO synthetic visibility/focus nudges: the stale state must be driven by the
  // socket drop itself (the open → non-open transition marks the store stale), not
  // by a test-injected refresh that would mask that wiring. Poll fast and passive.
  const deadline = Date.now() + ATTENTION_BACKSTOP_MS + 15_000
  let staleSection = false
  let staleBadge = false
  while (Date.now() < deadline && !(staleSection && staleBadge)) {
    staleSection = await page
      .locator('[role="alert"]')
      .filter({ hasText: /Attention unavailable/ })
      .first()
      .isVisible()
      .catch(() => false)
    staleBadge = (await page.locator('[data-stale-attention-indicator]').count()) > 0
    if (!(staleSection && staleBadge)) {
      await page.waitForTimeout(250)
    }
  }

  // The specific Attention states: the section's explicit stale alert AND the nav's
  // stale indicator (the green badge is gone). Snapshot the negatives in the same
  // observation so a later self-heal cannot retroactively green the assertion.
  expect(staleSection, 'the Attention section must show its explicit stale state after the socket drop').toBe(true)
  expect(staleBadge, 'the nav badge must flip to the stale indicator, never stay silently green').toBe(true)
  expect(await page.locator('[data-attention-nav-badge]').count()).toBe(0)
  expect(await page.getByText('No open attention items').first().count()).toBe(0)
})
