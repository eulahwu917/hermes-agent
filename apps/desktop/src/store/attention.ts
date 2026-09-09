import { atom, computed } from 'nanostores'

import type { AttentionItem } from '@/types/hermes'

// Live state for the unified Attention read model (cron.manage list_attention).
// The backend is authoritative: this store is a cache of that truth. It must
// never present an empty list as healthy unless the last fetch actually
// succeeded — on any failure the sync state goes 'stale' and surfaces keep
// last-known items + an explicit stale notice (never a green "all clear").
export type AttentionSyncState = 'loading' | 'live' | 'stale'

export const $attentionItems = atom<AttentionItem[]>([])
export const $attentionSyncState = atom<AttentionSyncState>('loading')

let attentionRequestGeneration = 0
// Ack scope: an ack targets the backend/profile whose rows the user clicked.
// Only a SCOPE teardown (resetAttention — profile/connection switch) bumps this;
// read-generation churn (polls, stale marks) must never invalidate an in-flight
// ack, or a concurrent refresh would turn a successful ack into a false failure.
let attentionScopeToken = 0

export function beginAttentionRequest(): number {
  attentionRequestGeneration += 1

  return attentionRequestGeneration
}

export function isAttentionRequestCurrent(token: number): boolean {
  return token === attentionRequestGeneration
}

/** Authoritative snapshot landed: consume the token and publish. */
export function commitAttentionItems(token: number, items: AttentionItem[]): boolean {
  if (!isAttentionRequestCurrent(token)) {
    return false
  }

  attentionRequestGeneration += 1
  $attentionItems.set(items)
  $attentionSyncState.set('live')

  return true
}

/** A read/ack failure (or an invalid payload): never interpret as empty. */
export function markAttentionStale(): void {
  attentionRequestGeneration += 1
  $attentionSyncState.set('stale')
}

/** The current scope token; an ack started under this token belongs to the backend/
 *  profile it was clicked against. */
export function currentAttentionScopeToken(): number {
  return attentionScopeToken
}

/** Scope teardown (profile/connection switch): reset to the pre-first-fetch state AND
 *  invalidate the scope — in-flight reads from the previous backend/profile are dropped
 *  (a late A response can never restore live under B), and an in-flight ack is rejected
 *  rather than being allowed to act as the new scope's mutation. */
export function resetAttention(): void {
  attentionRequestGeneration += 1
  attentionScopeToken += 1
  $attentionItems.set([])
  $attentionSyncState.set('loading')
}

export const $attentionOpenCount = computed($attentionItems, items =>
  items.reduce((count, item) => (item.state === 'open' ? count + 1 : count), 0)
)

// ─── Wire-item validation (fail closed: garbage is never rendered as healthy) ──────────────

const KINDS = new Set(['cron_incident', 'alert_event'])
const STATES = new Set(['open', 'closed'])
const SEVERITIES = new Set(['critical', 'warning', 'info'])

function validAttentionItem(value: unknown): value is AttentionItem {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false
  }

  const item = value as Partial<AttentionItem>

  return (
    typeof item.kind === 'string' &&
    KINDS.has(item.kind) &&
    typeof item.id === 'string' &&
    item.id.length > 0 &&
    typeof item.source === 'string' &&
    typeof item.severity === 'string' &&
    SEVERITIES.has(item.severity) &&
    typeof item.title === 'string' &&
    typeof item.body_excerpt === 'string' &&
    typeof item.state === 'string' &&
    STATES.has(item.state)
  )
}

/** null when the payload is not a valid attention list (caller marks stale). */
export function parseAttentionItems(value: unknown): AttentionItem[] | null {
  if (!Array.isArray(value)) {
    return null
  }

  if (!value.every(validAttentionItem)) {
    return null
  }

  return value as AttentionItem[]
}
