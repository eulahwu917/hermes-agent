import { beforeEach, describe, expect, it } from 'vitest'

import {
  $attentionItems,
  $attentionOpenCount,
  $attentionSyncState,
  beginAttentionRequest,
  commitAttentionItems,
  currentAttentionScopeToken,
  isAttentionRequestCurrent,
  markAttentionStale,
  parseAttentionItems,
  resetAttention
} from '@/store/attention'
import type { AttentionItem } from '@/types/hermes'

function item(overrides: Partial<AttentionItem> = {}): AttentionItem {
  return {
    kind: 'cron_incident',
    id: 'zz-tes_abc123',
    source: 'cron',
    severity: 'warning',
    title: 'zz-test job',
    body_excerpt: 'boom',
    first_seen_at: '2026-09-08T00:00:00',
    last_seen_at: '2026-09-08T01:00:00',
    state: 'open',
    acked_at: null,
    ...overrides
  }
}

beforeEach(() => {
  resetAttention()
})

describe('parseAttentionItems', () => {
  it('accepts a valid list and rejects malformed payloads fail-closed', () => {
    expect(parseAttentionItems([item()])).toEqual([item()])
    expect(parseAttentionItems(null)).toBeNull()
    expect(parseAttentionItems({ items: [] })).toBeNull()
    expect(parseAttentionItems([{ ...item(), state: 'bogus' }])).toBeNull()
    expect(parseAttentionItems([{ ...item(), kind: 'banana' }])).toBeNull()
    expect(parseAttentionItems([{ ...item(), severity: 'fatal' }])).toBeNull()
    expect(parseAttentionItems([{ ...item(), id: '' }])).toBeNull()
    // alert_event shape with producer/alert_type is valid.
    expect(
      parseAttentionItems([
        item({ kind: 'alert_event', source: 'alpharelay', producer: 'p', alert_type: 'a' })
      ])
    ).not.toBeNull()
  })
})

describe('attention sync state', () => {
  it('commit publishes live items; open count derives from the live list', () => {
    const token = beginAttentionRequest()
    expect(commitAttentionItems(token, [item(), item({ state: 'closed', id: 'zz-tes_x' })])).toBe(true)
    expect($attentionSyncState.get()).toBe('live')
    expect($attentionItems.get()).toHaveLength(2)
    expect($attentionOpenCount.get()).toBe(1)
  })

  it('stale responses never overwrite newer intent; a stale commit is dropped', () => {
    const first = beginAttentionRequest()
    const second = beginAttentionRequest()
    expect(isAttentionRequestCurrent(first)).toBe(false)
    expect(commitAttentionItems(first, [item()])).toBe(false)
    expect(commitAttentionItems(second, [item()])).toBe(true)
    expect($attentionItems.get()).toHaveLength(1)
  })

  it('failure marks stale and never reads as an empty healthy list', () => {
    commitAttentionItems(beginAttentionRequest(), [item()])
    markAttentionStale()
    expect($attentionSyncState.get()).toBe('stale')
    // Last-known items are retained so the UI can render rows + a stale notice.
    expect($attentionItems.get()).toHaveLength(1)
  })

  it('a scope reset drops an in-flight read: a late pre-switch response cannot restore live', () => {
    const token = beginAttentionRequest()
    resetAttention() // profile/connection switch
    expect(commitAttentionItems(token, [item()])).toBe(false)
    expect($attentionItems.get()).toHaveLength(0)
    expect($attentionSyncState.get()).toBe('loading')
  })

  it('a scope reset invalidates the ack scope: a late pre-switch ack cannot act as the new scope', () => {
    const scope = currentAttentionScopeToken()
    resetAttention()
    expect(currentAttentionScopeToken()).not.toBe(scope)
  })
})
