import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { GatewayRequester } from '@/app/contrib/types'
import {
  $attentionItems,
  $attentionSyncState,
  beginAttentionRequest,
  commitAttentionItems,
  resetAttention
} from '@/store/attention'
import type { AttentionItem } from '@/types/hermes'

import { ackAttentionItem, AttentionScopeChangedError, refreshAttention } from './attention-actions'

function wireItem(overrides: Partial<AttentionItem> = {}): AttentionItem {
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

const requestGatewayMock = vi.fn()
const requestGateway = requestGatewayMock as unknown as GatewayRequester

beforeEach(() => {
  resetAttention()
  requestGatewayMock.mockReset()
})

describe('refreshAttention', () => {
  it('commits a valid list as live', async () => {
    requestGatewayMock.mockResolvedValue({ items: [wireItem()] })
    const result = await refreshAttention(requestGateway)
    expect(result.items).toHaveLength(1)
    expect(result.error).toBeNull()
    expect($attentionSyncState.get()).toBe('live')
    expect($attentionItems.get()).toHaveLength(1)
  })

  it('marks stale on RPC failure — never an empty healthy list', async () => {
    requestGatewayMock.mockRejectedValue(new Error('backend down'))
    const result = await refreshAttention(requestGateway)
    expect(result.items).toBeNull()
    expect(result.error).toBeInstanceOf(Error)
    expect($attentionSyncState.get()).toBe('stale')
  })

  it('marks stale on an invalid payload and reports stale:true', async () => {
    requestGatewayMock.mockResolvedValue({ items: [{ state: 'bogus' }] })
    const result = await refreshAttention(requestGateway)
    expect(result.items).toBeNull()
    expect(result.stale).toBe(true)
    expect($attentionSyncState.get()).toBe('stale')
  })

  it('a late malformed response from a torn-down scope is side-effect-free — B stays live with B rows', async () => {
    let resolveA: (value: unknown) => void = () => undefined
    requestGatewayMock.mockReturnValue(new Promise(resolve => (resolveA = resolve)))
    const pending = refreshAttention(requestGateway) // A's read
    resetAttention() // profile/connection switch mid-flight
    const bToken = beginAttentionRequest()
    commitAttentionItems(bToken, [wireItem({ id: 'zz-tes_b', title: 'B row' })]) // B live
    resolveA({ items: [{ state: 'bogus' }] }) // late malformed A payload
    const result = await pending
    expect(result.stale).toBe(true)
    expect($attentionSyncState.get()).toBe('live') // A never flips B stale
    expect($attentionItems.get()).toHaveLength(1)
    expect($attentionItems.get()[0]?.id).toBe('zz-tes_b') // B's rows untouched
  })

  it('pins the read through a requester scope guard — the target is bound before send AND recovery', async () => {
    requestGatewayMock.mockResolvedValue({ items: [wireItem()] })
    await refreshAttention(requestGateway)
    expect(requestGatewayMock).toHaveBeenCalledTimes(1)

    const [method, params, timeoutMs, signal, options] = requestGatewayMock.mock.calls[0] as [
      string, unknown, unknown, unknown, { scopeGuard?: () => boolean }
    ]

    expect(method).toBe('cron.manage')
    expect(params).toMatchObject({ action: 'list_attention', open_only: true })
    expect(timeoutMs).toBeUndefined()
    expect(signal).toBeUndefined()
    expect(options?.scopeGuard).toBeTypeOf('function')
    expect(options?.scopeGuard?.()).toBe(true) // holds while the scope holds
    resetAttention() // scope torn down
    expect(options?.scopeGuard?.()).toBe(false) // flips exactly on the teardown
  })
})

describe('ackAttentionItem', () => {
  it('maps closed-ok / already-closed outcomes', async () => {
    requestGatewayMock.mockResolvedValue({ status: 'closed-ok', changed: true })
    await expect(ackAttentionItem(requestGateway, 'cron_incident', 'zz-tes_a')).resolves.toEqual({
      status: 'closed-ok',
      changed: true
    })
    requestGatewayMock.mockResolvedValue({ status: 'already-closed', changed: false })
    await expect(ackAttentionItem(requestGateway, 'cron_incident', 'zz-tes_a')).resolves.toEqual({
      status: 'already-closed',
      changed: false
    })
  })

  it('throws on anything else so the row stays in place', async () => {
    requestGatewayMock.mockResolvedValue({ status: 'nope' })
    await expect(ackAttentionItem(requestGateway, 'cron_incident', 'zz-tes_a')).rejects.toThrow()
  })

  it('a failed ack marks the store stale and retains last-known rows', async () => {
    commitAttentionItems(beginAttentionRequest(), [wireItem()])
    requestGatewayMock.mockResolvedValue({ status: 'nope' })
    await expect(ackAttentionItem(requestGateway, 'cron_incident', 'zz-tes_a')).rejects.toThrow()
    expect($attentionSyncState.get()).toBe('stale')
    expect($attentionItems.get()).toHaveLength(1)
  })

  it('an ack that lands after a scope switch is rejected — A can never act as B', async () => {
    let resolveAck: (value: unknown) => void = () => undefined
    requestGatewayMock.mockReturnValue(new Promise(resolve => (resolveAck = resolve)))
    const pending = ackAttentionItem(requestGateway, 'cron_incident', 'zz-tes_a')
    resetAttention() // profile/connection switch mid-flight
    resolveAck({ status: 'closed-ok', changed: true })
    await expect(pending).rejects.toThrow(/scope changed/)
  })

  it('pins the ack through a requester scope guard — the target is bound before send AND retry', async () => {
    requestGatewayMock.mockResolvedValue({ status: 'closed-ok', changed: true })
    await ackAttentionItem(requestGateway, 'cron_incident', 'zz-tes_a')
    expect(requestGatewayMock).toHaveBeenCalledTimes(1)

    const [method, params, timeoutMs, signal, options] = requestGatewayMock.mock.calls[0] as [
      string, unknown, unknown, unknown, { scopeGuard?: () => boolean }
    ]

    expect(method).toBe('cron.manage')
    expect(params).toMatchObject({ action: 'ack_attention', kind: 'cron_incident', id: 'zz-tes_a' })
    expect(timeoutMs).toBeUndefined()
    expect(signal).toBeUndefined()
    expect(options?.scopeGuard).toBeTypeOf('function')
    expect(options?.scopeGuard?.()).toBe(true) // holds while the scope holds
    resetAttention() // scope torn down
    expect(options?.scopeGuard?.()).toBe(false) // flips exactly on the teardown
  })

  it('a successful A ack completing after switch to B is side-effect-free — B stays live', async () => {
    let resolveAck: (value: unknown) => void = () => undefined
    requestGatewayMock.mockReturnValue(new Promise(resolve => (resolveAck = resolve)))
    const pending = ackAttentionItem(requestGateway, 'cron_incident', 'zz-tes_a')
    resetAttention() // switch mid-flight
    commitAttentionItems(beginAttentionRequest(), [wireItem({ id: 'zz-tes_b', title: 'B row' })])
    resolveAck({ status: 'closed-ok', changed: true }) // late A success
    await expect(pending).rejects.toBeInstanceOf(AttentionScopeChangedError)
    expect($attentionSyncState.get()).toBe('live') // no false B outage
    expect($attentionItems.get()).toHaveLength(1)
    expect($attentionItems.get()[0]?.id).toBe('zz-tes_b')
  })

  it('a transport failure after switch to B is side-effect-free — B never turns stale', async () => {
    let rejectAck: (reason?: unknown) => void = () => undefined
    requestGatewayMock.mockReturnValue(new Promise((_, reject) => (rejectAck = reject)))
    const pending = ackAttentionItem(requestGateway, 'cron_incident', 'zz-tes_a')
    resetAttention() // switch mid-flight
    commitAttentionItems(beginAttentionRequest(), [wireItem({ id: 'zz-tes_b', title: 'B row' })])
    rejectAck(new Error('connection closed')) // late A transport failure
    await expect(pending).rejects.toBeInstanceOf(AttentionScopeChangedError)
    expect($attentionSyncState.get()).toBe('live')
    expect($attentionItems.get()[0]?.id).toBe('zz-tes_b')
  })
})
