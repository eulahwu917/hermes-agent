import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { $attentionItems, $attentionSyncState, resetAttention } from '@/store/attention'
import { $attentionChangeTick, $changeEventsAvailable, $cronChangeTick, $sessionsChangeTick } from '@/store/live-sync'
import { $activeSessionId } from '@/store/session'
import type { AttentionItem } from '@/types/hermes'

import { useBackgroundSync } from './use-background-sync'

const noop = () => undefined
const requestGateway = async () => ({ sessions: [] })
const attentionRequestGateway = async () => ({ items: [] })

function render(
  activeGatewayProfile: string,
  activeConnectionId: string,
  refreshSessions: () => Promise<void>,
  gatewayRequest = requestGateway
) {
  return renderHook(
    ({ connectionId, profile }: { connectionId: string; profile: string }) => {
      useBackgroundSync({
        activeConnectionId: connectionId,
        activeGatewayProfile: profile,
        activeIsMessaging: false,
        activeSessionId: null,
        activeStoredSessionId: null,
        freshDraftReady: false,
        gatewayState: 'open',
        refreshActiveTranscript: noop,
        refreshCronJobs: noop,
        refreshCurrentModel: noop,
        refreshHermesConfig: noop,
        refreshMessagingSessions: noop,
        refreshSessions,
        requestGateway: gatewayRequest
        attentionRequestGateway,
        requestGateway
      })
    },
    { initialProps: { connectionId: activeConnectionId, profile: activeGatewayProfile } }
  )
}

describe('useBackgroundSync profile-scoped session refresh', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    $activeSessionId.set(null)
    $attentionChangeTick.set(0)
    $changeEventsAvailable.set(false)
    $cronChangeTick.set(0)
    $sessionsChangeTick.set(0)
    resetAttention()
  })

  afterEach(() => {
    cleanup()
    vi.useRealTimers()
  })

  it('coalesces change ticks while the live status request is pending', async () => {
    $changeEventsAvailable.set(true)
    let release!: (value: { sessions: [] }) => void

    const pending = new Promise<{ sessions: [] }>(resolve => {
      release = resolve
    })

    const request = vi.fn(() => pending)
    render('default', 'local', async () => undefined, request)
    await act(async () => undefined)

    for (let tick = 1; tick <= 8; tick += 1) {
      await act(async () => {
        $sessionsChangeTick.set(tick)
      })
    }

    expect(request).toHaveBeenCalledTimes(1)
    await act(async () => {
      release({ sessions: [] })
    })
    expect(request).toHaveBeenCalledTimes(2)
  })

  it('refreshes the session list after the active gateway profile changes', async () => {
    const refreshSessions = vi.fn(async () => undefined)
    const hook = render('default', 'local', refreshSessions)

    await act(async () => undefined)
    expect(refreshSessions).toHaveBeenCalledTimes(1)
    refreshSessions.mockClear()

    hook.rerender({ connectionId: 'local', profile: 'nova' })

    await act(async () => undefined)
    expect(refreshSessions).toHaveBeenCalledTimes(1)
  })

  it('refreshes the session list when the backend changes but the profile name does not', async () => {
    const refreshSessions = vi.fn(async () => undefined)
    const hook = render('default', 'work', refreshSessions)

    await act(async () => undefined)
    refreshSessions.mockClear()

    hook.rerender({ connectionId: 'homelab', profile: 'default' })

    await act(async () => undefined)
    expect(refreshSessions).toHaveBeenCalledTimes(1)
  })
})


function wireAttentionItem(profile: string): AttentionItem {
  return {
    kind: 'cron_incident',
    id: `zz-tes_${profile}_1`,
    source: 'cron',
    severity: 'warning',
    title: `item-${profile}`,
    body_excerpt: 'boom',
    first_seen_at: '2026-09-08T00:00:00',
    last_seen_at: '2026-09-08T01:00:00',
    state: 'open',
    acked_at: null,
    job_id: `zz-test-${profile}`,
    job_name: `job-${profile}`,
    error_sig: 'abc',
    output_file: null
  }
}

describe('useBackgroundSync attention lifecycle', () => {
  it('seeds the store on open and marks stale (retaining rows) when the socket drops', async () => {
    const activeProfile = { current: 'default' }

    const attentionRequestGateway = vi.fn(
      async (method: string, params: Record<string, unknown>) => {
        if (method === 'cron.manage' && params.action === 'list_attention') {
          return { items: [wireAttentionItem(activeProfile.current)] }
        }

        return { sessions: [] }
      }
    )

    const hook = renderHook(
      ({ profile, state }: { profile: string; state: string }) => {
        useBackgroundSync({
          activeConnectionId: 'local',
          activeGatewayProfile: profile,
          activeIsMessaging: false,
          activeSessionId: null,
          activeStoredSessionId: null,
          freshDraftReady: false,
          gatewayState: state,
          refreshActiveTranscript: noop,
          refreshCronJobs: noop,
          refreshCurrentModel: noop,
          refreshHermesConfig: noop,
          refreshMessagingSessions: noop,
          refreshSessions: noop,
          attentionRequestGateway,
          requestGateway: vi.fn(async () => ({ sessions: [] }))
        })
      },
      { initialProps: { profile: 'default', state: 'open' } }
    )

    await act(async () => undefined)
    expect($attentionItems.get()).toHaveLength(1)
    expect($attentionSyncState.get()).toBe('live')

    // A settled socket drop must flip the store stale and retain last-known rows —
    // never a silently green badge or an empty healthy list.
    hook.rerender({ profile: 'default', state: 'closed' })
    await act(async () => undefined)
    expect($attentionSyncState.get()).toBe('stale')
    expect($attentionItems.get()).toHaveLength(1)
  })

  it('a profile switch resets the store and reseeds from the new scope — A never renders as B', async () => {
    const activeProfile = { current: 'default' }

    const attentionRequestGateway = vi.fn(
      async (method: string, params: Record<string, unknown>) => {
        if (method === 'cron.manage' && params.action === 'list_attention') {
          return { items: [wireAttentionItem(activeProfile.current)] }
        }

        return { sessions: [] }
      }
    )

    const hook = renderHook(
      ({ profile, state }: { profile: string; state: string }) => {
        useBackgroundSync({
          activeConnectionId: 'local',
          activeGatewayProfile: profile,
          activeIsMessaging: false,
          activeSessionId: null,
          activeStoredSessionId: null,
          freshDraftReady: false,
          gatewayState: state,
          refreshActiveTranscript: noop,
          refreshCronJobs: noop,
          refreshCurrentModel: noop,
          refreshHermesConfig: noop,
          refreshMessagingSessions: noop,
          refreshSessions: noop,
          attentionRequestGateway,
          requestGateway: vi.fn(async () => ({ sessions: [] }))
        })
      },
      { initialProps: { profile: 'default', state: 'open' } }
    )

    await act(async () => undefined)
    expect($attentionItems.get()[0]?.title).toBe('item-default')

    activeProfile.current = 'nova'
    hook.rerender({ profile: 'nova', state: 'open' })
    await act(async () => undefined)

    const items = $attentionItems.get()
    expect(items).toHaveLength(1)
    expect(items[0]?.title).toBe('item-nova')
    expect(items.every(item => item.title !== 'item-default')).toBe(true)
  })

  it('stays on the declared ambient owner — a focused other-profile session never fills or clears A\u2019s list, and the guard options survive end-to-end', async () => {
    $attentionChangeTick.set(0)
    $changeEventsAvailable.set(false)
    $cronChangeTick.set(0)
    $sessionsChangeTick.set(0)

    // The focused session's backend (B) returns an EMPTY list. Pre-fix, the
    // session dispatcher routed this ambient read to B and committed the empty
    // snapshot live — clearing A's real alarm badge (or rendering B's rows on
    // A's page). The dispatcher must never carry the Attention surface.
    const sessionDispatcher = vi.fn(async (method: string, params: Record<string, unknown>) => {
      if (method === 'cron.manage' && params.action === 'list_attention') {
        return { items: [] }
      }

      return { sessions: [] }
    })

    // A's AMBIENT requester (the declared owner, local/default). Its FIRST
    // read is parked so the focused session can move to (and stay on) B
    // mid-flight; later reads resolve immediately with A's rows.
    let ambientReads = 0
    let resolveAmbient: (value: unknown) => void = () => undefined

    const ambientAttentionRequest = vi.fn((method: string, params: Record<string, unknown>) => {
      if (method === 'cron.manage' && params.action === 'list_attention') {
        ambientReads += 1

        if (ambientReads === 1) {
          return new Promise(resolve => (resolveAmbient = resolve))
        }

        return Promise.resolve({ items: [wireAttentionItem('default')] })
      }

      return Promise.resolve({ sessions: [] })
    })

    const hook = renderHook(
      ({ sessionId, storedId }: { sessionId: string | null; storedId: string | null }) => {
        useBackgroundSync({
          activeConnectionId: 'local',
          activeGatewayProfile: 'default',
          activeIsMessaging: false,
          activeSessionId: sessionId,
          activeStoredSessionId: storedId,
          freshDraftReady: false,
          gatewayState: 'open',
          refreshActiveTranscript: noop,
          refreshCronJobs: noop,
          refreshCurrentModel: noop,
          refreshHermesConfig: noop,
          refreshMessagingSessions: noop,
          refreshSessions: noop,
          attentionRequestGateway: ambientAttentionRequest,
          requestGateway: sessionDispatcher
        })
      },
      { initialProps: { sessionId: 'b-runtime-1', storedId: 'b-stored-1' } }
    )

    // The focused session is B's from the start; A's ambient read is in flight.
    await act(async () => undefined)
    expect(ambientAttentionRequest).toHaveBeenCalledTimes(1)

    // Focus moves to another B-session while A's read is still pending. The
    // Attention owner (local/default) is unchanged, so nothing reseeds — and a
    // focused-session change must never invalidate or redirect A's read.
    hook.rerender({ sessionId: 'b-runtime-2', storedId: 'b-stored-2' })
    await act(async () => undefined)
    expect(ambientAttentionRequest).toHaveBeenCalledTimes(1)

    act(() => resolveAmbient({ items: [wireAttentionItem('default')] }))
    await act(async () => undefined)

    // A's rows landed for A — B's empty snapshot never did.
    expect($attentionItems.get()).toHaveLength(1)
    expect($attentionItems.get()[0]?.title).toBe('item-default')
    expect($attentionSyncState.get()).toBe('live')

    // The session dispatcher never carried the non-session Attention surface.
    expect(sessionDispatcher).not.toHaveBeenCalledWith('cron.manage', expect.anything())

    // Event-path (attention.changed tick) reads stay on the declared owner
    // too: the effect re-runs on the tick and every read goes ambience-ward.
    act(() => $attentionChangeTick.set($attentionChangeTick.get() + 1))
    await act(async () => undefined)
    expect(ambientAttentionRequest.mock.calls.filter(([method]) => method === 'cron.manage')).toHaveLength(3)
    expect(sessionDispatcher).not.toHaveBeenCalledWith('cron.manage', expect.anything())
    expect($attentionItems.get()).toHaveLength(1)
    expect($attentionItems.get()[0]?.title).toBe('item-default')
    expect($attentionSyncState.get()).toBe('live')

    // The guard options made it end-to-end through the ambient requester.
    const attentionCalls = ambientAttentionRequest.mock.calls.filter(([method]) => method === 'cron.manage')
    expect(attentionCalls).toHaveLength(3)
    const call = attentionCalls[0] as unknown as [string, unknown, unknown, unknown, { scopeGuard?: () => boolean }]
    const options = call[4]
    expect(options?.scopeGuard).toBeTypeOf('function')
    expect(options?.scopeGuard?.()).toBe(true) // holds while the scope holds
    resetAttention() // scope torn down
    expect(options?.scopeGuard?.()).toBe(false) // flips exactly on the teardown
  })
})