import type { GatewayWsUrlResult } from '@hermes/shared'
import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const gatewayMocks = vi.hoisted(() => ({
  instances: [] as Array<{
    connect: ReturnType<typeof vi.fn>
    connectionState: string
    request: ReturnType<typeof vi.fn>
    wsUrl: string
  }>
}))

vi.mock('@/hermes', async importOriginal => {
  const actual = await importOriginal<typeof HermesModule>()

  class FakeHermesGateway {
    connectionState = 'closed'
    wsUrl = ''
    request = vi.fn()
    connect = vi.fn(async (wsUrl: string) => {
      this.wsUrl = wsUrl
      this.connectionState = 'open'

      for (const handler of this.stateHandlers) {
        handler('open')
      }
    })
    close = vi.fn(() => {
      this.connectionState = 'closed'

      for (const handler of this.stateHandlers) {
        handler('closed')
      }
    })
    onEvent = vi.fn(() => () => undefined)
    onState = vi.fn((handler: (state: string) => void) => {
      this.stateHandlers.add(handler)
      handler(this.connectionState)

      return () => this.stateHandlers.delete(handler)
    })
    private stateHandlers = new Set<(state: string) => void>()

    constructor() {
      gatewayMocks.instances.push(this)
    }
  }

  return { ...actual, HermesGateway: FakeHermesGateway }
})

import { refreshAttention } from '@/app/cron/attention-actions'
import type { HermesConnection } from '@/global'
import type * as HermesModule from '@/hermes'
import type { HermesGateway } from '@/hermes'
import {
  $attentionItems,
  $attentionSyncState,
  beginAttentionRequest,
  commitAttentionItems,
  currentAttentionScopeToken,
  resetAttention
} from '@/store/attention'
import {
  $gateway,
  closeSecondaryGateways,
  configureGatewayRegistry,
  ensureGatewayForAgent,
  setPrimaryGateway
} from '@/store/gateway'
import { $activeGatewayProfile } from '@/store/profile'
import { $connection, $gatewayState, setConnection } from '@/store/session'
import type { AttentionItem } from '@/types/hermes'

import { useGatewayRequest } from './use-gateway-request'

interface TestGateway {
  connect: ReturnType<typeof vi.fn>
  connectionState: string
  request: ReturnType<typeof vi.fn>
  wsUrl?: string
}

/** The descriptor shape installPrimaryDesktop('token').getConnection returns. */
type PrimaryConnectionDescriptor = {
  authMode: 'oauth' | 'token'
  baseUrl: string
  mode: 'local' | 'remote'
  profile: string
  token: string
  wsUrl: string
}

const fakeGateway = { connectionState: 'open' } as unknown as HermesGateway

const remoteConnection = {
  authMode: 'oauth' as const,
  baseUrl: 'https://ssh.example.test',
  connectionId: 'ssh-source',
  mode: 'remote' as const,
  profile: 'research',
  remoteIdentity: 'ssh.example.test',
  remoteKind: 'ssh' as const,
  token: 'remote-token',
  wsUrl: 'wss://ssh.example.test/api/ws?ticket=stale'
}

function installRemoteDesktop() {
  let mintCount = 0

  const getConnection = vi.fn(async (profile?: null | string) => ({
    authMode: 'token' as const,
    baseUrl: 'http://127.0.0.1:5151',
    mode: 'local' as const,
    profile: profile ?? 'default',
    token: 'local-token',
    wsUrl: 'ws://127.0.0.1:5151/api/ws?token=local'
  }))

  const getConnectionFor = vi.fn(async ({ connectionId, profile }: { connectionId: string; profile: string }) => ({
    ...remoteConnection,
    connectionId,
    profile
  }))

  const getGatewayWsUrl = vi.fn(async () => ({
    ok: true as const,
    wsUrl: 'ws://127.0.0.1:5151/api/ws?token=fresh-local'
  }))

  const getGatewayWsUrlFor = vi.fn(
    async ({ connectionId, profile }: { connectionId: string; profile: string }): Promise<GatewayWsUrlResult> => {
      mintCount += 1

      return {
        ok: true as const,
        wsUrl: `wss://${connectionId}.example.test/api/ws?profile=${profile}&ticket=fresh-${mintCount}`
      }
    }
  )

  Object.defineProperty(window, 'hermesDesktop', {
    configurable: true,
    value: { getConnection, getConnectionFor, getGatewayWsUrl, getGatewayWsUrlFor }
  })

  return { getConnection, getConnectionFor, getGatewayWsUrl, getGatewayWsUrlFor }
}

function installPrimaryDesktop(authMode: 'oauth' | 'token') {
  const getConnection = vi.fn(async (profile?: null | string) => ({
    authMode,
    baseUrl: authMode === 'oauth' ? 'https://gateway.example.test' : 'http://127.0.0.1:5151',
    mode: authMode === 'oauth' ? ('remote' as const) : ('local' as const),
    profile: profile ?? 'default',
    token: 'primary-token',
    wsUrl: authMode === 'oauth' ? 'wss://gateway.example.test/api/ws?ticket=stale' : 'ws://127.0.0.1:5151/api/ws'
  }))

  const getGatewayWsUrl = vi.fn(async (profile?: null | string) => ({
    ok: true as const,
    wsUrl:
      authMode === 'oauth'
        ? `wss://gateway.example.test/api/ws?profile=${profile ?? 'default'}&ticket=fresh`
        : 'ws://127.0.0.1:5151/api/ws?token=fresh'
  }))

  const getConnectionFor = vi.fn()
  const getGatewayWsUrlFor = vi.fn()

  Object.defineProperty(window, 'hermesDesktop', {
    configurable: true,
    value: { getConnection, getConnectionFor, getGatewayWsUrl, getGatewayWsUrlFor }
  })

  return { getConnection, getConnectionFor, getGatewayWsUrl, getGatewayWsUrlFor }
}

function makePrimaryGateway(): TestGateway {
  return {
    connect: vi.fn(async () => undefined),
    connectionState: 'open',
    request: vi.fn()
  }
}

interface Deferred<T> {
  promise: Promise<T>
  reject: (reason?: unknown) => void
  resolve: (value: T | PromiseLike<T>) => void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void
  let reject!: (reason?: unknown) => void

  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })

  return { promise, reject, resolve }
}

function wireAttentionItem(id: string): AttentionItem {
  return {
    kind: 'cron_incident',
    id,
    source: 'cron',
    severity: 'warning',
    title: 'zz-test job',
    body_excerpt: 'boom',
    first_seen_at: '2026-09-08T00:00:00',
    last_seen_at: '2026-09-08T01:00:00',
    state: 'open',
    acked_at: null
  }
}

async function activateRemoteGateway() {
  const desktop = installRemoteDesktop()
  const primary = makePrimaryGateway()

  setPrimaryGateway(primary as unknown as HermesGateway, 'default')
  $gateway.set(primary as unknown as HermesGateway)
  await ensureGatewayForAgent('ssh-source', 'research')

  const gateway = $gateway.get() as unknown as TestGateway

  expect(gateway).not.toBe(primary)
  expect($activeGatewayProfile.get()).toBe('research')

  return { desktop, gateway }
}

async function expectSecondaryRecoveryFailure(
  gateway: TestGateway,
  request: ReturnType<typeof useGatewayRequest>['requestGateway']
) {
  const transportError = new Error('connection closed')
  gateway.request.mockRejectedValueOnce(transportError)
  gateway.connectionState = 'closed'

  vi.useFakeTimers()

  const retry = request('session.resume').then(
    () => undefined,
    error => error
  )

  await act(async () => {
    await Promise.resolve()
    await Promise.resolve()
    await vi.advanceTimersByTimeAsync(8_000)
  })

  await expect(retry).resolves.toBe(transportError)
  expect(gateway.request).toHaveBeenCalledTimes(1)
  expect(gateway.connect).toHaveBeenCalledTimes(1)
}

beforeEach(() => {
  gatewayMocks.instances.length = 0
  closeSecondaryGateways()
  setPrimaryGateway(null)
  $gateway.set(null)
  $connection.set(null)
  $gatewayState.set('idle')
  $activeGatewayProfile.set('default')
  resetAttention()
  configureGatewayRegistry({
    onActiveRouteChanged: profile => $activeGatewayProfile.set(profile),
    onEvent: vi.fn()
  })
})

afterEach(() => {
  vi.useRealTimers()
  closeSecondaryGateways()
  setPrimaryGateway(null)
  $gateway.set(null)
  $connection.set(null)
  $gatewayState.set('idle')
  $activeGatewayProfile.set('default')
  Reflect.deleteProperty(window, 'hermesDesktop')
})

describe('useGatewayRequest', () => {
  it('exposes the live gateway on the first render, before effects run', () => {
    $gateway.set(fakeGateway)

    const { result } = renderHook(() => useGatewayRequest())

    expect(result.current.gateway).toBe(fakeGateway)
  })

  it('tracks the gateway when the active socket changes', () => {
    const { result } = renderHook(() => useGatewayRequest())

    expect(result.current.gateway).toBeNull()

    act(() => $gateway.set(fakeGateway))

    expect(result.current.gateway).toBe(fakeGateway)
  })

  it.each([
    { error: new Error('connection closed'), label: 'closed message' },
    { error: new Error('ECONNRESET'), label: 'reset message' },
    { error: Object.assign(new Error('socket failed'), { code: 'ECONNRESET' }), label: 'error code' },
    { error: Object.assign(new Error('socket failed'), { cause: { code: 'ECONNRESET' } }), label: 'cause code' }
  ])('recovers the registered remote source after a $label failure', async ({ error }) => {
    const { desktop, gateway } = await activateRemoteGateway()
    gateway.request.mockResolvedValueOnce({ turn: 1 }).mockRejectedValueOnce(error).mockResolvedValueOnce({ turn: 2 })

    const { result } = renderHook(() => useGatewayRequest())

    await act(async () => {
      await expect(result.current.requestGateway('prompt.submit', { text: 'first' })).resolves.toEqual({ turn: 1 })
    })
    gateway.connectionState = 'closed'
    await act(async () => {
      await expect(result.current.requestGateway('prompt.submit', { text: 'second' })).resolves.toEqual({ turn: 2 })
    })

    expect(desktop.getConnectionFor).toHaveBeenCalledTimes(2)
    expect(desktop.getConnectionFor).toHaveBeenCalledWith({ connectionId: 'ssh-source', profile: 'research' })
    expect(desktop.getGatewayWsUrlFor).toHaveBeenCalledTimes(2)
    expect(desktop.getGatewayWsUrlFor).toHaveBeenCalledWith({ connectionId: 'ssh-source', profile: 'research' })
    expect(desktop.getConnection).not.toHaveBeenCalled()
    expect(desktop.getGatewayWsUrl).not.toHaveBeenCalled()
    expect(gateway.connect).toHaveBeenLastCalledWith(expect.stringContaining('ticket=fresh-2'))
  })

  it('does not reconnect for a non-transport request failure', async () => {
    const { desktop, gateway } = await activateRemoteGateway()
    const failure = Object.assign(new Error('request rejected'), { code: 'EVALIDATION' })
    gateway.request.mockRejectedValueOnce(failure)

    const { result } = renderHook(() => useGatewayRequest())

    await expect(result.current.requestGateway('session.resume')).rejects.toBe(failure)
    expect(desktop.getConnectionFor).toHaveBeenCalledTimes(1)
    expect(desktop.getGatewayWsUrlFor).toHaveBeenCalledTimes(1)
    expect(gateway.connect).toHaveBeenCalledTimes(1)
  })

  it('surfaces a real secondary OAuth reauth rejection as the original transport failure', async () => {
    const { desktop, gateway } = await activateRemoteGateway()
    desktop.getGatewayWsUrlFor.mockImplementation(async () => ({
      error: '401 cookie expired',
      needsOauthLogin: true,
      ok: false as const
    }))

    const { result } = renderHook(() => useGatewayRequest())

    await expectSecondaryRecoveryFailure(gateway, result.current.requestGateway)

    expect(desktop.getConnectionFor).toHaveBeenCalledWith({ connectionId: 'ssh-source', profile: 'research' })
    expect(desktop.getGatewayWsUrlFor).toHaveBeenCalled()
    expect(desktop.getConnection).not.toHaveBeenCalled()
    expect(desktop.getGatewayWsUrl).not.toHaveBeenCalled()
  })

  it('surfaces a failed secondary OAuth ticket mint without using the stale ticket or local bridges', async () => {
    const { desktop, gateway } = await activateRemoteGateway()
    desktop.getGatewayWsUrlFor.mockRejectedValue(new Error('ticket mint failed'))

    const { result } = renderHook(() => useGatewayRequest())

    await expectSecondaryRecoveryFailure(gateway, result.current.requestGateway)

    expect(desktop.getConnectionFor).toHaveBeenCalledWith({ connectionId: 'ssh-source', profile: 'research' })
    expect(desktop.getConnection).not.toHaveBeenCalled()
    expect(desktop.getGatewayWsUrl).not.toHaveBeenCalled()
  })

  it('surfaces a missing optional scoped mint bridge without falling back to a stale ticket or local lookup', async () => {
    const { desktop, gateway } = await activateRemoteGateway()
    Reflect.deleteProperty(window.hermesDesktop, 'getGatewayWsUrlFor')

    const { result } = renderHook(() => useGatewayRequest())

    await expectSecondaryRecoveryFailure(gateway, result.current.requestGateway)

    expect(desktop.getConnectionFor).toHaveBeenCalledWith({ connectionId: 'ssh-source', profile: 'research' })
    expect(desktop.getConnection).not.toHaveBeenCalled()
    expect(desktop.getGatewayWsUrl).not.toHaveBeenCalled()
  })

  it.each([
    { authMode: 'oauth' as const, label: 'primary OAuth' },
    { authMode: 'token' as const, label: 'local primary' }
  ])('preserves $label recovery', async ({ authMode }) => {
    const desktop = installPrimaryDesktop(authMode)
    const primary = makePrimaryGateway()
    primary.request.mockRejectedValueOnce(new Error('connection closed')).mockResolvedValueOnce({ recovered: true })

    setPrimaryGateway(primary as unknown as HermesGateway, 'default')
    $gateway.set(primary as unknown as HermesGateway)
    $gatewayState.set('closed')

    const { result } = renderHook(() => useGatewayRequest())

    await act(async () => {
      await expect(result.current.requestGateway('session.resume')).resolves.toEqual({ recovered: true })
    })

    expect(desktop.getConnection).toHaveBeenCalledWith('default')
    expect(desktop.getGatewayWsUrl).toHaveBeenCalledWith('default')
    expect(desktop.getConnectionFor).not.toHaveBeenCalled()
    expect(desktop.getGatewayWsUrlFor).not.toHaveBeenCalled()
  })

  it('a scope-guarded request that holds its scope keeps the normal recovery path', async () => {
    const { gateway } = await activateRemoteGateway()
    gateway.request.mockResolvedValueOnce({ turn: 1 }).mockRejectedValueOnce(new Error('connection closed')).mockResolvedValueOnce({ turn: 2 })

    const { result } = renderHook(() => useGatewayRequest())
    const guard = { scopeGuard: () => true }

    await act(async () => {
      await expect(result.current.requestGateway('prompt.submit', { text: 'first' }, undefined, undefined, guard)).resolves.toEqual({ turn: 1 })
    })
    gateway.connectionState = 'closed'
    await act(async () => {
      await expect(result.current.requestGateway('prompt.submit', { text: 'second' }, undefined, undefined, guard)).resolves.toEqual({ turn: 2 })
    })

    expect(gateway.request).toHaveBeenCalledTimes(3)
    expect(gateway.connect).toHaveBeenCalled()
  })

  it('rejects before sending when the scope guard fails up front', async () => {
    const { gateway } = await activateRemoteGateway()

    const { result } = renderHook(() => useGatewayRequest())

    await expect(
      result.current.requestGateway('cron.manage', { action: 'ack_attention', kind: 'cron_incident', id: 'zz-tes_a' }, undefined, undefined, {
        scopeGuard: () => false
      })
    ).rejects.toThrow('gateway request scope changed before send')

    // Zero mutations: the method never reached any gateway.
    expect(gateway.request).not.toHaveBeenCalled()
  })

  it('a scope-guarded request aborts instead of retargeting: deferred A transport rejection after a switch to B never replays A\'s method on B', async () => {
    const { gateway: gatewayA } = await activateRemoteGateway()

    // A's request stays pending past the switch, then rejects with a transport error.
    let rejectTransport: (reason?: unknown) => void = () => undefined
    gatewayA.request.mockReturnValueOnce(new Promise((_, reject) => (rejectTransport = reject)))

    const { result } = renderHook(() => useGatewayRequest())

    let scope = 'A'

    const pending = result.current
      .requestGateway(
        'cron.manage',
        { action: 'ack_attention', kind: 'cron_incident', id: 'zz-tes_a' },
        undefined,
        undefined,
        { scopeGuard: () => scope === 'A' }
      )
      .then(
        () => undefined,
        error => error
      )

    // The user activates B while A's request is in flight; the scope token moves with it.
    await ensureGatewayForAgent('other-source', 'other')
    const gatewayB = $gateway.get() as unknown as TestGateway
    expect(gatewayB).not.toBe(gatewayA)
    scope = 'B'

    // A's transport rejection lands AFTER the switch — the recovery path must not
    // resolve the now-active route and replay the ack there.
    rejectTransport(new Error('connection closed'))

    const outcome = await act(async () => pending)
    expect(outcome).toBeInstanceOf(Error)
    expect((outcome as Error).message).toContain('scope changed before retry')

    // B receives zero A mutations: no ack_attention replay on the now-active route.
    expect(gatewayB.request).not.toHaveBeenCalled()
    expect(gatewayA.request).toHaveBeenCalledTimes(1)
  })

  it('a scope torn down while the primary reconnect is in flight aborts before replay — the recovery publishes and dial are suppressed and B stays live', async () => {
    const desktop = installPrimaryDesktop('token')
    const primary = makePrimaryGateway()
    primary.request.mockRejectedValueOnce(new Error('connection closed'))

    setPrimaryGateway(primary as unknown as HermesGateway, 'default')
    $gateway.set(primary as unknown as HermesGateway)
    $gatewayState.set('idle')

    // Park the primary recovery mid-IPC. By the time getConnection() is
    // reached, the transport rejection has been caught AND the guard at the
    // retry gate has passed — the reconnect is now suspended after the last
    // pre-recovery check: exactly the R4-1 window.
    let releaseConnection: (value: PrimaryConnectionDescriptor) => void = () => undefined
    desktop.getConnection.mockReturnValue(
      new Promise<PrimaryConnectionDescriptor>(resolve => {
        releaseConnection = resolve
      })
    )

    const { result } = renderHook(() => useGatewayRequest())

    // The REAL attention scope pinning — the same shape ackAttentionItem
    // builds around currentAttentionScopeToken().
    const scope = currentAttentionScopeToken()

    const pending = result.current
      .requestGateway(
        'cron.manage',
        { action: 'ack_attention', kind: 'cron_incident', id: 'zz-tes_a' },
        undefined,
        undefined,
        { scopeGuard: () => currentAttentionScopeToken() === scope }
      )
      .then(
        () => undefined,
        error => error
      )

    // Wait until the transport rejection has been caught and the recovery is
    // parked in getConnection() — the retry-gate guard has ALREADY passed at
    // this point (the scope is still intact). This is the R4-1 window: the
    // switch lands while the reconnect is suspended mid-IPC.
    await act(async () => {
      await vi.waitFor(() => expect(desktop.getConnection).toHaveBeenCalled())
    })

    const connectionA: PrimaryConnectionDescriptor = {
      authMode: 'token',
      baseUrl: 'http://127.0.0.1:5151',
      mode: 'local',
      profile: 'default',
      token: 'primary-token',
      wsUrl: 'ws://127.0.0.1:5151/api/ws?token=A'
    }

    const connectionB = { ...connectionA, wsUrl: 'ws://127.0.0.1:5151/api/ws?token=B' }

    // Apply the switch while the recovery is suspended: the REAL attention
    // scope teardown (the same call wipeSessionListsForGatewaySwitch makes),
    // B's rows committed live, and B's descriptor published as the new
    // primary connection.
    act(() => {
      resetAttention()
      commitAttentionItems(beginAttentionRequest(), [wireAttentionItem('zz-tes_b')])
      setConnection(connectionB as unknown as HermesConnection)
    })

    // Release the stale recovery with A's descriptor — the recovered path
    // must refuse to publish it, dial the shared primary object with it, or
    // replay A's ack on the now-rehomed primary.
    releaseConnection(connectionA)

    const outcome = await act(async () => pending)
    expect(outcome).toBeInstanceOf(Error)
    expect((outcome as Error).message).toContain('scope changed before replay')

    // No replay of A's ack on the rehomed primary: exactly one send ever.
    expect(primary.request).toHaveBeenCalledTimes(1)

    // The obsolete recovery never published A's descriptor over B and never
    // reconnected the shared primary object (no ticket mint, no dial).
    expect($connection.get()).toBe(connectionB)
    expect(primary.connect).not.toHaveBeenCalled()
    expect(desktop.getGatewayWsUrl).not.toHaveBeenCalled()

    // B's Attention remains live with B's open row — no B row closure.
    expect($attentionSyncState.get()).toBe('live')
    expect($attentionItems.get()).toHaveLength(1)
    expect($attentionItems.get()[0]?.id).toBe('zz-tes_b')
    expect($attentionItems.get()[0]?.state).toBe('open')
  })

  it.each([
    { label: 'the connection IPC rejects', park: 'connection' as const },
    { label: 'the ticket mint rejects', park: 'mint' as const },
    { label: 'the dial rejects', park: 'dial' as const }
  ])(
    'keeps an obsolete-scope reconnect failure side-effect-free when $label after the switch — B keeps its descriptor and rows',
    async ({ park }) => {
      const desktop = installPrimaryDesktop('oauth')
      const primary = makePrimaryGateway()
      primary.request.mockRejectedValueOnce(new Error('connection closed'))

      setPrimaryGateway(primary as unknown as HermesGateway, 'default')
      $gateway.set(primary as unknown as HermesGateway)
      $gatewayState.set('idle')

      // OAuth mode so a ticket-mint rejection propagates to the shared catch
      // (token mode swallows mint failures via .catch(() => null)).
      // Park the primary recovery at the chosen await. Each await REJECTS
      // (rather than fulfilling as in the R4-1 control) AFTER the scope is
      // torn down, so the failure continuation lands in the shared catch
      // under an obsolete scope.
      const connection = deferred<PrimaryConnectionDescriptor>()
      const mint = deferred<{ ok: true; wsUrl: string }>()
      const dial = deferred<void>()

      desktop.getConnection.mockReturnValue(connection.promise)
      desktop.getGatewayWsUrl.mockReturnValue(mint.promise)
      primary.connect.mockReturnValue(dial.promise)

      const { result } = renderHook(() => useGatewayRequest())

      const scope = currentAttentionScopeToken()

      const pending = result.current
        .requestGateway(
          'cron.manage',
          { action: 'ack_attention', kind: 'cron_incident', id: 'zz-tes_a' },
          undefined,
          undefined,
          { scopeGuard: () => currentAttentionScopeToken() === scope }
        )
        .then(
          () => undefined,
          error => error
        )

      const connectionA: PrimaryConnectionDescriptor = {
        authMode: 'oauth',
        baseUrl: 'https://gateway.example.test',
        mode: 'remote',
        profile: 'default',
        token: 'primary-token',
        wsUrl: 'wss://gateway.example.test/api/ws?ticket=A'
      }

      const connectionB = { ...connectionA, wsUrl: 'wss://gateway.example.test/api/ws?ticket=B' }

      // Advance the recovery to its parked await while the scope still holds.
      await act(async () => {
        await vi.waitFor(() => expect(desktop.getConnection).toHaveBeenCalled())
      })

      if (park !== 'connection') {
        await act(async () => {
          connection.resolve(connectionA)

          if (park === 'mint') {
            await vi.waitFor(() => expect(desktop.getGatewayWsUrl).toHaveBeenCalled())
          } else {
            mint.resolve({ ok: true, wsUrl: 'wss://gateway.example.test/api/ws?ticket=fresh-A' })

            await vi.waitFor(() => expect(primary.connect).toHaveBeenCalled())
          }
        })
      }

      // Apply the switch while the recovery is suspended at the failure point:
      // the real Attention teardown, B's rows committed live, and B's
      // descriptor published as the new primary connection.
      act(() => {
        resetAttention()
        commitAttentionItems(beginAttentionRequest(), [wireAttentionItem('zz-tes_b')])
        setConnection(connectionB as unknown as HermesConnection)
      })

      // The obsolete recovery now FAILS (timeout-class rejection) — the shared
      // catch must not clear B's published descriptor or stash the failure.
      if (park === 'connection') {
        connection.reject(new Error('Timed out reconnecting to Hermes backend'))
      } else if (park === 'mint') {
        mint.reject(new Error('Timed out re-minting the gateway WebSocket URL'))
      } else {
        dial.reject(new Error('connection closed during dial'))
      }

      const outcome = await act(async () => pending)
      expect(outcome).toBeInstanceOf(Error)
      expect((outcome as Error).message).toContain('scope changed before replay')

      // No replay of A's ack on the rehomed primary: exactly one send ever,
      // and no post-failure dial/re-mint (the dial stage's single dial is
      // A's own, made before the scope switch).
      expect(primary.request).toHaveBeenCalledTimes(1)
      expect(primary.connect).toHaveBeenCalledTimes(park === 'dial' ? 1 : 0)
      expect(desktop.getGatewayWsUrl).toHaveBeenCalledTimes(park === 'mint' || park === 'dial' ? 1 : 0)

      // B's published descriptor survives the obsolete failure untouched, and
      // B's Attention stays live/current with its open row.
      expect($connection.get()).toBe(connectionB)
      expect($attentionSyncState.get()).toBe('live')
      expect($attentionItems.get()).toHaveLength(1)
      expect($attentionItems.get()[0]?.id).toBe('zz-tes_b')
      expect($attentionItems.get()[0]?.state).toBe('open')
    }
  )

  it.each([
    { label: 'the stale recovery fulfills', reject: false },
    { label: 'the stale recovery rejects', reject: true }
  ])(
    'a scope guard passed by the production attention read suppresses obsolete recovery side effects when $label after the switch — B keeps its descriptor and rows',
    async ({ reject }) => {
      const desktop = installPrimaryDesktop('token')
      const primary = makePrimaryGateway()
      primary.request.mockRejectedValueOnce(new Error('connection closed'))

      setPrimaryGateway(primary as unknown as HermesGateway, 'default')
      $gateway.set(primary as unknown as HermesGateway)
      $gatewayState.set('idle')

      // Park the primary recovery in getConnection(), past the first guard —
      // the exact R6-1 window: A's list read failed at the transport, the
      // retry-gate guard passed while the scope still held, and the reconnect
      // is now suspended mid-IPC.
      const connection = deferred<PrimaryConnectionDescriptor>()
      desktop.getConnection.mockReturnValue(connection.promise)

      const { result } = renderHook(() => useGatewayRequest())

      // The PRODUCTION read — refreshAttention now pins its scope through the
      // requester guard, exactly like ackAttentionItem. Pre-fix it passed no
      // guard, so the recovery below ran unguarded (publish/dial over B on
      // fulfillment, setConnection(null) in the catch on rejection).
      const pending = refreshAttention(result.current.requestGateway)

      await act(async () => {
        await vi.waitFor(() => expect(desktop.getConnection).toHaveBeenCalled())
      })

      const connectionA: PrimaryConnectionDescriptor = {
        authMode: 'token',
        baseUrl: 'http://127.0.0.1:5151',
        mode: 'local',
        profile: 'default',
        token: 'primary-token',
        wsUrl: 'ws://127.0.0.1:5151/api/ws?token=A'
      }

      const connectionB = { ...connectionA, wsUrl: 'ws://127.0.0.1:5151/api/ws?token=B' }

      // Apply the switch while the recovery is suspended: the REAL attention
      // scope teardown, B's rows committed live, and B's descriptor published
      // as the new primary connection.
      act(() => {
        resetAttention()
        commitAttentionItems(beginAttentionRequest(), [wireAttentionItem('zz-tes_b')])
        setConnection(connectionB as unknown as HermesConnection)
      })

      // The obsolete recovery now settles — either fulfilling with A's stale
      // descriptor or failing (timeout-class rejection). Both land after the
      // scope switch, so neither may publish over B, dial the shared primary
      // object, or replay the read on the rehomed primary.
      if (reject) {
        connection.reject(new Error('Timed out reconnecting to Hermes backend'))
      } else {
        connection.resolve(connectionA)
      }

      const outcome = await act(async () => pending)
      // refreshAttention never throws for an obsolete scope: the read renders
      // as a stale no-op and the NEW scope's refresh owns the store.
      expect(outcome).toEqual({ items: null, error: null, stale: true })

      // No replay of A's read on the rehomed primary: exactly one send ever.
      expect(primary.request).toHaveBeenCalledTimes(1)
      // Fulfillment bailed before publishing A's descriptor; rejection bailed
      // in the catch before setConnection(null). No obsolete dial/re-mint.
      expect($connection.get()).toBe(connectionB)
      expect(primary.connect).not.toHaveBeenCalled()
      expect(desktop.getGatewayWsUrl).not.toHaveBeenCalled()

      // B's Attention remains live with B's open row — A's late read never
      // flips B stale or replaces B's rows.
      expect($attentionSyncState.get()).toBe('live')
      expect($attentionItems.get()).toHaveLength(1)
      expect($attentionItems.get()[0]?.id).toBe('zz-tes_b')
      expect($attentionItems.get()[0]?.state).toBe('open')
    }
  )

  it('a same-scope reconnect failure keeps the normal cleanup — the stale descriptor is cleared and the reauth error surfaces', async () => {
    const desktop = installPrimaryDesktop('token')
    const primary = makePrimaryGateway()
    primary.request.mockRejectedValueOnce(new Error('connection closed'))

    setPrimaryGateway(primary as unknown as HermesGateway, 'default')
    $gateway.set(primary as unknown as HermesGateway)
    $gatewayState.set('idle')

    // A's descriptor is currently published; the failed same-scope recovery
    // must clear this now-invalid descriptor (the pre-fix behavior).
    const connectionA: PrimaryConnectionDescriptor = {
      authMode: 'token',
      baseUrl: 'http://127.0.0.1:5151',
      mode: 'local',
      profile: 'default',
      token: 'primary-token',
      wsUrl: 'ws://127.0.0.1:5151/api/ws?token=A'
    }

    setConnection(connectionA as unknown as HermesConnection)

    // Park the recovery in getConnection, then fail it with a reauth
    // rejection while the scope HOLDS.
    const connection = deferred<PrimaryConnectionDescriptor>()

    desktop.getConnection.mockReturnValue(connection.promise)

    const { result } = renderHook(() => useGatewayRequest())

    const scope = currentAttentionScopeToken()

    const pending = result.current
      .requestGateway(
        'cron.manage',
        { action: 'ack_attention', kind: 'cron_incident', id: 'zz-tes_a' },
        undefined,
        undefined,
        { scopeGuard: () => currentAttentionScopeToken() === scope }
      )
      .then(
        () => undefined,
        error => error
      )

    await act(async () => {
      await vi.waitFor(() => expect(desktop.getConnection).toHaveBeenCalled())
    })

    const reauthError = Object.assign(new Error('session expired'), { needsOauthLogin: true })
    connection.reject(reauthError)

    const outcome = await act(async () => pending)
    expect(outcome).toBe(reauthError)

    // Same-scope cleanup preserved: the stale descriptor was cleared and the
    // actionable reauth error surfaced instead of the opaque transport error.
    expect($connection.get()).toBeNull()
    expect(primary.request).toHaveBeenCalledTimes(1)
    expect(primary.connect).not.toHaveBeenCalled()
  })

  it('rejects instead of hanging forever when the reconnect getConnection() wedges (#93454)', async () => {
    // Repro: a request lands on a dropped socket, the "not connected" catch
    // kicks off a reconnect, and the IPC round-trip into main
    // (desktop.getConnection) never settles — e.g. a wedged revalidation after
    // a liveness-probe trip. Without an internal timeout on that await,
    // reconnectingRef never clears and requestGateway hangs forever instead of
    // surfacing the original transport error.
    vi.useFakeTimers()

    const dropped = {
      connectionState: 'closed',
      request: vi.fn().mockRejectedValue(new Error('connection closed'))
    } as unknown as HermesGateway

    const getConnection = vi.fn(() => new Promise(() => undefined))

    ;(window as unknown as { hermesDesktop: unknown }).hermesDesktop = { getConnection }
    $gateway.set(dropped)

    const { result } = renderHook(() => useGatewayRequest())

    const pending = expect(result.current.requestGateway('some.method')).rejects.toThrow('connection closed')

    // Advance past the internal reconnect-attempt timeout (20s) — the stalled
    // getConnection() await must reject so the reconnect gives up and the
    // original transport error surfaces, instead of requestGateway() never
    // settling.
    await vi.advanceTimersByTimeAsync(20_000)
    await pending
  })
})
