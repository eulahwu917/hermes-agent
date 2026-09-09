import { isGatewayReauthRequired, resolveGatewayWsUrl } from '@hermes/shared'
import { useStore } from '@nanostores/react'
import { useCallback, useEffect, useRef } from 'react'

import type { HermesGateway } from '@/hermes'
import { RECONNECT_ATTEMPT_TIMEOUT_MS, withTimeout } from '@/lib/with-timeout'
import { $gateway, ensureActiveGatewayOpen, isActivePrimary } from '@/store/gateway'
import { $activeGatewayProfile } from '@/store/profile'
import { $gatewayState, setConnection } from '@/store/session'

/** Per-request scope pinning for callers whose target is tied to a
 *  profile/connection that can be torn down mid-flight. */
export interface GatewayRequestOptions {
  /**
   * Checked before the initial send, before every reconnect/retry, and again
   * immediately before the recovered replay — a scope can be torn down while
   * the asynchronous reconnect is in flight. When it reports false the
   * request aborts instead of being replayed against the now-active route: a
   * scope-pinned mutation must never act as the new scope's mutation.
   */
  scopeGuard?: () => boolean
}

export function useGatewayRequest() {
  const gatewayState = useStore($gatewayState)
  // Reactive companion to `gatewayRef`. The ref exists so `requestGateway`
  // keeps a stable identity and always reaches the live socket, but it is only
  // populated by the subscription effect below — i.e. AFTER the first render.
  // A component that reads `gatewayRef.current` while rendering therefore sees
  // null on mount, and if the connection state doesn't happen to flip
  // afterwards it never re-renders to pick the instance up. Anything that needs
  // the gateway as a render-time VALUE (props, memo deps) must use this.
  const gateway = useStore($gateway) as HermesGateway | null
  const gatewayRef = useRef<HermesGateway | null>(null)

  const connectionRef = useRef<Awaited<ReturnType<NonNullable<typeof window.hermesDesktop>['getConnection']>> | null>(
    null
  )

  const gatewayStateRef = useRef(gatewayState)
  const reconnectingRef = useRef<Promise<HermesGateway | null> | null>(null)
  // Holds the reauth error from the most recent failed reconnect so
  // requestGateway can surface the gateway's "session expired, sign in again"
  // message instead of the opaque "connection closed" that triggered the retry.
  const reauthErrorRef = useRef<unknown>(null)

  // eslint-disable-next-line no-restricted-syntax -- legitimate non-atom ref write (see eslint rule comment)
  useEffect(() => {
    gatewayStateRef.current = gatewayState
  }, [gatewayState])

  // Track the active gateway (primary or a background profile's socket) so
  // outbound requests and overlay props always target the focused profile.
  useEffect(
    () =>
      $gateway.subscribe(gateway => {
        gatewayRef.current = gateway as HermesGateway | null
      }),
    []
  )

  const ensureGatewayOpen = useCallback(async (scopeChanged?: () => boolean) => {
    const existing = gatewayRef.current

    if (!existing) {
      return null
    }

    if (gatewayStateRef.current === 'open') {
      return existing
    }

    if (reconnectingRef.current) {
      return reconnectingRef.current
    }

    reconnectingRef.current = (async () => {
      const desktop = window.hermesDesktop

      if (!desktop) {
        return null
      }

      reauthErrorRef.current = null

      try {
        // Reconnect to whichever profile the gateway is currently routed to (not
        // always the primary), so a sleep/wake reconnect keeps the user on the
        // profile they were chatting in. Both awaits below are IPC round-trips
        // into the main process with no timeout of their own (#93454) — a
        // wedged main-process round-trip otherwise hangs this await forever,
        // latching reconnectingRef.current so every later requestGateway() call
        // returns the same never-settling promise. Bound the same way
        // use-gateway-boot.ts bounds the primary boot/soft-switch equivalents.
        const conn = await withTimeout(
          desktop.getConnection($activeGatewayProfile.get()),
          RECONNECT_ATTEMPT_TIMEOUT_MS,
          'Timed out reconnecting to Hermes backend'
        )

        // A scope-pinned request's target can be torn down while this IPC
        // round-trip was in flight (the soft-apply path reuses the primary
        // gateway OBJECT and re-homes it to the new backend). Publishing this
        // descriptor now would clobber the newly selected primary's connection
        // — bail instead; the caller re-validates before any replay.
        if (scopeChanged?.()) {
          return null
        }

        connectionRef.current = conn
        setConnection(conn)

        // Re-mint the WS URL before reconnecting. OAuth tickets are single-use
        // and short-lived, so the cached conn.wsUrl ticket is dead here;
        // resolveGatewayWsUrl() never connects with a stale ticket. An explicit
        // auth rejection becomes a reauth error; transport failures remain
        // retryable. Stash only the former so requestGateway can show the
        // actionable "sign in again" message.
        const wsUrl = await withTimeout(
          resolveGatewayWsUrl(desktop, conn),
          RECONNECT_ATTEMPT_TIMEOUT_MS,
          'Timed out re-minting the gateway WebSocket URL'
        )

        // Same re-check between ticket mint and dial: the minted URL belongs
        // to the scope this reconnect started under, and connecting the shared
        // primary object after a switch would replace the new backend's
        // socket.
        if (scopeChanged?.()) {
          return null
        }

        await existing.connect(wsUrl)

        return existing
      } catch (error) {
        // Scope ownership governs the failure continuation too: every await
        // above (connection IPC, ticket mint, dial) can REJECT after a scope
        // switch landed mid-flight, and that failure belongs to the torn-down
        // scope. Clearing the connection here would erase the newly selected
        // primary's published descriptor (setConnection drives scoped stores
        // and remote-fs routing), and stashing a reauth error would later
        // surface A's expired session as B's. Obsolete-scope failure handling
        // is side-effect-free — the caller re-validates and aborts before any
        // replay; the same-scope path below keeps its normal cleanup.
        if (scopeChanged?.()) {
          return null
        }

        if (isGatewayReauthRequired(error)) {
          reauthErrorRef.current = error
        }

        connectionRef.current = null
        setConnection(null)

        return null
      } finally {
        reconnectingRef.current = null
      }
    })()

    return reconnectingRef.current
  }, [])

  const requestGateway = useCallback(
    async <T>(
      method: string,
      params: Record<string, unknown> = {},
      timeoutMs?: number,
      signal?: AbortSignal,
      options?: GatewayRequestOptions
    ) => {
      const gateway = gatewayRef.current

      if (!gateway) {
        throw new Error('Hermes gateway unavailable')
      }

      const scopeChanged = (): boolean =>
        options?.scopeGuard !== undefined && !options.scopeGuard()

      if (scopeChanged()) {
        // The scope this request belongs to was torn down before the send:
        // sending now would target the wrong backend, so abort instead.
        throw new Error('gateway request scope changed before send')
      }

      try {
        return await gateway.request<T>(method, params, timeoutMs, signal)
      } catch (error) {
        if (!isGatewayTransportError(error)) {
          throw error
        }

        // Recovery resolves from the CURRENT active route. A scope-pinned
        // mutation must never retarget: when its scope was torn down
        // mid-flight (profile/connection switch), replaying the method on the
        // now-active gateway would route A's mutation at B. Abort instead.
        if (scopeChanged()) {
          throw new Error('gateway request scope changed before retry')
        }

        // Primary keeps the OAuth-aware reconnect (remote gateways re-mint a
        // single-use ticket). Background profiles stay on the registry's
        // connection-owned reconnect path, including composite remote/SSH
        // sources.
        const recovered = isActivePrimary() ? await ensureGatewayOpen(scopeChanged) : await ensureActiveGatewayOpen()

        // Re-validate AFTER the asynchronous recovery: a scope can be torn
        // down while the reconnect is in flight (the soft-apply path re-homes
        // the primary gateway OBJECT this recovery shares), so a guard that
        // passed before the await proves nothing about the socket the replayed
        // send would use. Re-check immediately before replaying.
        if (scopeChanged()) {
          throw new Error('gateway request scope changed before replay')
        }

        if (!recovered) {
          // Prefer the reauth error from the failed reconnect (OAuth session
          // expired) over the generic transport error that triggered the retry.
          const reauthError = reauthErrorRef.current
          reauthErrorRef.current = null

          if (reauthError) {
            throw reauthError
          }

          throw error
        }

        return recovered.request<T>(method, params, timeoutMs, signal)
      }
    },
    [ensureGatewayOpen]
  )

  return { connectionRef, gateway, gatewayRef, requestGateway }
}

const GATEWAY_TRANSPORT_ERROR_CODES = new Set([
  'ECONNABORTED',
  'ECONNREFUSED',
  'ECONNRESET',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EPIPE',
  'ETIMEDOUT',
  'ERR_NETWORK',
  'ERR_SOCKET_CLOSED'
])

function errorCode(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) {
    return null
  }

  const code = (value as { code?: unknown }).code

  return typeof code === 'string' ? code.toUpperCase() : null
}

function isGatewayTransportError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error)

  if (/not connected|connection closed|connection reset|ECONNRESET/i.test(message)) {
    return true
  }

  const cause = typeof error === 'object' && error !== null ? (error as { cause?: unknown }).cause : undefined

  return [error, cause].some(value => {
    const code = errorCode(value)

    return code !== null && GATEWAY_TRANSPORT_ERROR_CODES.has(code)
  })
}
