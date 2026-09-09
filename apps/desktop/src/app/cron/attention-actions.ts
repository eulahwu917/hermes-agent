import {
  beginAttentionRequest,
  commitAttentionItems,
  currentAttentionScopeToken,
  isAttentionRequestCurrent,
  markAttentionStale,
  parseAttentionItems
} from '@/store/attention'
import type { AttentionAckResult, AttentionItem } from '@/types/hermes'

import type { GatewayRequester } from '../contrib/types'

// The unified Attention read model lives behind the cron.manage RPC actions
// (list_attention / ack_attention). These actions mirror cron-actions.ts:
// generation-guarded so a stale response can never overwrite newer intent,
// and fail-STALE on any read/ack failure (never an empty list, never a green
// badge).
//
// Scope (profile/connection) contract: a response that belongs to a torn-down
// scope is SIDE-EFFECT-FREE — it never writes an atom (items/live/stale) and
// never surfaces as the NEW scope's failure. Reads and the ack additionally
// pin their target through the requester itself: the scope guard aborts the
// send AND every reconnect/retry (and the post-recovery replay), so a
// transport failure mid-switch can never publish/dial over the now-active
// gateway B or replay A's RPC against it.

export interface AttentionListResult {
  items: AttentionItem[] | null
  error: unknown | null
  stale: boolean
}

/** An ack whose scope (profile/connection) was torn down mid-flight. The
 *  caller treats it as a non-event: the row belongs to a backend the UI no
 *  longer shows, and the new scope owns its own refresh. */
export class AttentionScopeChangedError extends Error {
  constructor() {
    super('attention scope changed during ack')
    this.name = 'AttentionScopeChangedError'
  }
}

interface ListAttentionResponse {
  items?: unknown
}

interface AckAttentionResponse {
  status?: unknown
  changed?: unknown
}

export async function refreshAttention(requestGateway: GatewayRequester): Promise<AttentionListResult> {
  const token = beginAttentionRequest()

  // Scope-pinned exactly like the ack: the guard travels INSIDE the request
  // (checked before the send, before every reconnect/retry, and again after
  // the async recovery by use-gateway-request), so an obsolete scope's
  // recovery can never publish its stale descriptor over the new connection
  // (setConnection drives filesystem routing), dial the shared primary
  // object, or replay the read on the now-active gateway.
  const scope = currentAttentionScopeToken()
  const scopeGuard = () => currentAttentionScopeToken() === scope

  try {
    const response = await requestGateway<ListAttentionResponse>('cron.manage', {
      action: 'list_attention',
      open_only: true
    }, undefined, undefined, { scopeGuard })

    // Ownership check FIRST: a late response from a torn-down scope/generation
    // must not validate its payload against the new scope or write any atom.
    if (!isAttentionRequestCurrent(token)) {
      return { items: null, error: null, stale: true }
    }

    const items = parseAttentionItems(response?.items)

    if (items === null) {
      markAttentionStale()

      return { items: null, error: new Error('invalid attention payload'), stale: true }
    }

    commitAttentionItems(token, items)

    return { items, error: null, stale: false }
  } catch (error) {
    if (!isAttentionRequestCurrent(token)) {
      return { items: null, error: null, stale: true }
    }

    markAttentionStale()

    return { items: null, error, stale: false }
  }
}

export async function ackAttentionItem(
  requestGateway: GatewayRequester,
  kind: AttentionItem['kind'],
  id: string
): Promise<AttentionAckResult> {
  // Scope-pinned: the ack targets the backend/profile whose rows the user clicked.
  // The guard travels INSIDE the request (checked before the initial send and
  // before every reconnect/retry by use-gateway-request), so a transport failure
  // after a switch aborts the request instead of replaying it on the new gateway.
  const scope = currentAttentionScopeToken()
  const scopeGuard = () => currentAttentionScopeToken() === scope

  try {
    const response = await requestGateway<AckAttentionResponse>(
      'cron.manage',
      { action: 'ack_attention', kind, id },
      undefined,
      undefined,
      { scopeGuard }
    )

    if (currentAttentionScopeToken() !== scope) {
      throw new AttentionScopeChangedError()
    }

    if (response?.status === 'closed-ok' || response?.status === 'already-closed') {
      return { status: response.status, changed: response.changed === true }
    }

    // Anything else (error response mapped by the client, or a shape we do not
    // recognize) is a failed ack — the row stays in place.
    throw new Error(response?.status ? `unexpected ack outcome: ${String(response.status)}` : 'ack failed')
  } catch (error) {
    // Obsolete-scope outcomes are side-effect-free: an old ack's rejection,
    // success, or transport failure must never flip the CURRENT scope stale
    // (B stays live with B's rows). Same-scope failures keep driving the
    // persistent stale state — the section/badge must never present an
    // all-clear after a failure (last-known rows are retained).
    if (currentAttentionScopeToken() !== scope) {
      throw error instanceof AttentionScopeChangedError ? error : new AttentionScopeChangedError()
    }

    markAttentionStale()

    throw error
  }
}
