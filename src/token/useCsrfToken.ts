import type {ResolvedCsrfMiddlewareOptions, UseCsrfToken} from "../types/types.js";
import {sha256} from "../utils/crypto.js";
import {runInternalCleanup} from "../cleanup/cleanup.js";

export const createUseCsrfToken = (
  options: ResolvedCsrfMiddlewareOptions
): UseCsrfToken => {

  const calculateExpireStackId =
    (t: number): string => (t - (t % options.csrfToken.ttl) + 2 * options.csrfToken.ttl).toString()
  const calculatePreviousExpireStackId =
    (t: number): string => (t - (t % options.csrfToken.ttl) + options.csrfToken.ttl).toString()

  const usedTokens: Record<string, Array<string>> = {}
  const localUsedStack: Record<string, boolean> = {}

  const context = {
    usedTokens,
    calculatePreviousExpireStackId,
    localUsedStack,
  }

  if (options.internals.cleanupProcess) options.internals.cleanupProcess(context, options)
  runInternalCleanup(context, options)

  return (async (token, peekOnly = false) => {
    const tokenHash = sha256(token)
    const tokenInUse = localUsedStack[tokenHash] ?? false
    if (tokenInUse) return false
    if (await options.internals.store?.has(tokenHash)) return false
    if (peekOnly) return true
    await options.internals.store?.set(tokenHash, options.csrfToken.ttl)
    localUsedStack[tokenHash] = true
    const stackId = calculateExpireStackId(Date.now())
    usedTokens[stackId] ??= []
    usedTokens[stackId].push(tokenHash)
    return true
  })
}
