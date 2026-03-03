import type {CleanupContext, ResolvedCsrfMiddlewareOptions} from "../types/types.js";
import {clearInterval, setInterval} from "node:timers";

export const runInternalCleanup = (
  ref: CleanupContext,
  options: ResolvedCsrfMiddlewareOptions
): void => {
  const interval = setInterval(() => {
    try {
      const stackId = ref.calculatePreviousExpireStackId(Date.now())
      if (!ref.usedTokens[stackId]) return
      ref.usedTokens[stackId].forEach(hash => delete ref.localUsedStack[hash])
      delete ref.usedTokens[stackId]
    } catch (e) {
      if (options.internals.debug) options.internals.debug('csrf cleanup error', e)
    }
  }, options.csrfToken.ttl).unref()

  options.internals.signal?.addEventListener('abort', () => clearInterval(interval))
}
