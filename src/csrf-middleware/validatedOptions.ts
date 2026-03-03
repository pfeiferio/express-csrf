import {CsrfConfigError} from '../CsrfConfigError.js'
import type {CsrfMiddlewareOptions, ResolvedCsrfMiddlewareOptions} from "../types/types.js";

/**
 * Merges user-provided options with defaults and validates the result.
 * Throws {@link CsrfConfigError} for any invalid configuration.
 */
export const validatedOptions = (
  options: CsrfMiddlewareOptions,
  defaults: ResolvedCsrfMiddlewareOptions
): ResolvedCsrfMiddlewareOptions => {

  //function v<G extends keyof ResolvedCsrfMiddlewareOptions>(
  //  group: G
  //): ResolvedCsrfMiddlewareOptions[G]
  function v<
    G extends keyof ResolvedCsrfMiddlewareOptions,
    K extends keyof ResolvedCsrfMiddlewareOptions[G]
  >(
    group: G,
    key: K
  ): ResolvedCsrfMiddlewareOptions[G][K]
  function v<
    G extends keyof ResolvedCsrfMiddlewareOptions,
    K extends keyof ResolvedCsrfMiddlewareOptions[G]
  >(group: G, key?: K) {
    //  if (key === undefined) {
    //    return options[group] ?? defaults[group]
    //  }
    return (options[group] as any)?.[key] ?? (defaults[group] as any)[key]
  }

  const cleanupProcess = v('internals', 'cleanupProcess')
  const debug = v('internals', 'debug')
  const store = v('internals', 'store')
  const tokenTtl = v('csrfToken', 'ttl')
  const tokenLookup = v('csrfToken', 'lookup')
  const scopeResolver = v('csrfToken', 'scopeResolver')
  const cookieName = v('csrfSecretCookie', 'name')
  const cookiePath = v('csrfSecretCookie', 'path')
  const cookieTtl = v('csrfSecretCookie', 'ttl')
  const cookieDomain = v('csrfSecretCookie', 'domain')
  const cookieSecure = v('csrfSecretCookie', 'secure')
  const cookieSameSite = v('csrfSecretCookie', 'sameSite')
  const jsonOnly = v('guard', 'jsonOnly')
  const origin = v('guard', 'origin')
  const onTokenRejected = v('guard', 'onTokenRejected')
  const exclude = v('guard', 'exclude')
  const skipTokenCreation = v('guard', 'skipTokenCreation')
  const skipValidation = v('guard', 'skipValidation')
  const signal = v('internals', 'signal')
  const cookieReader = v('csrfSecretCookie', 'cookieReader')

  if (signal !== undefined && (
    typeof signal !== 'object' ||
    signal === null ||
    typeof signal.aborted !== 'boolean' ||
    typeof signal.addEventListener !== 'function'
  )) {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "internals.signal" must be an AbortSignal'
    )
  }

  if (typeof cookieReader !== 'function') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "csrfSecretCookie.cookieReader" must be a function'
    )
  }

  if (debug !== undefined && typeof debug !== 'function') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "internals.debug" must be a function'
    )
  }

  if (store !== undefined && (
    typeof store.has !== 'function' ||
    typeof store.set !== 'function'
  )) {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "internals.store" must implement has and set'
    )
  }

  if (typeof tokenLookup !== 'function') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "csrfToken.lookup" must be a function'
    )
  }

  if (cleanupProcess !== undefined && typeof cleanupProcess !== 'function') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "cleanupProcess" must be a function'
    )
  }

  if (!cookieName || typeof cookieName !== 'string') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "csrfSecretCookie.name" must be a non-empty string'
    )
  }

  if (typeof tokenTtl !== 'number' || tokenTtl <= 0) {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "csrfToken.ttl" must be a positive number (milliseconds)'
    )
  }

  if (typeof cookieTtl !== 'number' || cookieTtl <= 0) {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "csrfSecretCookie.ttl" must be a positive number (milliseconds)'
    )
  }

  if (origin !== false && typeof origin !== 'string') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "guard.origin" must be a string or false'
    )
  }

  if (typeof scopeResolver !== 'function') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "csrfToken.scopeResolver" must be a function'
    )
  }

  if (typeof jsonOnly !== 'boolean') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "guard.jsonOnly" must be a boolean'
    )
  }

  if (!['strict', 'lax', 'none'].includes(cookieSameSite)) {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "csrfSecretCookie.sameSite" must be "strict", "lax", or "none"'
    )
  }

  if (cookieSameSite === 'none' && !cookieSecure) {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "csrfSecretCookie.secure" must be true when "sameSite" is "none"'
    )
  }

  if (onTokenRejected !== undefined && typeof onTokenRejected !== 'function') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "guard.onTokenRejected" must be a function'
    )
  }

  if (exclude !== undefined && typeof exclude !== 'function') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "guard.exclude" must be a function'
    )
  }

  if (skipTokenCreation !== undefined && typeof skipTokenCreation !== 'function') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "guard.skipTokenCreation" must be a function'
    )
  }

  if (skipValidation !== undefined && typeof skipValidation !== 'function') {
    throw new CsrfConfigError(
      'Invalid csrfMiddleware configuration: "guard.skipValidation" must be a function'
    )
  }

  return {
    internals: {
      signal,
      debug,
      cleanupProcess,
      store
    },
    csrfToken: {
      ttl: tokenTtl,
      lookup: tokenLookup,
      scopeResolver,
    },
    csrfSecretCookie: {
      cookieReader,
      name: cookieName,
      path: cookiePath,
      ttl: cookieTtl,
      domain: cookieDomain,
      secure: cookieSecure,
      sameSite: cookieSameSite,
    },
    guard: {
      jsonOnly,
      origin,
      onTokenRejected,
      exclude,
      skipTokenCreation,
      skipValidation,
    }
  }
}
