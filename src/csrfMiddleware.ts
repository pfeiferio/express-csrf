import crypto from 'crypto'
import {defaultOnTokenRejected, defaultScopeResolver, defaultTokenLookup} from "./utils.js";
import type {CsrfMiddlewareOptions, ResolvedCsrfMiddlewareOptions} from "./types/types.js";
import {validatedOptions} from "./csrf-middleware/validatedOptions.js";
import type {RequestHandler} from 'express'
import {createCsrfToken} from "./token/createCsrfToken.js";
import {validateCsrfToken} from "./token/validateCsrfToken.js";
import {createUseCsrfToken} from "./token/useCsrfToken.js";


export const csrfMiddlewareDefaults: ResolvedCsrfMiddlewareOptions = {
  internals: {
    signal: undefined,
    cleanupProcess: undefined,
    store: undefined,
    debug: undefined
  },
  csrfToken: {
    ttl: 60 * 5 * 1000,
    lookup: defaultTokenLookup,
    scopeResolver: defaultScopeResolver,
  },
  csrfSecretCookie: {
    name: '__csrf',
    path: '/',
    ttl: 7 * 24 * 60 * 60 * 1000,
    domain: undefined,
    secure: true,
    sameSite: 'strict',
    cookieReader: (req) =>
      req.cookies
      ?? {}
  },
  guard: {
    jsonOnly: true,
    origin: false,
    onTokenRejected: defaultOnTokenRejected,
    exclude: undefined,
    skipTokenCreation: undefined,
    skipValidation: undefined,
  }
}

/**
 * Express middleware factory for CSRF protection using short-lived,
 * one-time tokens bound to browser context.
 *
 * Security properties:
 * - CSRF tokens are time-limited (TTL)
 * - Tokens are single-use (replay protection)
 * - Tokens are bound to browser characteristics (IP prefix + User-Agent)
 * - Optional Origin validation
 * - Optional JSON-only enforcement
 * - CSRF secret is stored in an HttpOnly, SameSite cookie
 *
 * Design notes:
 * - Multiple CSRF tokens may be valid in parallel
 * - Tokens are flow-bound, not session-bound
 * - Token replay is prevented via an in-memory used-token registry
 * - Cleanup MUST be enabled to avoid unbounded memory growth
 *
 * @see CsrfMiddlewareOptions
 */
export const csrfMiddleware = (options: CsrfMiddlewareOptions): RequestHandler => {

  const resolvedOptions = validatedOptions(options, csrfMiddlewareDefaults)

  const useCsrfToken = createUseCsrfToken(resolvedOptions)

  /**
   * Express middleware handling CSRF secret management and token validation.
   *
   * Responsibilities:
   * - Ensures a CSRF secret exists in an HttpOnly cookie
   * - Issues new CSRF tokens for GET requests
   * - Validates CSRF tokens for state-changing requests
   * - Rejects invalid or replayed tokens
   *
   * Requests using safe HTTP methods (GET, HEAD, OPTIONS) bypass validation.
   *
   * @returns Express middleware function.
   */
  return async (req, res, next) => {

    const isExcluded = resolvedOptions.guard.exclude?.(req) ?? false
    const shouldSkipCreation = isExcluded || (resolvedOptions.guard.skipTokenCreation?.(req) ?? false)
    const shouldSkipValidation = isExcluded || (resolvedOptions.guard.skipValidation?.(req) ?? false)

    let secretFromCookie: string | undefined = resolvedOptions.csrfSecretCookie.cookieReader(req)[resolvedOptions.csrfSecretCookie.name]

    req.csrf = {
      hasSecret: () => !!secretFromCookie,
      generateToken: () => secretFromCookie
        ? createCsrfToken(resolvedOptions, req, secretFromCookie!)
        : false,
      isExcluded: () => isExcluded,
      isTokenCreationSkipped: () => shouldSkipCreation,
      isValidationSkipped: () => shouldSkipValidation
    }

    if (isExcluded) return next()

    if (!shouldSkipCreation && !secretFromCookie) {
      const secret = crypto.randomBytes(32).toString('hex')
      secretFromCookie = secret
      res.cookie(
        resolvedOptions.csrfSecretCookie.name,
        secret,
        {
          path: resolvedOptions.csrfSecretCookie.path,
          expires: new Date(Date.now() + resolvedOptions.csrfSecretCookie.ttl),
          domain: resolvedOptions.csrfSecretCookie.domain,
          httpOnly: true,
          sameSite: resolvedOptions.csrfSecretCookie.sameSite,
          secure: resolvedOptions.csrfSecretCookie.secure
        }
      )
    }

    if (req.method === 'GET' && secretFromCookie) {
      res.locals.csrfToken = createCsrfToken(resolvedOptions, req, secretFromCookie)
    }

    if (shouldSkipValidation || ['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return next()
    }

    const result = await validateCsrfToken(resolvedOptions, req, secretFromCookie, useCsrfToken)
    if (!result.valid) {
      resolvedOptions.guard.onTokenRejected(req, res, next, result)
      return
    }
    next()
  }
}
