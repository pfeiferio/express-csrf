import type {NextFunction, Request, RequestHandler, Response} from 'express'

export type CsrfRequestPredicate = (req: Request) => boolean

export type CsrfCookieReader = (req: Request) => Record<string, string>

export interface CsrfMiddlewareOptions {
  csrfToken?: {
    ttl?: number
    lookup?: (req: Request) => string | undefined
    scopeResolver?: (req: Request) => string
  }
  csrfSecretCookie?: {
    name?: string
    path?: string
    ttl?: number
    domain?: string
    secure?: boolean
    sameSite?: 'strict' | 'lax' | 'none'
    cookieReader?: CsrfCookieReader
  }
  guard?: {
    jsonOnly?: boolean
    origin?: string | false
    onTokenRejected?: RequestHandler
    exclude?: CsrfRequestPredicate
    skipTokenCreation?: CsrfRequestPredicate
    skipValidation?: CsrfRequestPredicate
  }
  internals?: {
    signal?: AbortSignal
    store?: CsrfStoreAdapter
    cleanupProcess?: ((ref: CleanupContext, options: ResolvedCsrfMiddlewareOptions) => void)
    debug?: (msg: string, ctx: unknown) => void
  }
}

export interface ResolvedCsrfMiddlewareOptions {
  csrfToken: {
    ttl: number
    lookup: (req: Request) => string | undefined
    scopeResolver: (req: Request) => string
  }
  csrfSecretCookie: {
    name: string
    path: string
    ttl: number
    domain: string | undefined
    secure: boolean
    sameSite: 'strict' | 'lax' | 'none'
    cookieReader: CsrfCookieReader
  }
  guard: {
    jsonOnly: boolean
    origin: string | false
    onTokenRejected: (req: Request, res: Response, next: NextFunction, result: CsrfValidationResult) => void
    exclude: CsrfRequestPredicate | undefined
    skipTokenCreation: CsrfRequestPredicate | undefined
    skipValidation: CsrfRequestPredicate | undefined
  },
  internals: {
    signal: AbortSignal | undefined
    store: CsrfStoreAdapter | undefined
    cleanupProcess: undefined | ((ref: CleanupContext, options: ResolvedCsrfMiddlewareOptions) => void)
    debug: undefined | ((msg: string, ctx: unknown) => void)
  }
}


export interface CleanupContext {
  usedTokens: Record<string, string[]>
  localUsedStack: Record<string, boolean>
  calculatePreviousExpireStackId: (t: number) => string
}


/**
 * Marks a CSRF token as used and prevents replay.
 *
 * Tokens are stored as SHA-256 hashes to avoid keeping raw token values
 * in memory.
 *
 * Cleanup is performed either via an internal timer or an externally
 * provided cleanup handler.
 * @param {string} token
 *        Base64-encoded CSRF token.
 *
 * @returns {boolean}
 *          True if the token was not used before and is now consumed,
 *          false if the token was already used.
 */
export type UseCsrfToken = (token: string, peekOnly?: boolean) => Promise<boolean>

export interface CsrfStoreAdapter {
  has(key: string): Promise<boolean>

  set(key: string, ttlMs: number): Promise<void>
}

export type CsrfValidationFailReason =
  | 'origin_mismatch'
  | 'invalid_content_type'
  | 'missing_token'
  | 'invalid_structure'
  | 'expired'
  | 'browser_signature_mismatch'
  | 'invalid_signature'
  | 'token_already_used'
  | 'missing_secret'
  | 'unknown'

export type CsrfValidationResult =
  | { valid: true }
  | { valid: false; reason: CsrfValidationFailReason }
