import {sha256Hmac} from "../utils/crypto.js";
import type {
  CsrfValidationFailReason,
  CsrfValidationResult,
  ResolvedCsrfMiddlewareOptions,
  UseCsrfToken
} from "../types/types.js";
import type {Request} from 'express'
import crypto from 'crypto'
import {compareSignatures} from "../utils/compareSignatures.js";
import {createBrowserSignature} from "./createBrowserSignature.js";

const LENGTH_SHA256 = 64

export const validateCsrfToken = async (
  options: ResolvedCsrfMiddlewareOptions,
  req: Request,
  secret: string | undefined,
  useCsrfToken: UseCsrfToken
): Promise<CsrfValidationResult> => {

  const fail = (reason: CsrfValidationFailReason): CsrfValidationResult => {
    if (options.internals.debug) options.internals.debug(`csrf validation failed: ${reason}`, {req})
    return {valid: false, reason}
  }

  if (!secret) return fail('missing_secret')

  if (options.guard.origin && req.get('origin') !== options.guard.origin)
    return fail('origin_mismatch')

  if (options.guard.jsonOnly) {
    const isJson = req.is('application/json')
      ?? req.headers['content-type']
        ?.split(';')[0]
        ?.toLowerCase()
      === 'application/json'

    if (!isJson) {
      return fail('invalid_content_type')
    }
  }

  try {
    const token = options.csrfToken.lookup(req)
    const scope = options.csrfToken.scopeResolver(req)

    if (!token) return fail('missing_token')

    const decoded = Buffer.from(token, 'base64').toString('utf8')
    const [random, expires, browserSignature, signature] = decoded.split('|')

    if (
      !random
      || !expires
      || !browserSignature
      || !signature
      || browserSignature.length !== LENGTH_SHA256
      || signature.length !== LENGTH_SHA256
    ) return fail('invalid_structure')

    const expiresNum = Number(expires)
    if (isNaN(expiresNum)) return fail('invalid_structure')

    const expireDiff = expiresNum - Date.now()
    if (expireDiff < 0 || expireDiff > options.csrfToken.ttl)
      return fail('expired')

    const validBrowserSignature = compareSignatures(
      Buffer.from(browserSignature),
      Buffer.from(createBrowserSignature(req, secret))
    )
    if (!validBrowserSignature) return fail('browser_signature_mismatch')

    const isValidToken = crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(sha256Hmac([random, expires, browserSignature].join('|'), secret))
    )
    if (!isValidToken) return fail('invalid_signature')

    const used = await useCsrfToken(`${scope}:${token}`)
    if (!used) return fail('token_already_used')

    return {valid: true}
  } catch (e) {
    if (options.internals.debug) options.internals.debug('csrf validation error', e)
    return fail('unknown')
  }
}
