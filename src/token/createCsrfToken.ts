import crypto from 'crypto'
import {createBrowserSignature} from "./createBrowserSignature.js";
import {sha256Hmac} from "../utils/crypto.js";
import type {Request} from 'express'
import type {ResolvedCsrfMiddlewareOptions} from "../types/types.js";

/**
 *
 * Creates a function that marks CSRF tokens as used and prevents replay.
 *
 * Tokens are hashed before storage to avoid keeping raw values in memory.
 * An optional external store can be provided for multi-instance deployments.
 * If no store is configured, an in-memory registry is used as fallback.
 *
 * Cleanup is performed either via an internal timer or an externally
 * provided cleanup handler.
 *
 * @returns A function that consumes a token and returns true if the token
 *          was valid and unused, false if it was already consumed.
 */
export const createCsrfToken = (
  options: ResolvedCsrfMiddlewareOptions,
  req: Request,
  secret: string
): string => {
  const random = crypto.randomBytes(16).toString('hex')
  const expires = Date.now() + options.csrfToken.ttl
  const data = [random, expires, createBrowserSignature(req, secret)].join('|')
  return Buffer.from(`${data}|${sha256Hmac(data, secret)}`).toString('base64')
}
