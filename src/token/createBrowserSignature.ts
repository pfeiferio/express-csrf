import {sha256Hmac} from "../utils/crypto.js";
import {getNormalizedIp} from "../utils/ip.js";
import type {Request} from 'express'

/**
 * Creates a browser-bound signature for CSRF tokens.
 *
 * The signature binds a token to the requesting browser context using
 * a normalized IP prefix and the User-Agent string.
 *
 * This value is HMAC-signed and has a fixed length.
 *
 * @param req Express request object.
 * @param secret Per-client CSRF secret stored in an HttpOnly cookie.
 *
 * @returns Hex-encoded HMAC-SHA256 browser signature.
 */
export const createBrowserSignature = (
  req: Request,
  secret: string
): string => sha256Hmac(`${getNormalizedIp(req)}|${req.get('user-agent')}`, secret)

