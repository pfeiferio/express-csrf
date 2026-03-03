import crypto from "crypto";

/**
 * Computes a SHA-256 hash of the given data.
 * Used to hash CSRF tokens before storing them in memory.
 */
export const sha256 = (data: string): string =>
  crypto.createHash('sha256').update(data).digest('hex')

/**
 * Computes an HMAC-SHA256 signature.
 * Used to sign CSRF token components and browser signatures.
 */
export const sha256Hmac = (data: string, secret: string): string =>
  crypto.createHmac('sha256', secret).update(data).digest('hex')
