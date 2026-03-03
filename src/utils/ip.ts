import type {Request} from 'express'

/**
 * Normalizes an IP address for browser binding.
 *
 * - IPv4 addresses are reduced to a /24 prefix
 * - IPv6 addresses are reduced to a /64 prefix
 *
 * This reduces false positives caused by mobile networks and proxies
 * while maintaining browser-level binding.
 *
 * @returns {string}
 *          Normalized IP prefix.
 */
export const getNormalizedIp = (req: Request): string => {
  let ip = req.ip || req.socket.remoteAddress;
  ip = ip?.split(',')[0]?.trim()
  if (!ip) return '0.0.0'
  if (ip.startsWith('::ffff:')) ip = ip.substring(7);

  if (ip.includes(':')) return ip.split(':').slice(0, 4).join(':') // /64
  return ip.split('.').slice(0, 3).join('.') // /24
}
