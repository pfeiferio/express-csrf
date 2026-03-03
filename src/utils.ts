import type {Request, RequestHandler, Response} from 'express'

/**
 * @param {import('express').Request} req
 * @return {string}
 */
export const defaultTokenLookup = (req: Request): string | undefined => {
  let header = req.headers['x-csrf-token'] ?? req.headers['x-xsrf-token']
  if (Array.isArray(header)) header = header[0]
  return header || req.body?._csrf
}

/**
 * Resolves the default CSRF token scope for a request.
 *
 * The scope is derived from the HTTP method and the matched route path.
 * Route parameters (e.g. ":id") are preserved to keep the scope stable
 * across retries and different resource instances.
 *
 * Example scopes:
 * - "POST:/api/user/update"
 * - "DELETE:/api/file/:id"
 *
 * @param {import('express').Request} req
 *        Express request object.
 *
 * @returns {string}
 *          Deterministic scope string used to bind a CSRF token
 *          to a specific class of requests.
 */
export const defaultScopeResolver = (req: Request): string =>
  `${req.method}:${req.route?.path ?? req.path}`


export const defaultOnTokenRejected: RequestHandler = (_req: Request, res: Response) =>
  res.status(403).json({error: 'Invalid CSRF token', error_details: 'invalid_csrf_token'})
