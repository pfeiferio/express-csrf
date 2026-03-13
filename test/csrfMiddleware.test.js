import test, {describe} from 'node:test'
import assert from 'node:assert/strict'
import {csrfMiddleware} from '../dist/csrfMiddleware.js'

// ─── Helpers ────────────────────────────────────────────────────────────────

const mockReq = (overrides = {}) => {
  const req = {
    method: 'GET',
    path: '/test',
    cookies: {},
    headers: {},
    body: {},
    ip: '192.168.1.1',
    socket: {remoteAddress: '192.168.1.1'},
    get: (key) => req.headers[key.toLowerCase()],
    is: (_type) => false,
    route: undefined,
    csrf: undefined,
    ...overrides
  }
  return req
}

const mockRes = () => {
  const res = {
    locals: {},
    cookies: {},
    statusCode: 200,
    body: undefined,
    cookie: (name, value, _options) => {
      res.cookies[name] = value
    },
    status: (code) => {
      res.statusCode = code
      return res
    },
    json: (body) => {
      res.body = body
      return res
    }
  }
  return res
}

const mockNext = () => {
  let called = false
  const fn = () => {
    called = true
  }
  fn.called = () => called
  return fn
}

const defaultOptions = {
  csrfSecretCookie: {name: '__csrf'}
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('csrfMiddleware', () => {

  describe('GET request', () => {

    test('sets a csrf secret cookie if none exists', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq()
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.ok(res.cookies['__csrf'])
      assert.ok(next.called())
    })

    test('does not overwrite existing csrf secret cookie', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const existingSecret = 'existingsecret'
      const req = mockReq({cookies: {'__csrf': existingSecret}})
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(res.cookies['__csrf'], undefined) // no new cookie set
      assert.ok(next.called())
    })

    test('sets res.locals.csrfToken on GET', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq()
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.ok(res.locals.csrfToken)
      assert.equal(typeof res.locals.csrfToken, 'string')
    })

    test('req.csrf.hasSecret() returns true after secret is set', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq()
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(req.csrf.hasSecret(), true)
    })

    test('req.csrf.generateToken() returns a string', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq()
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(typeof req.csrf.generateToken(), 'string')
    })

    test('req.csrf.isExcluded() returns false for normal request', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq()
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(req.csrf.isExcluded(), false)
    })

  })

  describe('POST request', () => {

    test('rejects POST without csrf token', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq({
        method: 'POST',
        cookies: {'__csrf': 'somesecret'},
        is: (type) => type === 'application/json'
      })
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(res.statusCode, 403)
      assert.equal(next.called(), false)
    })

    test('rejects POST without secret cookie', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq({
        method: 'POST',
        headers: {'x-csrf-token': 'sometoken'},
        is: (type) => type === 'application/json'
      })
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(res.statusCode, 403)
      assert.equal(next.called(), false)
    })

    test('rejects POST with invalid content type when jsonOnly is true', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq({
        method: 'POST',
        cookies: {'__csrf': 'somesecret'},
        headers: {'x-csrf-token': 'sometoken'},
        is: (_type) => false
      })
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(res.statusCode, 403)
    })

    test('accepts valid csrf token', async () => {
      const middleware = csrfMiddleware(defaultOptions)

      // First GET to obtain secret and token
      const getReq = mockReq()
      const getRes = mockRes()
      await middleware(getReq, getRes, mockNext())

      const secret = getRes.cookies['__csrf']
      const token = getRes.locals.csrfToken

      // Then POST with the token
      const postReq = mockReq({
        method: 'POST',
        cookies: {'__csrf': secret},
        headers: {'x-csrf-token': token},
        is: (type) => type === 'application/json'
      })
      const postRes = mockRes()
      const next = mockNext()

      await middleware(postReq, postRes, next)

      assert.equal(next.called(), true)
      assert.equal(postRes.statusCode, 200)
    })

    test('rejects replay of already used token', async () => {
      const middleware = csrfMiddleware(defaultOptions)

      const getReq = mockReq()
      const getRes = mockRes()
      await middleware(getReq, getRes, mockNext())

      const secret = getRes.cookies['__csrf']
      const token = getRes.locals.csrfToken

      const postReq = () => mockReq({
        method: 'POST',
        cookies: {'__csrf': secret},
        headers: {'x-csrf-token': token},
        is: (type) => type === 'application/json'
      })

      // First use
      const res1 = mockRes()
      const next1 = mockNext()
      await middleware(postReq(), res1, next1)
      assert.equal(next1.called(), true)

      // Replay
      const res2 = mockRes()
      const next2 = mockNext()
      await middleware(postReq(), res2, next2)
      assert.equal(next2.called(), false)
      assert.equal(res2.statusCode, 403)
    })

  })

  describe('guard options', () => {

    test('exclude skips middleware entirely', async () => {
      const middleware = csrfMiddleware({
        ...defaultOptions,
        guard: {
          exclude: (req) => req.path.includes('.')
        }
      })

      const req = mockReq({path: '/assets/style.css', method: 'POST'})
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(next.called(), true)
      assert.equal(req.csrf.isExcluded(), true)
    })

    test('skipValidation skips token validation', async () => {
      const middleware = csrfMiddleware({
        ...defaultOptions,
        guard: {
          skipValidation: (req) => req.path.startsWith('/webhook')
        }
      })

      const req = mockReq({
        method: 'POST',
        path: '/webhook/stripe',
        cookies: {'__csrf': 'somesecret'},
        is: (_type) => false
      })
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(next.called(), true)
      assert.equal(req.csrf.isValidationSkipped(), true)
    })

    test('skipTokenCreation skips token generation on GET', async () => {
      const middleware = csrfMiddleware({
        ...defaultOptions,
        guard: {
          skipTokenCreation: (req) => req.path.startsWith('/api/public')
        }
      })

      const req = mockReq({path: '/api/public/status'})
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(res.locals.csrfToken, undefined)
      assert.equal(req.csrf.isTokenCreationSkipped(), true)
    })

    test('origin mismatch rejects request', async () => {
      const middleware = csrfMiddleware({
        ...defaultOptions,
        guard: {
          origin: 'https://example.com'
        }
      })

      const req = mockReq({
        method: 'POST',
        cookies: {'__csrf': 'somesecret'},
        headers: {
          'x-csrf-token': 'sometoken',
          'origin': 'https://evil.com'
        },
        is: (type) => type === 'application/json'
      })
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(res.statusCode, 403)
      assert.equal(next.called(), false)
    })

    test('custom onTokenRejected is called with result', async () => {
      let capturedResult = null

      const middleware = csrfMiddleware({
        ...defaultOptions,
        guard: {
          onTokenRejected: (_req, res, _next, result) => {
            capturedResult = result
            res.status(403).json({reason: result.reason})
          }
        }
      })

      const req = mockReq({
        method: 'POST',
        cookies: {'__csrf': 'somesecret'},
        is: (type) => type === 'application/json'
      })
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.ok(capturedResult)
      assert.equal(capturedResult.valid, false)
      assert.ok(capturedResult.reason)
    })

  })

  describe('HEAD and OPTIONS', () => {

    test('HEAD request passes through without validation', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq({method: 'HEAD'})
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(next.called(), true)
    })

    test('OPTIONS request passes through without validation', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq({method: 'OPTIONS'})
      const res = mockRes()
      const next = mockNext()

      await middleware(req, res, next)

      assert.equal(next.called(), true)
    })

  })

  describe('CsrfConfigError', () => {

    test('throws on invalid cookieNameCsrfSecret', () => {
      assert.throws(
        () => csrfMiddleware({csrfSecretCookie: {name: ''}}),
        {name: 'CsrfConfigError'}
      )
    })

    test('throws on invalid sameSite', () => {
      assert.throws(
        () => csrfMiddleware({
          csrfSecretCookie: {name: '__csrf', sameSite: 'invalid'}
        }),
        {name: 'CsrfConfigError'}
      )
    })

    test('throws when sameSite is none and secure is false', () => {
      assert.throws(
        () => csrfMiddleware({
          csrfSecretCookie: {name: '__csrf', sameSite: 'none', secure: false}
        }),
        {name: 'CsrfConfigError'}
      )
    })

    test('throws on invalid cleanupProcess', () => {
      assert.throws(
        () => csrfMiddleware({
          csrfSecretCookie: {name: '__csrf'},
          internals: {cleanupProcess: 'invalid'}
        }),
        {name: 'CsrfConfigError'}
      )
    })
  })
  test('uses custom cookieReader to read cookies', async () => {
    const customCookies = {'__csrf': 'my-secret'}
    const cookieReader = () => customCookies

    const middleware = csrfMiddleware({
      csrfSecretCookie: {
        name: '__csrf',
        cookieReader
      }
    })

    const req = mockReq({method: 'GET'})
    const res = mockRes()
    const next = mockNext()

    await middleware(req, res, next)

    assert.equal(next.called(), true)
    assert.equal(req.csrf.hasSecret(), true)
    assert.ok(req.csrf.generateToken())
  })
  test('uses custom cookieReader to read secret cookie', async () => {
    const customCookies = {'__csrf': 'my-secret'}
    const cookieReader = () => customCookies

    const middleware = csrfMiddleware({
      csrfSecretCookie: {
        name: '__csrf',
        cookieReader
      }
    })

    const req = mockReq({method: 'GET'})
    const res = mockRes()
    const next = mockNext()

    await middleware(req, res, next)

    assert.equal(next.called(), true)
    assert.equal(req.csrf.hasSecret(), true)
    assert.ok(req.csrf.generateToken())
  })
  test('falls back to req.cookies ?? {} when no cookieReader provided and req.cookies is null', async () => {
    const middleware = csrfMiddleware({
      csrfSecretCookie: {
        name: '__csrf',
      }
    })

    const req = mockReq({method: 'GET', cookies: null})
    const res = mockRes()
    const next = mockNext()

    await middleware(req, res, next)

    assert.equal(req.cookies, null)
    assert.equal(next.called(), true)
    assert.equal(req.csrf.hasSecret(), true)
    assert.ok(req.csrf.generateToken())
  })

  describe('req.csrf.isValidToken(token)', () => {

    test('returns true for a valid token when validation is skipped', async () => {
      // isValidToken(token) is designed for use with skipValidation — the
      // middleware skips automatic validation so the caller can check manually.
      const middleware = csrfMiddleware({
        ...defaultOptions,
        guard: {skipValidation: () => true}
      })

      const getReq = mockReq()
      const getRes = mockRes()
      await middleware(getReq, getRes, mockNext())

      const secret = getRes.cookies['__csrf']
      const token = getRes.locals.csrfToken

      const postReq = mockReq({
        method: 'POST',
        cookies: {'__csrf': secret},
        is: (type) => type === 'application/json'
      })
      await middleware(postReq, mockRes(), mockNext())

      assert.equal(await postReq.csrf.isValidToken(token), true)
    })

    test('returns false when no secret exists', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq({
        method: 'POST',
        is: (type) => type === 'application/json'
      })
      await middleware(req, mockRes(), mockNext())

      assert.equal(await req.csrf.isValidToken('sometoken'), false)
    })

    test('returns false for an invalid token string', async () => {
      const middleware = csrfMiddleware(defaultOptions)
      const req = mockReq({
        method: 'POST',
        cookies: {'__csrf': 'somesecret'},
        is: (type) => type === 'application/json'
      })
      await middleware(req, mockRes(), mockNext())

      assert.equal(await req.csrf.isValidToken('invalid-token'), false)
    })

    test('returns false for an already used token (replay)', async () => {
      const middleware = csrfMiddleware({
        ...defaultOptions,
        guard: {skipValidation: () => true}
      })

      const getReq = mockReq()
      const getRes = mockRes()
      await middleware(getReq, getRes, mockNext())

      const secret = getRes.cookies['__csrf']
      const token = getRes.locals.csrfToken

      const makePostReq = () => mockReq({
        method: 'POST',
        cookies: {'__csrf': secret},
        is: (type) => type === 'application/json'
      })

      // First call — consumes the token
      const firstReq = makePostReq()
      await middleware(firstReq, mockRes(), mockNext())
      assert.equal(await firstReq.csrf.isValidToken(token), true)

      // Replay attempt — token already used
      const replayReq = makePostReq()
      await middleware(replayReq, mockRes(), mockNext())
      assert.equal(await replayReq.csrf.isValidToken(token), false)
    })

  })
})
