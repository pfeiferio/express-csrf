import test from 'node:test'
import assert from 'node:assert/strict'
import {csrfMiddleware} from "../dist/csrfMiddleware.js";

test('generateToken returns false when token creation is skipped', async () => {
  const req = {
    method: 'GET',
    headers: {},
    cookies: {}, // ← KEIN secret cookie
    socket: {
      remoteAddress: '1.2.3.4'
    },
    get(v) {
      return {
        origin: 'foo',
        'user-agent': 'foo---bar'
      }[v]
    }
  }

  const res = {
    locals: {},
    cookie: () => {
    }
  }


  const next = () => {
  }

  const middleware = csrfMiddleware({
    csrfSecretCookie: {
      name: 'csrf-secret',
      path: '/',
      ttl: 1000,
      domain: undefined,
      secure: false,
      sameSite: 'strict'
    },
    guard: {
      jsonOnly: false,
      origin: false,
      onTokenRejected: () => {
      },
      exclude: undefined,
      skipValidation: undefined,
      skipTokenCreation: () => true // ← DAS IST DER KEY
    },
    internals: {
      store: undefined,
      cleanupProcess: undefined,
      debug: undefined
    },
    csrfToken: {
      ttl: 1000,
      lookup: () => undefined,
      scopeResolver: () => 'scope'
    }
  })

  await middleware(req, res, next)

  assert.equal(req.csrf.generateToken(), false)
})
