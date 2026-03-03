import test from 'node:test'
import assert from 'node:assert/strict'
import {validateCsrfToken} from "../dist/token/validateCsrfToken.js";
import {sha256Hmac} from "../dist/utils/crypto.js";
import {createBrowserSignature} from "../dist/token/createBrowserSignature.js";


const LENGTH_SHA256 = 64
const SECRET = 'super-secret'
const TTL = 10_000
const FIXED_NOW = 1_700_000_000_000

/* ------------------------------------------------------------------ */
/* Helpers */
/* ------------------------------------------------------------------ */

const withFixedTime = (fn) => {
  const original = Date.now
  Date.now = () => FIXED_NOW
  return Promise.resolve(fn()).finally(() => {
    Date.now = original
  })
}

const createReq = ({
                     origin = 'http://localhost',
                     contentType = 'application/json',
                     userAgent = 'agent',
                     ip = '127.0.0.1'
                   } = {}) => ({
  headers: {
    origin,
    'user-agent': userAgent
  },
  get: (h) => ({
    origin,
    'user-agent': userAgent
  }[h.toLowerCase()]),
  is: (type) => type === contentType,
  ip,
  socket: {remoteAddress: ip}
})

const createOptions = ({
                         debug = false,
                         lookup,
                         scope = 'scope',
                         jsonOnly = false,
                         origin = false
                       } = {}) => ({
  csrfToken: {
    ttl: TTL,
    lookup: lookup ?? (() => undefined),
    scopeResolver: () => scope
  },
  csrfSecretCookie: {
    name: '',
    path: '',
    ttl: 0,
    domain: undefined,
    secure: false,
    sameSite: 'strict'
  },
  guard: {
    jsonOnly,
    origin,
    onTokenRejected: () => {
    },
    exclude: undefined,
    skipTokenCreation: undefined,
    skipValidation: undefined
  },
  internals: {
    store: undefined,
    cleanupProcess: true,
    debug: debug ? console.log : undefined
  }
})

const buildToken = (req, expires) => {
  const random = 'abc123'
  const browserSig = createBrowserSignature(req, SECRET)
  const signature = sha256Hmac(
    [random, expires, browserSig].join('|'),
    SECRET
  )

  return Buffer
    .from([random, expires, browserSig, signature].join('|'))
    .toString('base64')
}

/* ------------------------------------------------------------------ */
/* Tests */
/* ------------------------------------------------------------------ */

test('missing secret', async () => {
  const result = await validateCsrfToken(
    createOptions(),
    createReq(),
    undefined,
    async () => true
  )

  assert.equal(result.reason, 'missing_secret')
})

test('origin mismatch', async () => {
  const result = await validateCsrfToken(
    createOptions({origin: 'http://expected'}),
    createReq({origin: 'http://wrong'}),
    SECRET,
    async () => true
  )

  assert.equal(result.reason, 'origin_mismatch')
})

test('invalid content type', async () => {
  const result = await validateCsrfToken(
    createOptions({jsonOnly: true}),
    createReq({contentType: 'text/plain'}),
    SECRET,
    async () => true
  )

  assert.equal(result.reason, 'invalid_content_type')
})

test('missing token', async () => {
  const result = await validateCsrfToken(
    createOptions(),
    createReq(),
    SECRET,
    async () => true
  )

  assert.equal(result.reason, 'missing_token')
})

test('invalid structure', async () => {
  const options = createOptions({
    lookup: () => Buffer.from('broken').toString('base64')
  })

  const result = await validateCsrfToken(
    options,
    createReq(),
    SECRET,
    async () => true
  )

  assert.equal(result.reason, 'invalid_structure')
})

test('expired token', async () => {
  await withFixedTime(async () => {
    const req = createReq()
    const token = buildToken(req, FIXED_NOW - 1)

    const result = await validateCsrfToken(
      createOptions({lookup: () => token}),
      req,
      SECRET,
      async () => true
    )

    assert.equal(result.reason, 'expired')
  })
})

test('browser signature mismatch', async () => {
  await withFixedTime(async () => {
    const req = createReq()

    const random = 'abc'
    const expires = FIXED_NOW + 1000
    const fakeSig = '0'.repeat(LENGTH_SHA256)

    const signature = sha256Hmac(
      [random, expires, fakeSig].join('|'),
      SECRET
    )

    const token = Buffer
      .from([random, expires, fakeSig, signature].join('|'))
      .toString('base64')

    const result = await validateCsrfToken(
      createOptions({lookup: () => token}),
      req,
      SECRET,
      async () => true
    )

    assert.equal(result.reason, 'browser_signature_mismatch')
  })
})

test('invalid signature', async () => {
  await withFixedTime(async () => {
    const req = createReq()
    const token = buildToken(req, FIXED_NOW + 1000)

    const parts = Buffer.from(token, 'base64')
      .toString('utf8')
      .split('|')

    parts[3] = '0'.repeat(LENGTH_SHA256)

    const broken = Buffer
      .from(parts.join('|'))
      .toString('base64')

    const result = await validateCsrfToken(
      createOptions({lookup: () => broken}),
      req,
      SECRET,
      async () => true
    )

    assert.equal(result.reason, 'invalid_signature')
  })
})

test('token already used', async () => {
  await withFixedTime(async () => {
    const req = createReq()
    const token = buildToken(req, FIXED_NOW + 1000)

    const result = await validateCsrfToken(
      createOptions({lookup: () => token}),
      req,
      SECRET,
      async () => false
    )

    assert.equal(result.reason, 'token_already_used')
  })
})

test('valid token', async () => {
  await withFixedTime(async () => {
    const req = createReq()
    const token = buildToken(req, FIXED_NOW + 1000)

    const result = await validateCsrfToken(
      createOptions({lookup: () => token}),
      req,
      SECRET,
      async () => true
    )

    assert.equal(result.valid, true)
  })
})

test('returns unknown when internal error occurs', async () => {
  let debugCalled = false
  let debugMsg

  const options = createOptions({
    lookup: () => {
      throw new Error('forced error')
    },
    debug: true
  })

  options.internals.debug = (msg) => {
    debugCalled = true
    debugMsg = msg
  }

  const result = await validateCsrfToken(
    options,
    createReq(),
    SECRET,
    async () => true
  )

  assert.equal(result.valid, false)
  assert.equal(result.reason, 'unknown')

  assert.equal(debugCalled, true)
  assert.equal(debugMsg, 'csrf validation failed: unknown')
})

test('invalid structure when expires is not a number', async () => {
  const req = createReq()

  const random = 'abc'
  const expires = 'not-a-number'
  const browserSig = createBrowserSignature(req, SECRET)

  const signature = sha256Hmac(
    [random, expires, browserSig].join('|'),
    SECRET
  )

  const token = Buffer
    .from([random, expires, browserSig, signature].join('|'))
    .toString('base64')

  const result = await validateCsrfToken(
    createOptions({lookup: () => token}),
    req,
    SECRET,
    async () => true
  )

  assert.equal(result.reason, 'invalid_structure')
})
