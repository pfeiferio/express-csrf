import test, {describe} from 'node:test'
import assert from 'node:assert/strict'
import {validatedOptions} from '../dist/csrf-middleware/validatedOptions.js'
import {csrfMiddlewareDefaults} from '../dist/csrfMiddleware.js'
import {CsrfConfigError} from '../dist/CsrfConfigError.js'

describe('validatedOptions()', () => {

  describe('valid configuration', () => {

    test('returns resolved options with defaults', () => {
      const result = validatedOptions({
        csrfSecretCookie: {name: '__csrf'}
      }, csrfMiddlewareDefaults)

      assert.equal(result.csrfSecretCookie.name, '__csrf')
      assert.equal(result.csrfSecretCookie.secure, true)
      assert.equal(result.csrfSecretCookie.sameSite, 'strict')
      assert.equal(result.csrfToken.ttl, 60 * 5 * 1000)
      assert.equal(result.guard.jsonOnly, true)
      assert.equal(result.guard.origin, false)
      assert.equal(result.internals.cleanupProcess, undefined)
    })

    test('user options override defaults', () => {
      const result = validatedOptions({
        csrfSecretCookie: {name: '__csrf', secure: false, sameSite: 'lax'},
        csrfToken: {ttl: 60 * 1000},
        guard: {jsonOnly: false}
      }, csrfMiddlewareDefaults)

      assert.equal(result.csrfSecretCookie.secure, false)
      assert.equal(result.csrfSecretCookie.sameSite, 'lax')
      assert.equal(result.csrfToken.ttl, 60 * 1000)
      assert.equal(result.guard.jsonOnly, false)
    })

    test('accepts custom tokenLookup function', () => {
      const lookup = (req) => req.headers['x-custom-token']
      const result = validatedOptions({
        csrfToken: {lookup}
      }, csrfMiddlewareDefaults)
      assert.equal(result.csrfToken.lookup, lookup)
    })

    test('accepts custom scopeResolver function', () => {
      const scopeResolver = (req) => `${req.method}:custom`
      const result = validatedOptions({
        csrfToken: {scopeResolver}
      }, csrfMiddlewareDefaults)
      assert.equal(result.csrfToken.scopeResolver, scopeResolver)
    })

    test('accepts custom cleanupProcess function', () => {
      const cleanup = () => {
      }
      const result = validatedOptions({
        internals: {cleanupProcess: cleanup}
      }, csrfMiddlewareDefaults)
      assert.equal(result.internals.cleanupProcess, cleanup)
    })

    test('accepts valid store adapter', () => {
      const store = {
        has: async () => false,
        set: async () => {
        }
      }
      const result = validatedOptions({
        internals: {store}
      }, csrfMiddlewareDefaults)
      assert.equal(result.internals.store, store)
    })

    test('accepts sameSite none with secure true', () => {
      assert.doesNotThrow(() => validatedOptions({
        csrfSecretCookie: {sameSite: 'none', secure: true}
      }, csrfMiddlewareDefaults))
    })

    test('accepts origin as string', () => {
      const result = validatedOptions({
        guard: {origin: 'https://example.com'}
      }, csrfMiddlewareDefaults)
      assert.equal(result.guard.origin, 'https://example.com')
    })

    test('accepts all guard predicates', () => {
      const fn = () => false
      const result = validatedOptions({
        guard: {exclude: fn, skipTokenCreation: fn, skipValidation: fn}
      }, csrfMiddlewareDefaults)
      assert.equal(result.guard.exclude, fn)
      assert.equal(result.guard.skipTokenCreation, fn)
      assert.equal(result.guard.skipValidation, fn)
    })

  })

  describe('invalid configuration', () => {

    test('throws if csrfSecretCookie.name is empty string', () => {
      assert.throws(() => validatedOptions({
        csrfSecretCookie: {name: ''}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if csrfToken.ttl is zero', () => {
      assert.throws(() => validatedOptions({
        csrfToken: {ttl: 0}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if csrfToken.ttl is negative', () => {
      assert.throws(() => validatedOptions({
        csrfToken: {ttl: -1000}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if csrfSecretCookie.ttl is zero', () => {
      assert.throws(() => validatedOptions({
        csrfSecretCookie: {ttl: 0}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if csrfToken.lookup is not a function', () => {
      assert.throws(() => validatedOptions({
        csrfToken: {lookup: 'not-a-function'}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if csrfToken.scopeResolver is not a function', () => {
      assert.throws(() => validatedOptions({
        csrfToken: {scopeResolver: 'not-a-function'}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if cleanupProcess is not true or function', () => {
      assert.throws(() => validatedOptions({
        internals: {cleanupProcess: 'invalid'}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if sameSite is invalid string', () => {
      assert.throws(() => validatedOptions({
        csrfSecretCookie: {sameSite: 'invalid'}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if sameSite is none and secure is false', () => {
      assert.throws(() => validatedOptions({
        csrfSecretCookie: {sameSite: 'none', secure: false}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if origin is not string or false', () => {
      assert.throws(() => validatedOptions({
        guard: {origin: 123}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if jsonOnly is not boolean', () => {
      assert.throws(() => validatedOptions({
        guard: {jsonOnly: 'yes'}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if onTokenRejected is not a function', () => {
      assert.throws(() => validatedOptions({
        guard: {onTokenRejected: 'not-a-function'}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if exclude is not a function', () => {
      assert.throws(() => validatedOptions({
        guard: {exclude: 'not-a-function'}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if skipTokenCreation is not a function', () => {
      assert.throws(() => validatedOptions({
        guard: {skipTokenCreation: 'not-a-function'}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if skipValidation is not a function', () => {
      assert.throws(() => validatedOptions({
        guard: {skipValidation: 'not-a-function'}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if debug is not a function', () => {
      assert.throws(() => validatedOptions({
        internals: {debug: 'not-a-function'}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if store does not implement has', () => {
      assert.throws(() => validatedOptions({
        internals: {
          store: {
            set: async () => {
            }
          }
        }
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if store does not implement set', () => {
      assert.throws(() => validatedOptions({
        internals: {store: {has: async () => false}}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if signal is not an AbortSignal - string', () => {
      assert.throws(() => validatedOptions({
        internals: {signal: 'not-a-signal'}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if signal is missing aborted property', () => {
      assert.throws(() => validatedOptions({
        internals: {signal: {addEventListener: () => {}}}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('throws if signal is missing addEventListener', () => {
      assert.throws(() => validatedOptions({
        internals: {signal: {aborted: false}}
      }, csrfMiddlewareDefaults), CsrfConfigError)
    })

    test('accepts a valid AbortSignal', () => {
      const controller = new AbortController()
      assert.doesNotThrow(() => validatedOptions({
        internals: {signal: controller.signal}
      }, csrfMiddlewareDefaults))
    })
  })

})
