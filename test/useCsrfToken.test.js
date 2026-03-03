import test, {describe} from 'node:test'
import assert from 'node:assert/strict'
import {createUseCsrfToken} from '../dist/token/useCsrfToken.js'
import {csrfMiddlewareDefaults} from '../dist/csrfMiddleware.js'

describe('createUseCsrfToken()', () => {

  const makeOptions = (overrides = {}) => ({
    ...csrfMiddlewareDefaults,
    ...overrides
  })

  describe('in-memory (no store)', () => {

    test('returns true for a new token', async () => {
      const use = createUseCsrfToken(makeOptions())
      assert.equal(await use('token-a'), true)
    })

    test('returns false for an already used token', async () => {
      const use = createUseCsrfToken(makeOptions())
      await use('token-a')
      assert.equal(await use('token-a'), false)
    })

    test('different tokens are independent', async () => {
      const use = createUseCsrfToken(makeOptions())
      assert.equal(await use('token-a'), true)
      assert.equal(await use('token-b'), true)
    })

    test('same token cannot be used twice across calls', async () => {
      const use = createUseCsrfToken(makeOptions())
      const first = await use('token-replay')
      const second = await use('token-replay')
      assert.equal(first, true)
      assert.equal(second, false)
    })

  })

  describe('with external store', () => {

    const makeStore = () => {
      const store = new Map
      return {
        has: async (key) => store.has(key),
        set: async (key) => {
          store.set(key, true)
        },
        _store: store
      }
    }

    test('returns true for a new token', async () => {
      const store = makeStore()
      const use = createUseCsrfToken(makeOptions({internals: {...csrfMiddlewareDefaults.internals, store}}))
      assert.equal(await use('token-a'), true)
    })

    test('returns false if token is in store', async () => {
      const store = makeStore()
      const use = createUseCsrfToken(makeOptions({internals: {...csrfMiddlewareDefaults.internals, store}}))
      await use('token-a')
      // new instance — local cache is empty, but store has the token
      const use2 = createUseCsrfToken(makeOptions({internals: {...csrfMiddlewareDefaults.internals, store}}))
      assert.equal(await use2('token-a'), false)
    })

    test('local cache prevents store lookup for already used tokens', async () => {
      let storeCalls = 0
      const store = {
        has: async (key) => {
          storeCalls++;
          return false
        },
        set: async () => {
        }
      }
      const use = createUseCsrfToken(makeOptions({internals: {...csrfMiddlewareDefaults.internals, store}}))
      await use('token-a')
      const callsAfterFirst = storeCalls
      await use('token-a') // should be caught by local cache, no store call
      assert.equal(storeCalls, callsAfterFirst) // no additional store calls
    })

    test('token is written to store on first use', async () => {
      const store = makeStore()
      const use = createUseCsrfToken(makeOptions({internals: {...csrfMiddlewareDefaults.internals, store}}))
      await use('token-a')
      // sha256 of 'token-a' should be in store
      assert.equal(store._store.size, 1)
    })

  })

  describe('custom cleanupProcess', () => {

    test('calls cleanup handler with correct context', () => {
      let receivedContext = null
      const cleanup = (ctx) => {
        receivedContext = ctx
      }

      createUseCsrfToken(makeOptions({
        internals: {...csrfMiddlewareDefaults.internals, cleanupProcess: cleanup}
      }))

      assert.ok(receivedContext !== null)
      assert.ok(typeof receivedContext.calculatePreviousExpireStackId === 'function')
      assert.ok(typeof receivedContext.usedTokens === 'object')
      assert.ok(typeof receivedContext.localUsedStack === 'object')
    })

    test('exposes calculatePreviousExpireStackId via cleanupProcess context', () => {
      let receivedCtx = null
      createUseCsrfToken({
        ...csrfMiddlewareDefaults,
        internals: {
          ...csrfMiddlewareDefaults.internals,
          cleanupProcess: (ctx) => { receivedCtx = ctx }
        }
      })

      const t = Date.now()
      const result = receivedCtx.calculatePreviousExpireStackId(t)
      assert.equal(typeof result, 'string')
    })
  })
})
