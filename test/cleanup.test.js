import test, {describe} from 'node:test'
import assert from 'node:assert/strict'
import {runInternalCleanup} from '../dist/cleanup/cleanup.js'
import {csrfMiddlewareDefaults} from '../dist/csrfMiddleware.js'

describe('runInternalCleanup()', () => {

  let fakeId = 0
  const makeContext = () => {
    const usedTokens = {}
    const localUsedStack = {}
    const ttl = 100 // kurze TTL für Tests

    const calculatePreviousExpireStackId = (t) =>
      (t - (t % ttl) + ttl).toString()

    const calculateExpireStackId =
      (t) => (t - (t % ttl) + 2 * ttl).toString()

    return {usedTokens, localUsedStack, calculatePreviousExpireStackId, ttl, calculateExpireStackId}
  }

  const makeOptions = (signal) => ({
    ...csrfMiddlewareDefaults,
    csrfToken: {...csrfMiddlewareDefaults.csrfToken, ttl: 100},
    internals: {...csrfMiddlewareDefaults.internals, signal}
  })

  test('removes expired tokens from localUsedStack', async () => {
    const ctx = makeContext()
    const stackId = ctx.calculateExpireStackId(Date.now())
    //await new Promise(resolve => setTimeout(resolve, 110))
    //console.log('stackId',ctx.calculatePreviousExpireStackId(Date.now()))
    ctx.usedTokens[stackId] = ['hash1', 'hash2']
    ctx.localUsedStack['hash1'] = true
    ctx.localUsedStack['hash2'] = true

    runInternalCleanup(ctx, makeOptions())

    await new Promise(resolve => setTimeout(resolve, 150))

    assert.equal(ctx.localUsedStack['hash1'], undefined)
    assert.equal(ctx.localUsedStack['hash2'], undefined)
    assert.equal(ctx.usedTokens[stackId], undefined)
  })

  test('does nothing if stack is empty', async () => {
    const ctx = makeContext()
    runInternalCleanup(ctx, makeOptions())

    await new Promise(resolve => setTimeout(resolve, 150))

    assert.deepEqual(ctx.usedTokens, {})
    assert.deepEqual(ctx.localUsedStack, {})
  })

  test('stops cleanup when signal is aborted', async () => {
    const ctx = makeContext()
    const controller = new AbortController()

    runInternalCleanup(ctx, makeOptions(controller.signal))
    controller.abort()

    const stackId = ctx.calculatePreviousExpireStackId(Date.now())
    ctx.usedTokens[stackId] = ['hash1']
    ctx.localUsedStack['hash1'] = true

    await new Promise(resolve => setTimeout(resolve, 150))

    // cleanup wurde gestoppt, tokens noch vorhanden
    assert.equal(ctx.localUsedStack['hash1'], true)
  })

  test('handles errors in cleanup gracefully', async () => {
    const ctx = makeContext()
    const errors = []

    const options = {
      ...makeOptions(),
      internals: {
        ...makeOptions().internals,
        debug: (_msg, e) => errors.push(e)
      }
    }

    // calculatePreviousExpireStackId wirft einen Fehler
    ctx.calculatePreviousExpireStackId = () => {
      throw new Error('test error')
    }

    runInternalCleanup(ctx, options)

    await new Promise(resolve => setTimeout(resolve, 150))

    assert.equal(errors.length, 1)
  })

})
