import test from 'node:test'
import assert from 'node:assert/strict'
import {defaultTokenLookup} from "../dist/utils.js";

test('defaultTokenLookup uses first header element when header is array', () => {
  const req = {
    headers: {
      'x-csrf-token': ['token1', 'token2']
    },
    body: {}
  }

  const result = defaultTokenLookup(req)
  assert.equal(result, 'token1')
})

test('defaultTokenLookup falls back to body when no header', () => {
  const req = {
    headers: {},
    body: {_csrf: 'body-token'}
  }

  const result = defaultTokenLookup(req)
  assert.equal(result, 'body-token')
})

test('defaultTokenLookup prefers x-xsrf-token if x-csrf-token missing', () => {
  const req = {
    headers: {'x-xsrf-token': 'xsrf-token'},
    body: {}
  }

  const result = defaultTokenLookup(req)
  assert.equal(result, 'xsrf-token')
})
