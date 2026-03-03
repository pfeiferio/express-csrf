import test from 'node:test'
import assert from 'node:assert/strict'
import {defaultScopeResolver} from "../dist/utils.js";

test('uses route.path when available', () => {
  const req = {
    method: 'POST',
    route: { path: '/users/:id' },
    path: '/users/123'
  }

  const result = defaultScopeResolver(req)

  assert.equal(result, 'POST:/users/:id')
})

test('falls back to req.path when route.path is undefined', () => {
  const req = {
    method: 'POST',
    route: undefined,
    path: '/users/123'
  }

  const result = defaultScopeResolver(req)

  assert.equal(result, 'POST:/users/123')
})
