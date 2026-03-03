import test, {describe} from 'node:test'
import assert from 'node:assert/strict'
import {compareSignatures} from "../dist/utils/compareSignatures.js";

describe('validatedOptions()', () => {

  test('tbd', () => {
    assert.equal(compareSignatures('foo', 'foo2'), false)
  })
})
