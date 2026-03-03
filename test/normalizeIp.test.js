import test, {describe} from 'node:test'
import assert from 'node:assert/strict'
import {getNormalizedIp} from '../dist/utils/ip.js'

describe('getNormalizedIp()', () => {

  const mockReq = (ip, remoteAddress) => ({
    ip,
    socket: {remoteAddress},
    headers: {}
  })

  test('standard IPv4 returns /24 prefix', () => {
    assert.equal(getNormalizedIp(mockReq('192.168.1.15')), '192.168.1')
  })

  test('IPv4-mapped IPv6 is unwrapped and returns /24 prefix', () => {
    assert.equal(getNormalizedIp(mockReq('::ffff:192.168.1.15')), '192.168.1')
  })

  test('falls back to socket.remoteAddress if req.ip is undefined', () => {
    assert.equal(getNormalizedIp(mockReq(undefined, '10.0.0.5')), '10.0.0')
  })

  test('returns 0.0.0 if no IP is available', () => {
    assert.equal(getNormalizedIp(mockReq()), '0.0.0')
  })

  test('real IPv6 returns /64 prefix', () => {
    assert.equal(getNormalizedIp(mockReq('2001:0db8:85a3:0000:0000:8a2e:0370:7334')), '2001:0db8:85a3:0000')
  })
})
