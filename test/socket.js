'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert')
const net = require('node:net')
const { EventEmitter } = require('node:events')

const { PluggableStream, createServer, connect } = require('../lib/socket')

// Minimal mock socket — no real I/O
function makeSocket(props = {}) {
  const s = new EventEmitter()
  s.remotePort = props.remotePort ?? 12345
  s.remoteAddress = props.remoteAddress ?? '1.2.3.4'
  s.localPort = props.localPort ?? 25
  s.localAddress = props.localAddress ?? '0.0.0.0'
  s.writable = props.writable ?? true
  s.readable = props.readable ?? true
  s.encrypted = props.encrypted ?? false
  s.authorized = props.authorized ?? false
  s.write = (data, enc, cb) => {
    if (cb) cb()
    return true
  }
  s.end = () => {}
  s.destroy = () => {}
  s.destroySoon = () => {}
  s.pause = () => {}
  s.resume = () => {}
  s.setTimeout = () => {}
  s.setKeepAlive = () => {}
  s.setNoDelay = () => {}
  s.unref = () => {}
  s.removeAllListeners = EventEmitter.prototype.removeAllListeners.bind(s)
  return s
}

describe('tls/socket', () => {
  describe('PluggableStream', () => {
    it('can be constructed without a socket', () => {
      const ps = new PluggableStream()
      assert.ok(ps)
      assert.equal(ps.readable, true)
      assert.equal(ps.writable, true)
      assert.equal(ps._timeout, 0)
      assert.equal(ps._keepalive, false)
    })

    it('can be constructed with a socket', () => {
      const raw = makeSocket()
      const ps = new PluggableStream(raw)
      assert.equal(ps.targetsocket, raw)
    })

    it('mirrors address properties from the attached socket', () => {
      const raw = makeSocket({ remotePort: 1234, remoteAddress: '10.0.0.1', localPort: 25 })
      const ps = new PluggableStream(raw)
      assert.equal(ps.remotePort, 1234)
      assert.equal(ps.remoteAddress, '10.0.0.1')
      assert.equal(ps.localPort, 25)
    })

    it('forwards data events', () => {
      const raw = makeSocket()
      const ps = new PluggableStream(raw)
      let received = null
      ps.on('data', (d) => {
        received = d
      })
      raw.emit('data', Buffer.from('hello'))
      assert.deepEqual(received, Buffer.from('hello'))
    })

    it('forwards end event and updates writable', () => {
      const raw = makeSocket()
      const ps = new PluggableStream(raw)
      raw.writable = false
      let got_end = false
      ps.on('end', () => {
        got_end = true
      })
      raw.emit('end')
      assert.ok(got_end)
      assert.equal(ps.writable, false)
    })

    it('forwards close event', () => {
      const raw = makeSocket()
      const ps = new PluggableStream(raw)
      let had_error = null
      ps.on('close', (e) => {
        had_error = e
      })
      raw.emit('close', true)
      assert.equal(had_error, true)
    })

    it('annotates error events with source=tls', () => {
      const raw = makeSocket()
      const ps = new PluggableStream(raw)
      ps.on('error', () => {}) // prevent unhandled
      let caught = null
      ps.on('error', (e) => {
        caught = e
      })
      const err = new Error('boom')
      raw.emit('error', err)
      assert.equal(caught, err)
      assert.equal(caught.source, 'tls')
    })

    it('forwards secureConnect as both secureConnect and secure', () => {
      const raw = makeSocket()
      const ps = new PluggableStream(raw)
      let sc = 0
      let s = 0
      ps.on('secureConnect', () => sc++)
      ps.on('secure', () => s++)
      raw.emit('secureConnect')
      assert.equal(sc, 1)
      assert.equal(s, 1)
    })

    it('_detach() stops forwarding events', () => {
      const raw = makeSocket()
      const ps = new PluggableStream(raw)
      ps._detach()
      let received = false
      ps.on('data', () => {
        received = true
      })
      raw.emit('data', Buffer.from('ignored'))
      assert.equal(received, false)
    })

    it('write() delegates to underlying socket', () => {
      const raw = makeSocket()
      const ps = new PluggableStream(raw)
      let written = null
      raw.write = (d) => {
        written = d
        return true
      }
      ps.write(Buffer.from('test'))
      assert.deepEqual(written, Buffer.from('test'))
    })

    it('write() returns false when no socket is attached', () => {
      const ps = new PluggableStream()
      assert.equal(ps.write(Buffer.from('x')), false)
    })

    it('setTimeout() stores the value and delegates', () => {
      const raw = makeSocket()
      let set_to = null
      raw.setTimeout = (ms) => {
        set_to = ms
      }
      const ps = new PluggableStream(raw)
      ps.setTimeout(30000)
      assert.equal(ps._timeout, 30000)
      assert.equal(set_to, 30000)
    })

    it('setKeepAlive() stores the value', () => {
      const raw = makeSocket()
      raw.setKeepAlive = (b) => {}
      const ps = new PluggableStream(raw)
      ps.setKeepAlive(true)
      assert.equal(ps._keepalive, true)
    })

    it('isEncrypted() reflects socket.encrypted', () => {
      assert.equal(new PluggableStream(makeSocket({ encrypted: false })).isEncrypted(), false)
      assert.equal(new PluggableStream(makeSocket({ encrypted: true })).isEncrypted(), true)
    })

    it('isSecure() requires both encrypted and authorized', () => {
      assert.equal(new PluggableStream(makeSocket({ encrypted: true, authorized: false })).isSecure(), false)
      assert.equal(new PluggableStream(makeSocket({ encrypted: false, authorized: true })).isSecure(), false)
      assert.equal(new PluggableStream(makeSocket({ encrypted: true, authorized: true })).isSecure(), true)
    })

    it('pause() sets readable=false', () => {
      const raw = makeSocket()
      const ps = new PluggableStream(raw)
      ps.pause()
      assert.equal(ps.readable, false)
    })

    it('resume() sets readable=true', () => {
      const raw = makeSocket()
      const ps = new PluggableStream(raw)
      ps.pause()
      ps.resume()
      assert.equal(ps.readable, true)
    })
  })

  describe('createServer()', () => {
    it('returns a net.Server', () => {
      const tls_state = {
        contexts: { sni_callback: () => (_, cb) => cb(null, null) },
        cfg: {},
      }
      const server = createServer(tls_state, () => {})
      assert.ok(server instanceof net.Server)
      server.close()
    })
  })

  describe('connect()', () => {
    it('returns a PluggableStream', () => {
      const socket = connect({ host: '127.0.0.1', port: 1 })
      assert.ok(socket instanceof PluggableStream)
      socket.on('error', () => {}) // swallow connection refused
      socket.destroy()
    })

    it('returned socket has an upgrade() method', () => {
      const socket = connect({ host: '127.0.0.1', port: 1 })
      assert.equal(typeof socket.upgrade, 'function')
      socket.on('error', () => {})
      socket.destroy()
    })
  })
})
