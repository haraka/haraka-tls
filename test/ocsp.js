'use strict'

const { describe, it, beforeEach } = require('node:test')
const assert = require('node:assert')
const { EventEmitter } = require('node:events')

// Reset module state between tests
function fresh_ocsp() {
  delete require.cache[require.resolve('../lib/ocsp')]
  return require('../lib/ocsp')
}

describe('tls/ocsp', () => {
  beforeEach(() => {
    // Each test starts with the module's lazy-load state reset
    fresh_ocsp()
  })

  describe('add_ocsp()', () => {
    it('does nothing when @haraka/ocsp is unavailable', () => {
      // Force the optional dep to "missing" by replacing it in require.cache
      // with a thrower.
      const ocsp_path = require.resolve('../lib/ocsp')
      delete require.cache[ocsp_path]
      const Module = require('node:module')
      const orig_load = Module._load
      Module._load = function (request, ...rest) {
        if (request === '@haraka/ocsp') {
          const e = new Error('Cannot find module')
          e.code = 'MODULE_NOT_FOUND'
          throw e
        }
        return orig_load.call(this, request, ...rest)
      }
      try {
        const { add_ocsp } = require('../lib/ocsp')
        const server = new EventEmitter()
        assert.doesNotThrow(() => add_ocsp(server))
        assert.equal(server.listenerCount('OCSPRequest'), 0, 'no listener attached')
      } finally {
        Module._load = orig_load
      }
    })

    it('attaches an OCSPRequest listener when @haraka/ocsp is installed', () => {
      // Inject a fake @haraka/ocsp into the require cache.
      const ocsp_pkg_path = require.resolve('../lib/ocsp')
      delete require.cache[ocsp_pkg_path]
      const Module = require('node:module')
      const orig_load = Module._load
      const fake = {
        Cache: function () {
          this.cache = {}
          this.probe = async () => null
          this.request = (id, opts, cb) => cb(null, Buffer.from('OCSP'))
        },
        getOCSPURI: (cert, cb) => cb(null, 'http://ocsp.example.com'),
        request: { generate: () => ({ id: 'reqid', data: Buffer.from('req') }) },
      }
      Module._load = function (request, ...rest) {
        if (request === '@haraka/ocsp') return fake
        return orig_load.call(this, request, ...rest)
      }
      try {
        const { add_ocsp } = require('../lib/ocsp')
        const server = new EventEmitter()
        add_ocsp(server)
        assert.equal(server.listenerCount('OCSPRequest'), 1)
      } finally {
        Module._load = orig_load
      }
    })

    it('does not attach a second listener if already attached', () => {
      const ocsp_pkg_path = require.resolve('../lib/ocsp')
      delete require.cache[ocsp_pkg_path]
      const Module = require('node:module')
      const orig_load = Module._load
      const fake = {
        Cache: function () {
          this.cache = {}
        },
        getOCSPURI: (_, cb) => cb(null, null),
        request: { generate: () => ({ id: 'x', data: Buffer.alloc(0) }) },
      }
      Module._load = function (request, ...rest) {
        if (request === '@haraka/ocsp') return fake
        return orig_load.call(this, request, ...rest)
      }
      try {
        const { add_ocsp } = require('../lib/ocsp')
        const server = new EventEmitter()
        add_ocsp(server)
        add_ocsp(server)
        assert.equal(server.listenerCount('OCSPRequest'), 1, 'still only one listener')
      } finally {
        Module._load = orig_load
      }
    })
  })

  describe('shutdown()', () => {
    it('is a no-op when OCSP was never loaded', () => {
      const { shutdown } = require('../lib/ocsp')
      assert.doesNotThrow(() => shutdown())
    })

    it('clears cache timers after add_ocsp loaded the module', () => {
      const ocsp_pkg_path = require.resolve('../lib/ocsp')
      delete require.cache[ocsp_pkg_path]
      const Module = require('node:module')
      const orig_load = Module._load
      const cleared = []
      const fake_timer = (id) => ({ id })
      const fake = {
        Cache: function () {
          this.cache = { a: { timer: fake_timer('a') }, b: { timer: fake_timer('b') } }
        },
        getOCSPURI: (_, cb) => cb(null, null),
        request: { generate: () => ({ id: 'x', data: Buffer.alloc(0) }) },
      }
      Module._load = function (request, ...rest) {
        if (request === '@haraka/ocsp') return fake
        return orig_load.call(this, request, ...rest)
      }
      const orig_clearTimeout = global.clearTimeout
      global.clearTimeout = (t) => cleared.push(t)
      try {
        const { add_ocsp, shutdown } = require('../lib/ocsp')
        add_ocsp(new EventEmitter()) // forces module load + cache construction
        shutdown()
        assert.equal(cleared.length, 2, 'both timers cleared')
      } finally {
        Module._load = orig_load
        global.clearTimeout = orig_clearTimeout
      }
    })
  })
})
