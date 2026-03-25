'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert')
const fs = require('node:fs')
const path = require('node:path')

const { ContextStore, build_context } = require('../lib/context')

const KEY = fs.readFileSync(path.join('test', 'config', 'tls_key.pem'))
const CERT = fs.readFileSync(path.join('test', 'config', 'tls_cert.pem'))

describe('tls/context', () => {
  describe('build_context()', () => {
    it('returns a SecureContext from valid key/cert', () => {
      const ctx = build_context({ key: KEY, cert: CERT })
      assert.ok(ctx)
    })

    it('throws on invalid material', () => {
      assert.throws(() => build_context({ key: 'garbage', cert: 'garbage' }))
    })
  })

  describe('ContextStore', () => {
    it('get() returns undefined when empty', () => {
      const store = new ContextStore()
      assert.equal(store.get('example.com'), undefined)
    })

    it('set() and get() round-trip', () => {
      const store = new ContextStore()
      const ctx = build_context({ key: KEY, cert: CERT })
      store.set('*', ctx)
      assert.equal(store.get('*'), ctx)
    })

    it('get() falls back to "*" for unknown hostname', () => {
      const store = new ContextStore()
      const ctx = build_context({ key: KEY, cert: CERT })
      store.set('*', ctx)
      assert.equal(store.get('unknown.example.com'), ctx)
    })

    it('get() prefers specific entry over "*"', () => {
      const store = new ContextStore()
      const default_ctx = build_context({ key: KEY, cert: CERT })
      const specific_ctx = build_context({ key: KEY, cert: CERT })
      store.set('*', default_ctx)
      store.set('mail.example.com', specific_ctx)
      assert.equal(store.get('mail.example.com'), specific_ctx)
      assert.equal(store.get('other.example.com'), default_ctx)
    })

    it('has() reports correctly', () => {
      const store = new ContextStore()
      assert.equal(store.has('foo'), false)
      store.set('foo', {})
      assert.equal(store.has('foo'), true)
    })

    it('size reflects the number of stored contexts', () => {
      const store = new ContextStore()
      assert.equal(store.size, 0)
      store.set('*', build_context({ key: KEY, cert: CERT }))
      assert.equal(store.size, 1)
    })

    it('build() creates the default "*" context', () => {
      const store = new ContextStore()
      store.build({ key: KEY, cert: CERT }, new Map())
      assert.ok(store.has('*'))
    })

    it('build() creates per-hostname contexts from cert map', () => {
      const certs = new Map([
        ['mail.example.com', { key: KEY, cert: CERT }],
        ['smtp.example.com', { key: KEY, cert: CERT }],
      ])
      const store = new ContextStore()
      store.build({ key: KEY, cert: CERT }, certs)
      assert.ok(store.has('*'))
      assert.ok(store.has('mail.example.com'))
      assert.ok(store.has('smtp.example.com'))
    })

    it('build() skips contexts that fail to construct', () => {
      const certs = new Map([['bad.example.com', { key: Buffer.from('bad'), cert: Buffer.from('bad') }]])
      const store = new ContextStore()
      store.build({ key: KEY, cert: CERT }, certs)
      assert.ok(store.has('*'))
      assert.ok(!store.has('bad.example.com'))
    })

    it('invalidate() clears all contexts', () => {
      const store = new ContextStore()
      store.set('*', build_context({ key: KEY, cert: CERT }))
      assert.equal(store.size, 1)
      store.invalidate()
      assert.equal(store.size, 0)
      assert.equal(store.get('*'), undefined)
    })

    describe('sni_callback()', () => {
      it('returns a function', () => {
        const store = new ContextStore()
        assert.equal(typeof store.sni_callback(), 'function')
      })

      it('resolves the correct context by hostname', (t, done) => {
        const store = new ContextStore()
        const ctx = build_context({ key: KEY, cert: CERT })
        store.set('mail.example.com', ctx)
        const sni = store.sni_callback()
        sni('mail.example.com', (err, returned) => {
          assert.equal(err, null)
          assert.equal(returned, ctx)
          done()
        })
      })

      it('falls back to default context for unknown hostname', (t, done) => {
        const store = new ContextStore()
        const ctx = build_context({ key: KEY, cert: CERT })
        store.set('*', ctx)
        const sni = store.sni_callback()
        sni('unknown.host', (err, returned) => {
          assert.equal(err, null)
          assert.equal(returned, ctx)
          done()
        })
      })

      it('returns null when no default exists', (t, done) => {
        const store = new ContextStore()
        const sni = store.sni_callback()
        sni('anything', (err, returned) => {
          assert.equal(err, null)
          assert.equal(returned, null)
          done()
        })
      })
    })
  })
})
