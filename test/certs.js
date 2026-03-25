'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert')
const fs = require('node:fs')
const path = require('node:path')

const config_module = require('haraka-config')
const { parse_pem, load_dir } = require('../lib/certs')

const EC_PEM = fs.readFileSync(path.join('test', 'config', 'tls', 'ec.pem'), 'utf8')
const HARAKA_LOCAL_PEM = fs.readFileSync(path.join('test', 'config', 'tls', 'haraka.local.pem'), 'utf8')

const test_cfg = config_module.module_config(path.resolve('test'))

describe('tls/certs', () => {
  describe('parse_pem()', () => {
    it('returns empty object for falsy input', () => {
      assert.deepEqual(parse_pem(''), {})
      assert.deepEqual(parse_pem(null), {})
      assert.deepEqual(parse_pem(undefined), {})
    })

    it('returns empty object for non-PEM text', () => {
      const result = parse_pem('hello world, no PEM here')
      assert.deepEqual(result, {})
    })

    it('extracts PKCS8 PRIVATE KEY from haraka.local.pem', () => {
      const result = parse_pem(HARAKA_LOCAL_PEM)
      assert.ok(result.keys?.length >= 1, 'should have a key')
      assert.ok(result.keys[0].includes('PRIVATE KEY'))
    })

    it('extracts EC PRIVATE KEY from ec.pem', () => {
      const result = parse_pem(EC_PEM)
      assert.ok(result.keys?.length >= 1, 'should have a key')
      assert.ok(result.keys[0].includes('EC PRIVATE KEY'))
    })

    it('extracts RSA PRIVATE KEY', () => {
      const rsa = '-----BEGIN RSA PRIVATE KEY-----\nhello\n-----END RSA PRIVATE KEY-----\n'
      const result = parse_pem(rsa)
      assert.ok(result.keys?.length >= 1)
      assert.ok(result.keys[0].includes('RSA PRIVATE KEY'))
    })

    it('extracts certificate chain from ec.pem', () => {
      const result = parse_pem(EC_PEM)
      assert.ok(result.chain?.length >= 1, 'should have cert chain')
      assert.ok(result.chain[0].includes('BEGIN CERTIFICATE'))
    })

    it('extracts CN from subject — ec.pem → mail.haraka.io', () => {
      const result = parse_pem(EC_PEM)
      assert.ok(result.names?.includes('mail.haraka.io'), `names=${result.names}`)
    })

    it('extracts CN from subject — haraka.local.pem → haraka.local', () => {
      const result = parse_pem(HARAKA_LOCAL_PEM)
      assert.ok(result.names?.includes('haraka.local'), `names=${result.names}`)
    })

    it('populates expire as a Date', () => {
      const result = parse_pem(EC_PEM)
      assert.ok(result.expire instanceof Date, 'expire should be a Date')
    })

    it('has no names when input contains only a key', () => {
      const key_only = '-----BEGIN PRIVATE KEY-----\nhello\n-----END PRIVATE KEY-----\n'
      const result = parse_pem(key_only)
      assert.ok(result.keys?.length >= 1)
      assert.equal(result.chain, undefined)
      assert.equal(result.names, undefined)
    })

    it('handles multiple certs in a chain', () => {
      const two_certs =
        '-----BEGIN CERTIFICATE-----\naaa\n-----END CERTIFICATE-----\n' +
        '-----BEGIN CERTIFICATE-----\nbbb\n-----END CERTIFICATE-----\n'
      // These are fake certs; parse_pem will fail X509Certificate parse but
      // should still populate res.chain without throwing
      const result = parse_pem(two_certs)
      assert.ok(result.chain?.length >= 1)
    })
  })

  describe('load_dir()', () => {
    it('returns empty Map when directory does not exist', async () => {
      const result = await load_dir(test_cfg, 'no-such-dir')
      assert.ok(result instanceof Map)
      assert.equal(result.size, 0)
    })

    it('loads certs from test/config/tls', async () => {
      const result = await load_dir(test_cfg, 'tls')
      assert.ok(result instanceof Map)
      assert.ok(result.size > 0, `expected certs, got ${result.size}`)
    })

    it('all entries have key and cert as Buffers', async () => {
      const result = await load_dir(test_cfg, 'tls')
      for (const [name, entry] of result) {
        assert.ok(Buffer.isBuffer(entry.key), `${name}: key should be Buffer`)
        assert.ok(Buffer.isBuffer(entry.cert), `${name}: cert should be Buffer`)
      }
    })

    it('loads EC cert as mail.haraka.io', async () => {
      const result = await load_dir(test_cfg, 'tls')
      assert.ok(result.has('mail.haraka.io'), `keys: ${[...result.keys()]}`)
    })

    it('loads haraka.local cert', async () => {
      const result = await load_dir(test_cfg, 'tls')
      assert.ok(result.has('haraka.local'), `keys: ${[...result.keys()]}`)
    })

    it('loads wildcard cert as *.example.com', async () => {
      const result = await load_dir(test_cfg, 'tls')
      assert.ok(result.has('*.example.com'), `keys: ${[...result.keys()]}`)
    })

    it('entries include the source file path', async () => {
      const result = await load_dir(test_cfg, 'tls')
      for (const [, entry] of result) {
        assert.ok(entry.file, 'entry should have a file path')
      }
    })
  })
})
