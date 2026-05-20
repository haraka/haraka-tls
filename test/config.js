'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert')
const path = require('node:path')

const config_module = require('haraka-config')
const { load, merge_plugin_tls } = require('../lib/config')

const test_cfg = config_module.module_config(path.resolve('test'))
const empty_cfg = config_module.module_config(path.resolve('test', 'non-exist'))

describe('tls/config', () => {
  describe('load() with no tls.ini', () => {
    it('returns default main section', () => {
      const result = load(empty_cfg)
      assert.deepEqual(result.main, {
        requestCert: true,
        rejectUnauthorized: false,
        honorCipherOrder: true,
        requestOCSP: false,
        mutual_tls: false,
        requireAuthorized: [],
        no_starttls_ports: [],
      })
    })

    it('returns default redis section', () => {
      const result = load(empty_cfg)
      assert.deepEqual(result.redis, { disable_for_failed_hosts: false })
    })

    it('returns empty host lists', () => {
      const result = load(empty_cfg)
      assert.deepEqual(result.no_tls_hosts, {})
      assert.deepEqual(result.mutual_auth_hosts, {})
      assert.deepEqual(result.mutual_auth_hosts_exclude, {})
    })

    it('outbound no_tls_hosts and force_tls_hosts are arrays', () => {
      const result = load(empty_cfg)
      assert.ok(Array.isArray(result.outbound.no_tls_hosts))
      assert.ok(Array.isArray(result.outbound.force_tls_hosts))
    })
  })

  describe('load() with test/config/tls.ini', () => {
    it('parses boolean options correctly', () => {
      const result = load(test_cfg)
      assert.equal(result.main.requestCert, true)
      assert.equal(result.main.rejectUnauthorized, false)
      assert.equal(result.main.honorCipherOrder, true)
    })

    it('parses cipher string', () => {
      const result = load(test_cfg)
      assert.ok(result.main.ciphers?.includes('ECDHE'), `ciphers: ${result.main.ciphers}`)
    })

    it('requireAuthorized is always an array', () => {
      const result = load(test_cfg)
      assert.ok(Array.isArray(result.main.requireAuthorized))
      assert.ok(result.main.requireAuthorized.includes(2465))
      assert.ok(result.main.requireAuthorized.includes(2587))
    })

    it('no_starttls_ports is always an array', () => {
      const result = load(test_cfg)
      assert.ok(Array.isArray(result.main.no_starttls_ports))
      assert.ok(result.main.no_starttls_ports.includes(2525))
    })

    it('no_tls_hosts is an object', () => {
      const result = load(test_cfg)
      assert.equal(typeof result.no_tls_hosts, 'object')
      assert.ok('192.168.1.1' in result.no_tls_hosts)
    })

    it('outbound section has key/cert/ciphers', () => {
      const result = load(test_cfg)
      assert.ok(result.outbound.key)
      assert.ok(result.outbound.cert)
      assert.ok(result.outbound.ciphers)
    })

    it('outbound force_tls_hosts is an array', () => {
      const result = load(test_cfg)
      assert.ok(Array.isArray(result.outbound.force_tls_hosts))
      assert.ok(result.outbound.force_tls_hosts.includes('first.example.com'))
    })

    it('outbound no_tls_hosts is an array', () => {
      const result = load(test_cfg)
      assert.ok(Array.isArray(result.outbound.no_tls_hosts))
      assert.ok(result.outbound.no_tls_hosts.includes('127.0.0.2'))
    })

    it('each call returns an independent object', () => {
      const r1 = load(test_cfg)
      const r2 = load(test_cfg)
      r1.main.ciphers = 'mutated'
      assert.notEqual(r2.main.ciphers, 'mutated')
    })
  })

  describe('merge_plugin_tls()', () => {
    it('inherits from main when plugin cfg is empty', () => {
      const main = load(test_cfg).main
      const merged = merge_plugin_tls(test_cfg, main, {})
      assert.equal(merged.rejectUnauthorized, false)
      assert.equal(merged.minVersion, 'TLSv1')
      assert.ok(merged.ciphers)
      assert.ok(Buffer.isBuffer(merged.key))
      assert.ok(Buffer.isBuffer(merged.cert))
    })

    it('plugin cfg overrides main', () => {
      const main = load(test_cfg).main
      const merged = merge_plugin_tls(test_cfg, main, {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.3',
      })
      assert.equal(merged.rejectUnauthorized, true)
      assert.equal(merged.minVersion, 'TLSv1.3')
    })

    it('resolves key/cert filenames to Buffers', () => {
      const merged = merge_plugin_tls(test_cfg, {}, { key: 'outbound_tls_key.pem', cert: 'outbound_tls_cert.pem' })
      assert.ok(Buffer.isBuffer(merged.key) && merged.key.length > 0)
      assert.ok(Buffer.isBuffer(merged.cert) && merged.cert.length > 0)
    })

    it('drops missing files rather than leaving null', () => {
      const merged = merge_plugin_tls(test_cfg, {}, { dhparam: 'does_not_exist.pem' })
      assert.equal(merged.dhparam, undefined)
    })

    it('normalises no_tls_hosts / force_tls_hosts to arrays', () => {
      const a = merge_plugin_tls(test_cfg, {}, { no_tls_hosts: '10.0.0.5' })
      assert.deepEqual(a.no_tls_hosts, ['10.0.0.5'])
      const b = merge_plugin_tls(test_cfg, {}, {})
      assert.deepEqual(b.no_tls_hosts, [])
      assert.deepEqual(b.force_tls_hosts, [])
    })

    it('does not omit no_tls_hosts from inheritance ([main] is inbound-only)', () => {
      // Even when [main] sets no_tls_hosts, merge_plugin_tls does NOT inherit it.
      const main = { no_tls_hosts: ['1.2.3.4'] }
      const merged = merge_plugin_tls(test_cfg, main, {})
      assert.deepEqual(merged.no_tls_hosts, [])
    })

    it('does not mutate the input plugin cfg', () => {
      const input = { rejectUnauthorized: true, no_tls_hosts: '10.0.0.5' }
      const before = JSON.stringify(input)
      merge_plugin_tls(test_cfg, {}, input)
      assert.equal(JSON.stringify(input), before)
    })
  })
})
