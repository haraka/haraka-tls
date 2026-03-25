'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert')
const path = require('node:path')

const config_module = require('haraka-config')
const { load } = require('../lib/config')

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
})
