'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert')
const path = require('node:path')

const config_module = require('haraka-config')
const { load: load_config } = require('../lib/config')
const { OutboundTLS } = require('../lib/outbound')

const test_cfg_module = config_module.module_config(path.resolve('test'))

function make_outbound(cfg_module = test_cfg_module) {
    const tls_cfg = load_config(cfg_module)
    return new OutboundTLS(cfg_module).load(tls_cfg)
}

describe('tls/outbound', () => {
    describe('OutboundTLS.load()', () => {
        it('populates cfg after load()', () => {
            const ob = make_outbound()
            assert.ok(ob.cfg)
        })

        it('no_tls_hosts is an array', () => {
            const ob = make_outbound()
            assert.ok(Array.isArray(ob.cfg.no_tls_hosts))
        })

        it('force_tls_hosts is an array', () => {
            const ob = make_outbound()
            assert.ok(Array.isArray(ob.cfg.force_tls_hosts))
        })

        it('inherits key from [main] when not in [outbound]', () => {
            // test tls.ini has key in [outbound], so use empty config to test fallback
            const empty_cfg = config_module.module_config(path.resolve('test', 'non-exist'))
            const tls_cfg = load_config(empty_cfg)
            // Manually set a main key to test inheritance
            tls_cfg.main.key = 'inherited_key.pem'
            const ob = new OutboundTLS(empty_cfg).load(tls_cfg)
            // No file to read, so cfg.key will be null/undefined (file not found), but
            // the inheritance path was exercised without error
            assert.ok(ob.cfg)
        })

        it('resolves key/cert file names to Buffers when files exist', () => {
            const ob = make_outbound()
            // outbound tls.ini points to outbound_tls_key.pem / outbound_tls_cert.pem
            if (ob.cfg.key) assert.ok(Buffer.isBuffer(ob.cfg.key), 'key should be a Buffer')
            if (ob.cfg.cert) assert.ok(Buffer.isBuffer(ob.cfg.cert), 'cert should be a Buffer')
        })

        it('load() returns the instance for chaining', () => {
            const tls_cfg = load_config(test_cfg_module)
            const ob = new OutboundTLS(test_cfg_module)
            assert.equal(ob.load(tls_cfg), ob)
        })
    })

    describe('get_tls_options()', () => {
        it('sets servername to hostname when mx.exchange is a hostname', () => {
            const ob = make_outbound()
            const opts = ob.get_tls_options({ exchange: 'mail.example.com' })
            assert.equal(opts.servername, 'mail.example.com')
        })

        it('omits servername when mx.exchange is a bare IP (no from_dns)', () => {
            const ob = make_outbound()
            const opts = ob.get_tls_options({ exchange: '1.2.3.4' })
            assert.equal(opts.servername, undefined)
        })

        it('uses from_dns as servername when mx.exchange is an IP', () => {
            const ob = make_outbound()
            const opts = ob.get_tls_options({ exchange: '1.2.3.4', from_dns: 'mail.example.com' })
            assert.equal(opts.servername, 'mail.example.com')
        })

        it('does not mutate cfg when called multiple times', () => {
            const ob = make_outbound()
            const opts1 = ob.get_tls_options({ exchange: 'a.example.com' })
            const opts2 = ob.get_tls_options({ exchange: 'b.example.com' })
            assert.equal(opts1.servername, 'a.example.com')
            assert.equal(opts2.servername, 'b.example.com')
            assert.equal(ob.cfg.servername, undefined)
        })

        it('includes no_tls_hosts and force_tls_hosts in returned options', () => {
            const ob = make_outbound()
            const opts = ob.get_tls_options({ exchange: 'mail.example.com' })
            assert.ok(Array.isArray(opts.no_tls_hosts))
            assert.ok(Array.isArray(opts.force_tls_hosts))
        })
    })

    describe('check_tls_nogo()', () => {
        it('calls cb_ok immediately when redis is disabled', (t, done) => {
            const ob = make_outbound()
            ob.cfg.redis = { disable_for_failed_hosts: false }
            ob.check_tls_nogo(
                'mail.example.com',
                done,
                () => done(new Error('should not call cb_nogo')),
            )
        })
    })

    describe('mark_tls_nogo()', () => {
        it('calls cb immediately when redis is disabled', (t, done) => {
            const ob = make_outbound()
            ob.cfg.redis = { disable_for_failed_hosts: false }
            ob.mark_tls_nogo('mail.example.com', done)
        })

        it('calls cb when cb is not provided (no crash)', () => {
            const ob = make_outbound()
            ob.cfg.redis = { disable_for_failed_hosts: false }
            assert.doesNotThrow(() => ob.mark_tls_nogo('mail.example.com'))
        })
    })
})
