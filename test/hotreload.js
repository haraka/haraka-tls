'use strict'

const { describe, it, before, after } = require('node:test')
const assert = require('node:assert')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const config_module = require('haraka-config')

const { ContextStore } = require('../lib/context')
const { OutboundTLS } = require('../lib/outbound')
const { watch } = require('..')

// haraka-config watchers debounce file events for ~2s before firing watchCb,
// then we read+parse+apply. On busy CI runners that chain can take >5s, so
// give the predicate generous headroom.
const WATCH_TIMEOUT_MS = 8000
const POLL_MS = 50

function wait_for(predicate, timeout = WATCH_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeout
    ;(function tick() {
      if (predicate()) return resolve()
      if (Date.now() > deadline) return reject(new Error('wait_for: timeout'))
      setTimeout(tick, POLL_MS)
    })()
  })
}

describe('tls/watch (hot reload)', () => {
  let tmproot
  let cfg_root
  let cfg_module_instance
  let cert_a
  let cert_b
  let key_a
  let key_b

  before(() => {
    tmproot = fs.mkdtempSync(path.join(os.tmpdir(), 'haraka-tls-watch-'))
    cfg_root = path.join(tmproot, 'config')
    fs.mkdirSync(path.join(cfg_root, 'tls'), { recursive: true })

    // Two distinct key+cert pairs to swap between. Use the EC fixture as
    // material — the parser only cares that the file is a valid PEM with a
    // CN; we'll rewrite the file in place to simulate renewal.
    const fixture_dir = path.resolve(__dirname, 'config', 'tls')
    const haraka_local = fs.readFileSync(path.join(fixture_dir, 'haraka.local.pem'), 'utf8')
    const ec = fs.readFileSync(path.join(fixture_dir, 'ec.pem'), 'utf8')

    cert_a = haraka_local // CN=haraka.local
    cert_b = ec // CN=mail.haraka.io
    key_a = cert_a
    key_b = cert_b

    fs.writeFileSync(path.join(cfg_root, 'tls.ini'), '[main]\nrejectUnauthorized=false\n')
    fs.writeFileSync(path.join(cfg_root, 'tls', 'host.pem'), cert_a)

    cfg_module_instance = config_module.module_config(tmproot)
    void key_a
    void key_b
  })

  after(() => {
    fs.rmSync(tmproot, { recursive: true, force: true })
  })

  it('rebuilds contexts when a cert file changes', async () => {
    const contexts = new ContextStore()
    const events = []
    const handle = await watch(cfg_module_instance, {
      contexts,
      onChange: ({ certs }) => events.push(certs.size),
    })

    try {
      // Initial state: haraka.local is loaded
      assert.ok(contexts.has('haraka.local'), 'initial cert loaded')
      assert.equal(contexts.has('mail.haraka.io'), false, 'second cert not yet loaded')
      assert.equal(events.length, 1, 'one apply on startup')

      // Swap the cert file in place
      fs.writeFileSync(path.join(cfg_root, 'tls', 'host.pem'), cert_b)

      await wait_for(() => contexts.has('mail.haraka.io'))
      assert.ok(contexts.has('mail.haraka.io'), 'new cert picked up after change')
      assert.ok(events.length >= 2, `onChange fired at least twice (got ${events.length})`)
    } finally {
      handle.cancel()
    }
  })

  it('reloads OutboundTLS cfg + certs when configured', async () => {
    // Start fresh tmpdir for this case so watchers don't collide
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'haraka-tls-watch-ob-'))
    const cfg_root2 = path.join(root, 'config')
    fs.mkdirSync(path.join(cfg_root2, 'tls'), { recursive: true })
    fs.writeFileSync(path.join(cfg_root2, 'tls.ini'), '[main]\nrejectUnauthorized=false\n')
    fs.writeFileSync(path.join(cfg_root2, 'tls', 'host.pem'), cert_a)

    const cfgm = config_module.module_config(root)
    const contexts = new ContextStore()
    const outbound = new OutboundTLS(cfgm)
    const handle = await watch(cfgm, { contexts, outbound })

    try {
      assert.ok(outbound.cfg, 'outbound loaded on startup')
      assert.ok(outbound._certs.has('haraka.local'), 'outbound certs map populated')

      // Edit tls.ini, then touch the cert dir to trigger the reload.
      // haraka-config's file watcher (used by `get`) is registered against
      // the singleton config_path on Linux, so a direct tls.ini edit in a
      // tmpdir isn't observed. The cert-dir watcher (used by `getDir`)
      // watches the actual path passed in and fires on all platforms; its
      // callback re-reads tls.ini, picking up our edit.
      fs.writeFileSync(path.join(cfg_root2, 'tls.ini'), '[main]\nrejectUnauthorized=true\n')
      fs.writeFileSync(path.join(cfg_root2, 'tls', 'host.pem'), cert_b)
      await wait_for(() => outbound.cfg?.rejectUnauthorized === true)
      assert.equal(outbound.cfg.rejectUnauthorized, true, 'outbound cfg reflects tls.ini edit')
    } finally {
      handle.cancel()
      fs.rmSync(root, { recursive: true, force: true })
    }
  })

  it('cancel() stops applying changes', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'haraka-tls-watch-cancel-'))
    const cfg_root3 = path.join(root, 'config')
    fs.mkdirSync(path.join(cfg_root3, 'tls'), { recursive: true })
    fs.writeFileSync(path.join(cfg_root3, 'tls.ini'), '[main]\n')
    fs.writeFileSync(path.join(cfg_root3, 'tls', 'host.pem'), cert_a)

    const cfgm = config_module.module_config(root)
    const contexts = new ContextStore()
    let calls = 0
    const handle = await watch(cfgm, { contexts, onChange: () => calls++ })

    try {
      assert.equal(calls, 1, 'one onChange call from initial apply')
      handle.cancel()

      // Touch the file post-cancel — onChange must not fire
      fs.writeFileSync(path.join(cfg_root3, 'tls', 'host.pem'), cert_b)
      // Wait past the debounce window
      await new Promise((r) => setTimeout(r, 3000))
      assert.equal(calls, 1, 'onChange did not fire after cancel()')
    } finally {
      handle.cancel()
      fs.rmSync(root, { recursive: true, force: true })
    }
  })
})
