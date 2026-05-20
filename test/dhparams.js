'use strict'

const { describe, it, beforeEach, afterEach } = require('node:test')
const assert = require('node:assert')
const child_process = require('node:child_process')
const cluster = require('node:cluster')
const { EventEmitter } = require('node:events')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const { ensure_dhparams } = require('../lib/dhparams')

// Always point at an ephemeral tmpdir so that, if the spawn mock ever fails to
// attach and real openssl runs, it can't overwrite a checked-in fixture.
const tmp_root = fs.mkdtempSync(path.join(os.tmpdir(), 'haraka-tls-dh-'))

function make_cfg_module(overrides = {}) {
  return {
    root_path: overrides.root_path ?? tmp_root,
    get: overrides.get ?? (() => Buffer.from('FAKE_DH_PARAMS')),
  }
}

describe('tls/dhparams', () => {
  describe('ensure_dhparams()', () => {
    let orig_spawn, orig_isWorker, spawn_args, fake_proc

    beforeEach(() => {
      orig_spawn = child_process.spawn
      orig_isWorker = cluster.isWorker
      spawn_args = null
      fake_proc = new EventEmitter()
      fake_proc.stdout = new EventEmitter()
      fake_proc.stderr = new EventEmitter()
      child_process.spawn = (cmd, args, opts) => {
        spawn_args = { cmd, args, opts }
        return fake_proc
      }
    })

    afterEach(() => {
      child_process.spawn = orig_spawn
      Object.defineProperty(cluster, 'isWorker', { value: orig_isWorker, configurable: true })
    })

    it('invokes cb immediately when dhparam is already loaded', (t, done) => {
      const buf = Buffer.from('already-loaded')
      ensure_dhparams(make_cfg_module(), { dhparam: buf }, (err, out) => {
        assert.equal(err, null)
        assert.equal(out, buf)
        assert.equal(spawn_args, null, 'spawn should not be called')
        done()
      })
    })

    it('on a worker, does nothing (waits for master)', (t, done) => {
      Object.defineProperty(cluster, 'isWorker', { value: true, configurable: true })
      ensure_dhparams(make_cfg_module(), {}, (err, out) => {
        assert.equal(err, null)
        assert.equal(out, null)
        assert.equal(spawn_args, null, 'spawn should not be called on workers')
        done()
      })
    })

    it('spawns openssl dhparam with the configured bit size', (t, done) => {
      Object.defineProperty(cluster, 'isWorker', { value: false, configurable: true })
      ensure_dhparams(make_cfg_module(), { bits: 4096, filename: 'dh.pem' }, (err, out) => {
        assert.equal(err, null)
        assert.ok(Buffer.isBuffer(out))
        assert.equal(spawn_args.cmd, 'openssl')
        assert.deepEqual(spawn_args.args.slice(0, 2), ['dhparam', '-out'])
        assert.ok(spawn_args.args[2].endsWith('dh.pem'))
        assert.equal(spawn_args.args[3], '4096')
        done()
      })
      // Simulate openssl finishing successfully
      setImmediate(() => fake_proc.emit('close', 0))
    })

    it('reports non-zero exit code via cb', (t, done) => {
      Object.defineProperty(cluster, 'isWorker', { value: false, configurable: true })
      ensure_dhparams(make_cfg_module(), {}, (err) => {
        assert.ok(err instanceof Error)
        assert.match(err.message, /exited with code 1/)
        done()
      })
      setImmediate(() => fake_proc.emit('close', 1))
    })

    it('forwards spawn errors via cb', (t, done) => {
      Object.defineProperty(cluster, 'isWorker', { value: false, configurable: true })
      const spawn_err = new Error('ENOENT openssl')
      ensure_dhparams(make_cfg_module(), {}, (err) => {
        assert.equal(err, spawn_err)
        done()
      })
      setImmediate(() => fake_proc.emit('error', spawn_err))
    })
  })
})
