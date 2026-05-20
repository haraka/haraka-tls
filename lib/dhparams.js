'use strict'

// Ensure a Diffie-Hellman parameters file exists, generating one if needed.
// 2048-bit generation is slow (~30s); only the master process does the work
// and only when the file is missing.

const cluster = require('node:cluster')
const path = require('node:path')
const child_process = require('node:child_process')

const log = require('./logger')

/**
 * If `dhparam` is already loaded (Buffer in base_opts), invoke cb with it.
 * Otherwise spawn `openssl dhparam -out <path> 2048` and load the result.
 *
 * Worker processes do nothing (they pick up the file once the master writes
 * it and re-loads config). Callers should defer relying on DH params until
 * after the callback fires on the master.
 *
 * @param {object}   cfg_module       - haraka-config (or module_config result)
 * @param {object}   opts
 * @param {Buffer}   [opts.dhparam]   - already-loaded DH params (no-op path)
 * @param {string}   [opts.filename]  - filename to generate (default dhparams.pem)
 * @param {number}   [opts.bits]      - key size (default 2048)
 * @param {number}   [opts.timeout]   - spawn timeout in ms (default 60000)
 * @param {Function} cb               - (err, buffer) => void
 */
function ensure_dhparams(cfg_module, opts, cb) {
  if (typeof opts === 'function') {
    cb = opts
    opts = {}
  }

  if (opts.dhparam) return cb(null, opts.dhparam)

  // Workers wait for the master to produce the file.
  if (cluster.isWorker) return cb(null, null)

  const filename = opts.filename || 'dhparams.pem'
  const bits = opts.bits || 2048
  const timeout = opts.timeout || 60000
  const out_path = path.resolve(cfg_module.root_path || '.', filename)

  log.info(`tls/dhparams: generating a ${bits} bit dhparams file at ${out_path}`)

  // Call via the module ref (not a destructured const) so tests can patch
  // child_process.spawn.
  const proc = child_process.spawn('openssl', ['dhparam', '-out', out_path, String(bits)], { timeout })

  // openssl writes a progress spinner to stderr — silently consume it
  proc.stdout?.on('data', (data) => log.debug(`tls/dhparams: ${data}`))
  proc.stderr?.on('data', () => {})

  // 'error' and 'close' can both fire (e.g. ENOENT triggers error then exit).
  // Make sure cb is invoked exactly once.
  let done = false
  const finish = (err, out) => {
    if (done) return
    done = true
    cb(err, out)
  }

  proc.on('error', (err) => finish(err))

  proc.on('close', (code) => {
    if (code !== 0) return finish(new Error(`openssl dhparam exited with code ${code}`))
    log.info(`tls/dhparams: saved to ${out_path}`)
    const content = cfg_module.get(filename, 'binary')
    finish(null, content)
  })
}

module.exports = { ensure_dhparams }
