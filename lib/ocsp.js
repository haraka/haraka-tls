'use strict'

// OCSP stapling — attach an OCSPRequest listener to a tls.Server so peer
// certificates are stapled with a fresh status response. @haraka/ocsp is an
// optional dependency; this module loads it lazily so callers who don't use
// OCSP never need it installed.

const util = require('node:util')

const log = require('./logger')

let _ocsp
let _cache

function load_ocsp() {
  if (_ocsp !== undefined) return _ocsp
  try {
    _ocsp = require('@haraka/ocsp')
    _cache = new _ocsp.Cache()
    log.debug('tls/ocsp: @haraka/ocsp loaded')
  } catch (err) {
    _ocsp = null
    log.notice(`tls/ocsp: OCSP stapling not available (${err.code || err.message})`)
  }
  return _ocsp
}

/**
 * Attach an OCSPRequest listener to `server` so it staples OCSP responses
 * during the TLS handshake. Cached responses are reused until they expire.
 *
 * Does nothing if @haraka/ocsp is not installed or if the listener is
 * already attached.
 *
 * @param {tls.Server} server
 */
function add_ocsp(server) {
  const ocsp = load_ocsp()
  if (!ocsp) return

  if (server.listenerCount('OCSPRequest') > 0) {
    log.debug('tls/ocsp: OCSPRequest listener already attached')
    return
  }

  log.debug('tls/ocsp: attaching OCSPRequest listener')
  server.on('OCSPRequest', (cert, issuer, cb) => {
    ocsp.getOCSPURI(cert, async (err, uri) => {
      if (err) return cb(err)
      if (uri === null) return cb() // no OCSP responder advertised

      const req = ocsp.request.generate(cert, issuer)
      try {
        const cached = await _cache.probe(req.id)
        if (cached) {
          log.debug(`tls/ocsp: cache hit ${util.inspect(cached)}`)
          return cb(null, cached.response)
        }
        _cache.request(req.id, { url: uri, ocsp: req.data }, cb)
      } catch (probe_err) {
        cb(probe_err)
      }
    })
  })
}

/**
 * Clear OCSP cache timers so the process can exit cleanly.
 * Safe to call when OCSP was never loaded.
 */
function shutdown() {
  if (!_cache) return
  log.debug(`tls/ocsp: clearing ${Object.keys(_cache.cache).length} cache entries`)
  for (const key of Object.keys(_cache.cache)) {
    clearTimeout(_cache.cache[key].timer)
  }
}

// Exposed for tests
function _reset() {
  _ocsp = undefined
  _cache = undefined
}

module.exports = { add_ocsp, shutdown, _reset }
