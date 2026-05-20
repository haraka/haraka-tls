'use strict'

const net = require('node:net')

const logger = require('./logger')

// haraka-plugin-redis is an optional dependency, loaded lazily in init()
// to avoid MODULE_NOT_FOUND when the TLS-NO-GO feature is not used.

// Config keys that [outbound] inherits from [main] when not locally overridden.
// Exhaustive: adding a new TLS option to tls.ini[main] is sufficient — no
// code change needed here.
const MAIN_INHERITABLE = [
  'key',
  'cert',
  'dhparam',
  'ciphers',
  'minVersion',
  'honorCipherOrder',
  'requestCert',
  'rejectUnauthorized',
]

/**
 * Manages outbound TLS configuration and the Redis "TLS-NO-GO" cache that
 * tracks remote hosts which have previously failed TLS negotiation.
 *
 * Usage:
 *   const ob = new OutboundTLS(config_module)
 *   ob.load(tls_cfg)           // tls_cfg from tls/config.load()
 *   await ob.init(cb)          // starts Redis if enabled
 *   const opts = ob.get_tls_options(mx)
 */
class OutboundTLS {
  constructor(cfg_module) {
    this.config = cfg_module
    this.name = 'OutboundTLS'
    this._certs = null // optional: certs Map from load_dir() for mutual TLS
    logger.add_log_methods(this)
  }

  /**
   * Build the outbound TLS config from the merged tls_cfg returned by
   * tls/config.load().  Resolves file-name references to Buffers.
   *
   * @param  {object} tls_cfg  - result of tls/config.load()
   * @returns {this}
   */
  load(tls_cfg) {
    const cfg = { ...tls_cfg.outbound }
    cfg.redis = tls_cfg.redis // Don't clone — may contain a live redis client

    // Inherit missing options from [main]
    for (const opt of MAIN_INHERITABLE) {
      if (cfg[opt] !== undefined) continue
      if (tls_cfg.main[opt] !== undefined) cfg[opt] = tls_cfg.main[opt]
    }

    // Resolve file-name strings → Buffers using the haraka-config module
    for (const field of ['key', 'cert', 'dhparam']) {
      if (!cfg[field]) continue
      const filename = Array.isArray(cfg[field]) ? cfg[field][0] : cfg[field]
      cfg[field] = this.config.get(filename, 'binary')
    }

    cfg.no_tls_hosts = Array.isArray(cfg.no_tls_hosts) ? cfg.no_tls_hosts : []
    cfg.force_tls_hosts = Array.isArray(cfg.force_tls_hosts) ? cfg.force_tls_hosts : []

    this.cfg = cfg
    return this
  }

  /**
   * Optionally connect to Redis for the TLS-NO-GO feature.
   *
   * Returns a Promise that resolves once Redis is ready (or immediately when
   * the feature is disabled). `haraka-plugin-redis` is required lazily so that
   * callers who don't enable `[redis] disable_for_failed_hosts` never need it
   * installed.
   *
   * @returns {Promise<void>}
   */
  async init() {
    if (!this.cfg.redis?.disable_for_failed_hosts) return
    this.logdebug('Will disable outbound TLS for failing TLS hosts')

    let hkredis
    try {
      hkredis = require('haraka-plugin-redis')
    } catch (err) {
      throw new Error(
        `tls/outbound: [redis] disable_for_failed_hosts=true requires haraka-plugin-redis (npm install haraka-plugin-redis): ${err.message}`,
      )
    }

    Object.assign(this, hkredis)
    this.merge_redis_ini()

    await new Promise((resolve, reject) => {
      try {
        this.init_redis_plugin((err) => (err ? reject(err) : resolve()))
      } catch (err) {
        reject(err)
      }
    })
  }

  /**
   * Provide a hostname → { key, cert } Map so apply_mutual_tls() can find
   * client certificates. Typically the Map returned by load_dir().
   *
   * @param {Map<string, { key: Buffer, cert: Buffer }>} certs
   */
  set_certs(certs) {
    this._certs = certs
  }

  /**
   * If `host` is in tls.ini [mutual_auth_hosts] or [main] mutual_tls is set,
   * mix the corresponding client cert/key into tls_opts. Returns a new
   * options object — tls_opts is not mutated.
   *
   * @param  {string} host
   * @param  {object} tls_opts
   * @returns {object}
   */
  apply_mutual_tls(host, tls_opts = {}) {
    const mah = this.cfg?.mutual_auth_hosts
    const mae = this.cfg?.mutual_auth_hosts_exclude
    const main = this.cfg?.main

    // Pick the cert source: explicit override CN, the host itself, or none.
    // Use `in` for the exclude check — Haraka's config allows empty-string
    // values for "host present, no override CN", which is falsy.
    let cert_for
    if (host && mah?.[host]) {
      cert_for = mah[host] // may be `true` (use host) or a specific CN
      if (cert_for === true || cert_for === 'true') cert_for = host
    } else if (host && mae && host in mae) {
      return { ...tls_opts } // explicitly excluded
    } else if (main?.mutual_tls && host) {
      cert_for = host
    } else {
      return { ...tls_opts }
    }

    const entry = this._certs?.get(cert_for) ?? this._certs?.get('*')
    if (!entry || !entry.key || !entry.cert) return { ...tls_opts }

    return { ...tls_opts, key: entry.key, cert: entry.cert }
  }

  /**
   * Return a TLS options object for an outbound connection to the given MX.
   * Sets `servername` to a hostname (never an IP) for correct SNI behaviour.
   *
   * @param  {{ exchange: string, from_dns?: string }} mx
   * @returns {object}
   */
  get_tls_options(mx) {
    const opts = { ...this.cfg }
    if (net.isIP(mx.exchange)) {
      if (mx.from_dns) opts.servername = mx.from_dns
    } else {
      opts.servername = mx.exchange
    }
    return opts
  }

  /**
   * Check whether `host` is in the TLS-NO-GO cache.
   * Calls cb_ok() if TLS should be attempted, cb_nogo(reason) if not.
   */
  check_tls_nogo(host, cb_ok, cb_nogo) {
    if (!this.cfg.redis?.disable_for_failed_hosts) return cb_ok()
    this.db
      .get(`no_tls|${host}`)
      .then((r) => (r ? cb_nogo(r) : cb_ok()))
      .catch((err) => {
        this.logdebug(`Redis error during check_tls_nogo: ${err}`)
        cb_ok()
      })
  }

  /**
   * Record that `host` failed TLS so future connections skip it.
   * @param {string}   host
   * @param {Function} [cb]
   */
  mark_tls_nogo(host, cb) {
    if (!this.cfg.redis?.disable_for_failed_hosts) return cb?.()
    const expiry = this.cfg.redis.disable_expiry ?? 604800
    this.lognotice(`TLS failed for ${host}, disabling for ${expiry}s`)
    this.db
      .setEx(`no_tls|${host}`, expiry, new Date().toISOString())
      .then(() => cb?.())
      .catch((err) => {
        this.logerror(`Redis error during mark_tls_nogo: ${err}`)
      })
  }
}

module.exports = { OutboundTLS }
