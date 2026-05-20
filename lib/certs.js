'use strict'

// Certificate parsing and directory loading.
// Uses Node's built-in crypto.X509Certificate — no openssl subprocess needed.

const { X509Certificate } = require('node:crypto')
const path = require('node:path')

const log = require('./logger')

// PEM block patterns
const KEY_RE = /(-----BEGIN (?:\w+ )?PRIVATE KEY-----[\s\S]*?-----END (?:\w+ )?PRIVATE KEY-----)/g
const CERT_RE = /(-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)/g

/**
 * Parse a PEM string and extract private key(s), certificate chain,
 * hostnames (CN + SANs), and the leaf certificate's expiry date.
 *
 * @param  {string} pem
 * @returns {{ keys?: string[], chain?: string[], names?: string[], expire?: Date }}
 */
function parse_pem(pem) {
  const res = {}
  if (!pem) return res

  const keys = Array.from(pem.matchAll(KEY_RE), (m) => m[1])
  if (keys.length) res.keys = keys

  const chain = Array.from(pem.matchAll(CERT_RE), (m) => m[1])
  if (!chain.length) return res

  res.chain = chain

  try {
    const leaf = new X509Certificate(chain[0])
    res.expire = new Date(leaf.validTo)

    const cn_match = /CN=([^,\n]+)/.exec(leaf.subject)
    res.names = cn_match ? [cn_match[1].trim()] : []

    if (leaf.subjectAltName) {
      for (const san of leaf.subjectAltName.split(',')) {
        const m = /DNS:(.+)/.exec(san.trim())
        if (m) {
          const name = m[1].trim()
          if (!res.names.includes(name)) res.names.push(name)
        }
      }
    }
  } catch (err) {
    log.debug(`tls/certs: X509Certificate parse error: ${err.message}`)
  }

  return res
}

/**
 * Load every PEM file in a config directory and return a Map of
 *   hostname → { key: Buffer, cert: Buffer, file: string }
 *
 * Files with a key but no embedded cert have their filename used as the CN.
 * Incomplete pairs (key without cert or vice-versa) are silently dropped.
 * Expired certificates are logged as errors but still loaded.
 *
 * If `opts.watchCb` is provided, haraka-config watches the directory and
 * fires `watchCb()` (no args) on any change. Watchers are deduped by path.
 *
 * @param  {object}   cfg_module    - haraka-config module (supports .getDir)
 * @param  {string}   dir_name      - directory name relative to config root (e.g. 'tls')
 * @param  {object}   [opts]
 * @param  {Function} [opts.watchCb] - called (no args) on any change in the directory
 * @returns {Promise<Map<string, {key: Buffer, cert: Buffer, file: string}>>}
 */
async function load_dir(cfg_module, dir_name, opts = {}) {
  const result = new Map()
  let files

  const getDir_opts = { type: 'binary' }
  if (opts.watchCb) getDir_opts.watchCb = opts.watchCb

  try {
    files = await cfg_module.getDir(dir_name, getDir_opts)
  } catch (err) {
    if (err.code !== 'ENOENT') log.error(`tls/certs: load_dir ${dir_name}: ${err.message}`)
    return result
  }

  if (!files?.length) return result

  // ── Stage 1: parse every file ─────────────────────────────────────────────

  const parsed = {}
  for (const file of files) {
    try {
      parsed[file.path] = parse_pem(file.data.toString())
    } catch (err) {
      log.debug(`tls/certs: skipping ${file.path}: ${err.message}`)
    }
  }

  log.debug(`tls/certs: parsed ${Object.keys(parsed).length} file(s) in ${dir_name}`)

  // ── Stage 2: collate by hostname ──────────────────────────────────────────

  const by_name = {}
  for (const [fp, info] of Object.entries(parsed)) {
    if (info.expire && info.expire < new Date()) {
      log.error(`tls/certs: ${fp} expired on ${info.expire.toUTCString()}`)
    }

    // Files with a key but no embedded cert use the base filename as the CN.
    // The `_` → `*` rewrite is a Windows-filename workaround and applies only
    // to filename-derived names, not to legitimate SAN/CN entries that may
    // legitimately start with `_` (e.g. `_dmarc.example.com`).
    if (!info.names) {
      let base = path.parse(fp).name
      if (base.startsWith('_')) base = `*${base.slice(1)}`
      info.names = [base]
    }

    for (const name of info.names) {
      by_name[name] ??= {}
      if (!by_name[name].key && info.keys?.length) by_name[name].key = info.keys[0]
      if (!by_name[name].cert && info.chain?.length) {
        // Preserve the full chain (leaf + intermediates) so clients receive
        // the certs they need for validation. tls.createSecureContext accepts
        // a single PEM string containing multiple cert blocks.
        by_name[name].cert = info.chain.join('\n')
        by_name[name].file = fp
      }
    }
  }

  // ── Stage 3: emit complete pairs only ─────────────────────────────────────

  for (const [name, entry] of Object.entries(by_name)) {
    if (!entry.key || !entry.cert) {
      log.debug(`tls/certs: incomplete pair for "${name}" (key=${!!entry.key} cert=${!!entry.cert}), skipping`)
      continue
    }
    result.set(name, {
      key: Buffer.from(entry.key),
      cert: Buffer.from(entry.cert),
      file: entry.file,
    })
  }

  log.info(`tls/certs: loaded ${result.size} cert(s) from ${dir_name}`)
  return result
}

module.exports = { parse_pem, load_dir }
