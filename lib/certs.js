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
 * @param  {object} cfg_module  - haraka-config module (supports .getDir)
 * @param  {string} dir_name    - directory name relative to config root (e.g. 'tls')
 * @returns {Promise<Map<string, {key: Buffer, cert: Buffer, file: string}>>}
 */
async function load_dir(cfg_module, dir_name) {
  const result = new Map()
  let files

  try {
    files = await cfg_module.getDir(dir_name, { type: 'binary' })
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

    // Files with a key but no cert use the base filename as the CN
    if (!info.names) info.names = [path.parse(fp).name]

    for (let name of info.names) {
      if (name.startsWith('_')) name = name.replace('_', '*') // Windows wildcard workaround
      by_name[name] ??= {}
      if (!by_name[name].key && info.keys?.length) by_name[name].key = info.keys[0]
      if (!by_name[name].cert && info.chain?.length) {
        by_name[name].cert = info.chain[0]
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
