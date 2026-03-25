'use strict'

// Pure config loading — no global state, no side effects.
// Returns a plain object that callers own and may mutate freely.

const BOOLEANS = [
  '-redis.disable_for_failed_hosts',

  // Wildcards initialise the type parser but not the value
  '*.requestCert',
  '*.rejectUnauthorized',
  '*.honorCipherOrder',
  '*.requestOCSP',

  // Explicitly declared so the defaults below are applied
  '+main.requestCert',
  '-main.rejectUnauthorized',
  '+main.honorCipherOrder',
  '-main.requestOCSP',
  '-main.mutual_tls',
]

/**
 * Load tls.ini via the given haraka-config module and return a normalised
 * config object.  Calling load() twice with the same cfg_module is safe and
 * cheap — each call returns a fresh plain object.
 *
 * @param  {object} cfg_module  - haraka-config (or module_config() result)
 * @returns {object} Normalised TLS config
 */
function load(cfg_module) {
  const raw = cfg_module.get('tls.ini', { booleans: BOOLEANS })

  // Handle deprecated enableOCSPStapling alias
  if (raw.main?.enableOCSPStapling !== undefined) {
    raw.main.requestOCSP = raw.main.enableOCSPStapling
    delete raw.main.enableOCSPStapling
  }

  const result = {
    main: { ...raw.main },
    redis: { disable_for_failed_hosts: false, ...raw.redis },
    no_tls_hosts: raw.no_tls_hosts ?? {},
    mutual_auth_hosts: raw.mutual_auth_hosts ?? {},
    mutual_auth_hosts_exclude: raw.mutual_auth_hosts_exclude ?? {},
    outbound: { ...(raw.outbound ?? {}) },
  }

  // Always arrays — avoids scattered defensive checks everywhere
  result.main.requireAuthorized = [result.main.requireAuthorized].flat().filter(Boolean)
  result.main.no_starttls_ports = [result.main.no_starttls_ports].flat().filter(Boolean)

  if (!Array.isArray(result.outbound.no_tls_hosts)) result.outbound.no_tls_hosts = []
  if (!Array.isArray(result.outbound.force_tls_hosts)) result.outbound.force_tls_hosts = []

  return result
}

module.exports = { load }
