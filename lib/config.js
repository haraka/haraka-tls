'use strict'

// Pure config loading — no global state, no side effects.
// Returns a plain object that callers own and may mutate freely.

// Options a plugin's [tls] section inherits from tls.ini [main]. Deliberately
// omits no_tls_hosts: the [main].no_tls_hosts list is documented as
// inbound-only; outbound plugins should opt in via their own section.
const PLUGIN_INHERITABLE = [
  'key',
  'cert',
  'ciphers',
  'minVersion',
  'dhparam',
  'requestCert',
  'honorCipherOrder',
  'rejectUnauthorized',
  'force_tls_hosts',
]

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
 * If `opts.watchCb` is provided, it is registered with haraka-config so the
 * callback fires whenever tls.ini changes on disk. haraka-config dedupes
 * watchers by path, so calling load() repeatedly with watchCb is safe.
 *
 * @param  {object}   cfg_module    - haraka-config (or module_config() result)
 * @param  {object}   [opts]
 * @param  {Function} [opts.watchCb] - called (no args) when tls.ini changes
 * @returns {object} Normalised TLS config
 */
function load(cfg_module, opts = {}) {
  const raw = opts.watchCb
    ? cfg_module.get('tls.ini', { booleans: BOOLEANS }, opts.watchCb)
    : cfg_module.get('tls.ini', { booleans: BOOLEANS })

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

/**
 * Merge a plugin's `[tls]` section over `tls.ini` `[main]` to produce a client
 * tls_options object suitable for an outbound STARTTLS upgrade. Resolves
 * key/cert/dhparam filename refs to Buffers via `cfg_module.get(name, 'binary')`.
 * Inputs are not mutated.
 *
 * @param  {object} cfg_module    - haraka-config (or module_config result)
 * @param  {object} main_cfg      - tls.ini [main] section
 * @param  {object} plugin_cfg    - plugin's own [tls] section
 * @returns {object} merged tls_options
 */
function merge_plugin_tls(cfg_module, main_cfg = {}, plugin_cfg = {}) {
  const cfg = JSON.parse(JSON.stringify(plugin_cfg))

  for (const opt of PLUGIN_INHERITABLE) {
    if (cfg[opt] !== undefined) continue // set in plugin [tls]
    if (main_cfg[opt] === undefined) continue // unset in tls.ini [main]
    cfg[opt] = main_cfg[opt]
  }

  // Resolve key/cert/dhparam file refs to buffers; drop empty results so we
  // never pass null to tls.connect.
  for (const k of ['key', 'cert', 'dhparam']) {
    if (!cfg[k]) {
      delete cfg[k]
      continue
    }
    const ref = Array.isArray(cfg[k]) ? cfg[k][0] : cfg[k]
    const bin = cfg_module.get(ref, 'binary')
    if (bin) cfg[k] = bin
    else delete cfg[k]
  }

  for (const k of ['no_tls_hosts', 'force_tls_hosts']) {
    if (!cfg[k]) {
      cfg[k] = []
      continue
    }
    if (!Array.isArray(cfg[k])) cfg[k] = [cfg[k]]
  }

  return cfg
}

module.exports = { load, merge_plugin_tls }
