'use strict'

// haraka-tls: Modern TLS support for Haraka.
//
// Sub-modules are intentionally independent so callers can require only what
// they need without pulling in the entire stack.

const log = require('./lib/logger')

const { load: load_config, merge_plugin_tls } = require('./lib/config')
const { parse_pem, load_dir } = require('./lib/certs')
const { ContextStore, build_context } = require('./lib/context')
const { PluggableStream, createServer, connect, createConnection } = require('./lib/socket')
const { OutboundTLS } = require('./lib/outbound')
const { ensure_dhparams } = require('./lib/dhparams')
const { add_ocsp, shutdown: ocsp_shutdown } = require('./lib/ocsp')

/**
 * Hot-reload TLS state when tls.ini or files under `dir` change on disk.
 *
 * Loads the config and certs once, builds the ContextStore, and registers a
 * haraka-config watchCb on both paths. When a change fires (debounced 2s by
 * haraka-config) everything is re-read and ContextStore.rebuild() is called.
 * If `outbound` is passed, its config and certs are reloaded too.
 *
 * In-flight TLS connections keep their original SecureContext; only new
 * handshakes see the new certs. Each cluster worker watches independently
 * (haraka-config's watchers are process-local).
 *
 * @param {object}      cfg_module                    - haraka-config or module_config result
 * @param {object}      opts
 * @param {ContextStore} opts.contexts                - ContextStore to rebuild on change
 * @param {OutboundTLS} [opts.outbound]               - OutboundTLS to reload on change
 * @param {string}      [opts.dir='tls']              - cert directory (relative to config root)
 * @param {Function}    [opts.onChange]               - ({ cfg, certs }) => void after each rebuild
 * @returns {Promise<{ cancel(): void }>}
 */
async function watch(cfg_module, opts) {
  const { contexts, outbound, dir = 'tls', onChange } = opts
  if (!contexts) throw new Error('watch(): opts.contexts is required')

  let cfg
  let certs
  let cancelled = false

  const apply = () => {
    if (cancelled) return
    contexts.rebuild(cfg.main, certs)
    if (outbound) {
      outbound.load(cfg)
      outbound.set_certs(certs)
    }
    if (onChange) {
      try {
        onChange({ cfg, certs })
      } catch (err) {
        log.error(`tls/watch: onChange threw: ${err.message}`)
      }
    }
  }

  const reload = async () => {
    if (cancelled) return
    try {
      // haraka-config's read_dir overwrites stored opts on each call;
      // re-pass watchCb so the live watcher's callback stays defined.
      cfg = load_config(cfg_module, { watchCb: reload })
      certs = await load_dir(cfg_module, dir, { watchCb: reload })
      apply()
      log.debug(`tls/watch: rebuilt ${certs.size} cert(s) after change`)
    } catch (err) {
      log.error(`tls/watch: reload failed: ${err.message}`)
    }
  }

  cfg = load_config(cfg_module, { watchCb: reload })
  certs = await load_dir(cfg_module, dir, { watchCb: reload })
  apply()

  return {
    cancel() {
      cancelled = true
      cfg_module.stop_watching('tls.ini')
      cfg_module.stop_watching(dir)
    },
  }
}

module.exports = {
  // Config
  load_config,
  merge_plugin_tls,

  // Certificates
  parse_pem,
  load_dir,

  // TLS Contexts
  ContextStore,
  build_context,

  // Sockets
  PluggableStream,
  createServer,
  connect,
  createConnection,

  // Outbound
  OutboundTLS,

  // DH parameters
  ensure_dhparams,

  // OCSP stapling
  add_ocsp,
  ocsp_shutdown,

  // Hot reload
  watch,
}
