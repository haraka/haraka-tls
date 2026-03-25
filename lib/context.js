'use strict'

const tls = require('node:tls')

const log = require('./logger')

/**
 * Build a tls.SecureContext from the given options.
 * Throws on invalid key/cert material so callers can handle errors explicitly.
 *
 * @param  {object} opts - options accepted by tls.createSecureContext()
 * @returns {tls.SecureContext}
 */
function build_context(opts) {
    return tls.createSecureContext(opts)
}

/**
 * Manages a set of TLS SecureContexts keyed by hostname.
 *
 * The special key '*' is the default/fallback used by SNI when no
 * hostname-specific context exists.
 */
class ContextStore {
    constructor() {
        this._ctxs = new Map()
    }

    /** Store a context under the given name (use '*' for the default). */
    set(name, ctx) {
        this._ctxs.set(name, ctx)
    }

    /**
     * Return the context for `name`, falling back to '*'.
     * Returns undefined only when no default context has been set.
     */
    get(name) {
        return this._ctxs.get(name) ?? this._ctxs.get('*')
    }

    has(name) {
        return this._ctxs.has(name)
    }

    get size() {
        return this._ctxs.size
    }

    /**
     * Build contexts from a base-options object and a certs Map produced by
     * tls/certs.load_dir().
     *
     * The base_opts are used for the default '*' context and as a template
     * for per-hostname contexts (with the hostname's key/cert substituted in).
     *
     * @param {object}                         base_opts  - base TLS options
     * @param {Map<string, {key, cert}>}       certs      - per-hostname material
     */
    build(base_opts, certs) {
        // Default context
        if (base_opts.key && base_opts.cert) {
            try {
                this.set('*', build_context(base_opts))
                log.debug('tls/context: built default (*) context')
            } catch (err) {
                log.error(`tls/context: failed to build default context: ${err.message}`)
            }
        }

        // Per-hostname contexts (inherit base opts, override key/cert)
        for (const [name, entry] of certs) {
            try {
                this.set(name, build_context({ ...base_opts, key: entry.key, cert: entry.cert }))
                log.debug(`tls/context: built context for ${name}`)
            } catch (err) {
                log.error(`tls/context: failed to build context for "${name}": ${err.message}`)
            }
        }
    }

    /**
     * Return an SNI callback suitable for passing to tls.TLSSocket / tls.Server.
     * Resolves to the most specific context available, falling back to '*'.
     *
     * @returns {Function} (servername: string, done: Function) => void
     */
    sni_callback() {
        return (servername, done) => {
            const ctx = this.get(servername)
            if (!this._ctxs.has(servername)) {
                log.debug(`tls/context: no context for "${servername}", using default`)
            }
            done(null, ctx ?? null)
        }
    }

    /** Clear all stored contexts (e.g. to force a reload). */
    invalidate() {
        this._ctxs.clear()
    }
}

module.exports = { ContextStore, build_context }
