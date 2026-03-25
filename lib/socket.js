'use strict'

// Socket wrapper that supports transparent STARTTLS upgrade.
// Used for both inbound (server) and outbound (client) connections.

const net = require('node:net')
const tls = require('node:tls')
const { EventEmitter } = require('node:events')

const log = require('./logger')

// Events forwarded from the underlying socket to the wrapper
const FORWARDED_EVENTS = ['data', 'connect', 'end', 'close', 'drain', 'timeout']

/**
 * A transparent socket wrapper that delegates reads and writes to an
 * underlying net.Socket or tls.TLSSocket, and can be upgraded from plain
 * TCP to TLS mid-stream (STARTTLS) without changing the reference held by
 * the caller.
 *
 * Forwarded events: data, connect, secureConnect, secure, end, close, drain,
 *                   error, timeout
 */
class PluggableStream extends EventEmitter {
    constructor(socket) {
        super()
        this.readable = true
        this.writable = true
        this._timeout = 0
        this._keepalive = false
        this.targetsocket = null
        this.cleartext = null

        if (socket) this._attach(socket)
    }

    // ── Internal attachment/detachment ─────────────────────────────────────────

    _attach(socket) {
        this.targetsocket = socket

        socket.on('data', (d) => this.emit('data', d))
        socket.on('connect', (...a) => this.emit('connect', ...a))
        socket.on('secureConnect', (...a) => {
            this.emit('secureConnect', ...a)
            this.emit('secure', ...a)
        })
        socket.on('secure', (...a) => this.emit('secure', ...a))
        socket.on('end', () => {
            this.writable = socket.writable
            this.emit('end')
        })
        socket.on('close', (had_err) => {
            this.writable = socket.writable
            this.emit('close', had_err)
        })
        socket.on('drain', () => this.emit('drain'))
        socket.once('error', (err) => {
            this.writable = socket.writable
            err.source = 'tls'
            this.emit('error', err)
        })
        socket.on('timeout', () => this.emit('timeout'))

        // Mirror address metadata onto the wrapper
        for (const prop of ['remotePort', 'remoteAddress', 'localPort', 'localAddress']) {
            if (socket[prop] != null) this[prop] = socket[prop]
        }
    }

    _detach() {
        if (!this.targetsocket) return
        for (const event of ['data', 'secureConnect', 'secure', ...FORWARDED_EVENTS, 'error']) {
            this.targetsocket.removeAllListeners(event)
        }
        // Stub out the old socket so any stray writes go nowhere
        this.targetsocket = { write: () => false, end: () => {} }
    }

    // ── Socket interface (delegates to targetsocket) ───────────────────────────

    write(data, encoding, cb) {
        return this.targetsocket?.write(data, encoding, cb) ?? false
    }

    end(data, encoding) {
        return this.targetsocket?.end(data, encoding)
    }

    destroy() {
        return this.targetsocket?.destroy()
    }

    destroySoon() {
        return this.targetsocket?.destroySoon?.()
    }

    pause() {
        this.readable = false
        this.targetsocket?.pause()
    }

    resume() {
        this.readable = true
        this.targetsocket?.resume()
    }

    setTimeout(ms) {
        this._timeout = ms
        return this.targetsocket?.setTimeout(ms)
    }

    setKeepAlive(bool) {
        this._keepalive = bool
        return this.targetsocket?.setKeepAlive(bool)
    }

    setNoDelay() {} // no-op — callers may call this

    unref() {
        return this.targetsocket?.unref()
    }

    isEncrypted() {
        return this.targetsocket?.encrypted ?? false
    }

    isSecure() {
        return !!(this.targetsocket?.encrypted && this.targetsocket?.authorized)
    }
}

// ── Server factory ─────────────────────────────────────────────────────────────

/**
 * Create a net.Server whose connections are wrapped in PluggableStream.
 * Each socket gains an `.upgrade(cb)` method that performs the STARTTLS
 * handshake in-place.
 *
 * @param {object}   tls_state              - { contexts: ContextStore, cfg: object }
 * @param {Function} connection_handler     - called with (socket: PluggableStream)
 * @returns {net.Server}
 */
function createServer(tls_state, connection_handler) {
    const server = net.createServer((rawSocket) => {
        const socket = new PluggableStream(rawSocket)

        socket.upgrade = (upgrade_cb) => {
            log.debug('tls/socket: upgrading inbound connection to TLS')

            socket._detach()
            rawSocket.removeAllListeners('data')

            const { contexts, cfg } = tls_state
            const tls_opts = {
                ...cfg,
                isServer: true,
                server,
                SNICallback: contexts.sni_callback(),
            }

            if (cfg.requireAuthorized?.includes(rawSocket.localPort)) {
                tls_opts.rejectUnauthorized = true
            }

            const cleartext = new tls.TLSSocket(rawSocket, tls_opts)

            cleartext.on('error', (err) => {
                err.source = 'tls'
                socket.emit('error', err)
            })

            cleartext.on('secure', () => {
                log.debug('tls/socket: inbound TLS secured')
                socket._attach(cleartext)
                const cipher = cleartext.getCipher()
                if (cipher) cipher.version = cleartext.getProtocol()
                socket.emit('secure')
                upgrade_cb?.(
                    cleartext.authorized,
                    cleartext.authorizationError,
                    cleartext.getPeerCertificate(),
                    cipher,
                )
            })

            socket.cleartext = cleartext
            if (socket._timeout) cleartext.setTimeout(socket._timeout)
            cleartext.setKeepAlive(socket._keepalive)
        }

        connection_handler(socket)
    })

    return server
}

// ── Client factory ─────────────────────────────────────────────────────────────

/**
 * Create a plain TCP socket wrapped in PluggableStream.
 * The socket has an `.upgrade(tls_opts, cb)` method for outbound STARTTLS.
 *
 * @param  {object} conn_opts - options forwarded to net.connect()
 * @returns {PluggableStream}
 */
function connect(conn_opts = {}) {
    const rawSocket = net.connect(conn_opts)
    const socket = new PluggableStream(rawSocket)

    socket.upgrade = (tls_opts = {}, upgrade_cb) => {
        log.debug('tls/socket: upgrading outbound connection to TLS')

        socket._detach()
        rawSocket.removeAllListeners('data')

        const cleartext = tls.connect({ ...tls_opts, socket: rawSocket })

        cleartext.on('error', (err) => {
            if (err.reason) log.error(`tls/socket: client TLS error: ${err}`)
            socket.emit('error', err)
        })

        cleartext.once('secureConnect', () => {
            log.debug('tls/socket: outbound TLS secured')
            socket._attach(cleartext)
            const cipher = cleartext.getCipher()
            if (cipher) cipher.version = cleartext.getProtocol()
            upgrade_cb?.(
                cleartext.authorized,
                cleartext.authorizationError,
                cleartext.getPeerCertificate(),
                cipher,
            )
        })

        socket.cleartext = cleartext
        if (socket._timeout) cleartext.setTimeout(socket._timeout)
        cleartext.setKeepAlive(socket._keepalive)
    }

    return socket
}

module.exports = {
    PluggableStream,
    createServer,
    connect,
    createConnection: connect, // alias for drop-in compat
}
