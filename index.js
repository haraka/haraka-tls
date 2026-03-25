'use strict'

// haraka-tls: Modern TLS support for Haraka.
//
// Sub-modules are intentionally independent so callers can require only what
// they need without pulling in the entire stack.

const { load: load_config } = require('./lib/config')
const { parse_pem, load_dir } = require('./lib/certs')
const { ContextStore, build_context } = require('./lib/context')
const { PluggableStream, createServer, connect, createConnection } = require('./lib/socket')
const { OutboundTLS } = require('./lib/outbound')

module.exports = {
    // Config
    load_config,

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
}
