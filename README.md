# haraka-tls

Modern TLS support for [Haraka](https://haraka.github.io).

## Features

- **No `openssl` subprocess** — certificate parsing uses Node's built-in
  `crypto.X509Certificate`
- **No global state** — every API returns plain objects; callers own them
- **STARTTLS upgrades** — `PluggableStream` wraps a raw TCP socket and upgrades it to TLS in-place without changing the reference held by the connection handler
- **SNI** — `ContextStore` manages per-hostname `SecureContext` objects and generates a ready-to-use SNI callback
- **Hot reload** — `ContextStore.invalidate()` clears all contexts; call `build()` again to pick up new certificates
- **Outbound TLS-NO-GO** — optional Redis cache that skips TLS for hosts that have previously failed negotiation

## Installation

```sh
npm install haraka-tls
```

`haraka-plugin-redis` is an optional peer dependency, required only when the
`[redis] disable_for_failed_hosts` feature is enabled.

## Quick start

```js
const {
  load_config,
  load_dir,
  ContextStore,
  createServer,
  connect,
  OutboundTLS,
} = require('haraka-tls')

const config = require('haraka-config').module_config('/path/to/haraka/config')

// Load tls.ini
const tls_cfg = load_config(config)

// Load per-hostname certs from config/tls/
const certs = await load_dir(config, 'tls')

// Build TLS contexts
const contexts = new ContextStore()
contexts.build(tls_cfg.main, certs)

// Inbound server
const server = createServer({ contexts, cfg: tls_cfg.main }, (socket) => {
  // socket is a PluggableStream
  socket.on('data', (chunk) => { /* ... */ })

  // Upgrade to TLS when the client sends STARTTLS
  socket.upgrade((verified, verifyErr, peerCert, cipher) => {
    console.log('TLS established, cipher:', cipher.name)
  })
})
server.listen(25)

// Outbound connection
const ob = new OutboundTLS(config)
ob.load(tls_cfg)

const mx = { exchange: 'mail.example.com' }
const socket = connect({ host: mx.exchange, port: 25 })
socket.on('connect', () => {
  // After the remote server sends 250 STARTTLS:
  socket.upgrade(ob.get_tls_options(mx), (verified, verifyErr, peerCert, cipher) => {
    console.log('Outbound TLS established')
  })
})
```

## API

### `load_config(cfg_module)` → `object`

Reads `tls.ini` via the given `haraka-config` module and returns a normalised
config object. Each call returns a fresh plain object — safe to mutate.

```js
const { load_config } = require('haraka-tls')
const tls_cfg = load_config(config)
// tls_cfg.main, tls_cfg.outbound, tls_cfg.redis, tls_cfg.no_tls_hosts, …
```

### `parse_pem(pem)` → `object`

Parses a PEM string and extracts private key(s), the certificate chain,
hostnames (CN + SANs), and the leaf certificate's expiry date.

```js
const { parse_pem } = require('haraka-tls')
const { keys, chain, names, expire } = parse_pem(fs.readFileSync('cert.pem', 'utf8'))
```

### `load_dir(cfg_module, dir_name)` → `Promise<Map>`

Scans a config directory for `.pem` files, pairs keys with certificates by
hostname, and returns a `Map<string, { key: Buffer, cert: Buffer, file: string }>`.

```js
const { load_dir } = require('haraka-tls')
const certs = await load_dir(config, 'tls')  // reads config/tls/*.pem
```

### `ContextStore`

Manages a set of `tls.SecureContext` objects keyed by hostname. The special key
`'*'` is the fallback used by SNI when no hostname-specific context exists.

```js
const { ContextStore } = require('haraka-tls')

const store = new ContextStore()
store.build(base_opts, certs)        // builds '*' + per-hostname contexts
store.get('mail.example.com')        // returns context, falls back to '*'
store.sni_callback()                 // returns (servername, cb) => void
store.invalidate()                   // clears all contexts (force reload)
```

### `build_context(opts)` → `tls.SecureContext`

Thin wrapper around `tls.createSecureContext(opts)`. Throws on invalid material
so callers can handle errors explicitly.

### `createServer(tls_state, connection_handler)` → `net.Server`

Creates a `net.Server` whose connections are wrapped in `PluggableStream`. Each
socket gains an `.upgrade(cb)` method for inbound STARTTLS.

```js
const { createServer } = require('haraka-tls')

const server = createServer({ contexts, cfg: tls_cfg.main }, (socket) => {
  socket.upgrade((verified, verifyErr, peerCert, cipher) => { /* … */ })
})
```

### `connect(conn_opts)` → `PluggableStream`

Creates a plain TCP socket wrapped in `PluggableStream`. The returned socket has
an `.upgrade(tls_opts, cb)` method for outbound STARTTLS. Also exported as
`createConnection` for drop-in compatibility.

```js
const { connect } = require('haraka-tls')

const socket = connect({ host: 'mail.example.com', port: 25 })
socket.on('connect', () => {
  socket.upgrade(tls_opts, (verified, verifyErr, peerCert, cipher) => { /* … */ })
})
```

### `PluggableStream`

An `EventEmitter` that wraps a `net.Socket` or `tls.TLSSocket` and supports
transparent STARTTLS upgrade. The reference held by the caller does not change
when the underlying socket is swapped.

Forwarded events: `data`, `connect`, `secureConnect`, `secure`, `end`, `close`,
`drain`, `error`, `timeout`.

```js
socket.isEncrypted()   // → boolean
socket.isSecure()      // → boolean (encrypted + authorized)
socket.write(data)
socket.end()
socket.destroy()
socket.setTimeout(ms)
socket.setKeepAlive(bool)
```

### `OutboundTLS`

Manages outbound TLS configuration and an optional Redis cache that disables TLS
for hosts that have previously failed negotiation.

```js
const { OutboundTLS } = require('haraka-tls')

const ob = new OutboundTLS(config)
ob.load(tls_cfg)              // inherit from [main], resolve file paths to Buffers
await ob.init(cb)             // connect to Redis if disable_for_failed_hosts=true

const opts = ob.get_tls_options({ exchange: 'mail.example.com' })
// opts.servername is set to the hostname (never a bare IP)

ob.check_tls_nogo(host, cb_ok, cb_nogo)
ob.mark_tls_nogo(host, cb)
```

## Configuration

`tls.ini` sections understood by this package:

```ini
; [main] — inbound TLS defaults
key             = tls_key.pem
cert            = tls_cert.pem
dhparam         = dhparams.pem
ciphers         = ECDHE-RSA-AES256-GCM-SHA384:…
minVersion      = TLSv1.2
rejectUnauthorized = false
requestCert     = true
honorCipherOrder = true
requireAuthorized[] = 465
requireAuthorized[] = 587

; [outbound] — overrides for outbound connections
; Any key absent here falls back to [main]
key             = outbound_key.pem
cert            = outbound_cert.pem
rejectUnauthorized = false
force_tls_hosts[] = smtp.example.com
no_tls_hosts[]  = broken.example.net

; [redis] — TLS-NO-GO cache (optional)
disable_for_failed_hosts = true
disable_expiry  = 604800   ; seconds (default: 7 days)

; [no_tls_hosts] — disable TLS for inbound connections from these hosts/CIDRs
192.168.1.0/24
```

## Per-hostname certificates

Place PEM files in `config/tls/`. Each file may contain a private key and one or
more certificates. The CN and SAN DNS entries are used as the hostname key:

```
config/
  tls/
    mail.example.com.pem   ← CN=mail.example.com
    smtp.example.com.pem   ← CN=smtp.example.com
    _.example.net.key      ← key for wildcard (paired with example.net.crt)
    example.net.crt
```

Filenames starting with `_` have the leading underscore replaced with `*` to
work around Windows filesystem restrictions on wildcard filenames.

## Integrating with Haraka's logger

By default this package logs to `console`. To use Haraka's logger instead, call
`set_logger()` before any other import:

```js
const tls_logger = require('haraka-tls/lib/logger')
tls_logger.set_logger(require('./logger'))  // Haraka's logger

const haraka_tls = require('haraka-tls')
```

The logger object passed to `set_logger` must implement `debug`, `info`,
`notice`, `warn`, and `error` methods that each accept a message string.

## License

MIT
