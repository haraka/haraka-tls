# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

- feat: TLS certificate hot reload (fixes haraka/Haraka#3533).
  - new top-level `watch` helper — listens to haraka-config's `watchCb` on
    both `tls.ini` and the cert directory
  - `config.load(cfg_module, { watchCb })` — watch on tls.ini
  - `certs.load_dir(cfg_module, dir, { watchCb })` — watch on cert directory
  - `ContextStore#rebuild(base_opts, certs)` — `invalidate()` + `build()` in one call
- feat(config): `merge_plugin_tls(cfg_module, main_cfg, plugin_cfg)` — merge a
  plugin's `[tls]` section over `tls.ini` `[main]`; ports
- feat(outbound): `OutboundTLS#apply_mutual_tls(host, tls_opts)` + `set_certs()`
  — port of the mutual-TLS lookup in `Haraka/tls_socket.js#connect`
- feat(socket): `connect()` accepts an optional `apply_mutual_tls` callback
  that's invoked inside `upgrade()` so client certs are mixed in transparently
- feat(dhparams): new `ensure_dhparams(cfg_module, opts, cb)` helper that
  generates `dhparams.pem` via `openssl dhparam` when missing
  (cluster-master-only); ports `Haraka/tls_socket.js#ensureDhparams`
- feat(ocsp): new `add_ocsp(server)` + `ocsp_shutdown()` — OCSP stapling for
  inbound TLS servers, with lazy `require('@haraka/ocsp')`; ports
  `Haraka/tls_socket.js#addOCSP/shutdown`
- deps: `@haraka/ocsp` declared as `optionalDependencies` (loaded lazily by
  `add_ocsp` only when invoked)

### [1.0.2] - 2026-03-31

- ci: update configs

### [1.0.1] - 2026-03-31

- test release

#### Other

- Initial commit

[1.0.0]: https://github.com/haraka/haraka-tls/releases/tag/v1.0.0
[1.0.1]: https://github.com/haraka/haraka-tls/releases/tag/v1.0.1
[1.0.2]: https://github.com/haraka/haraka-tls/releases/tag/v1.0.2
