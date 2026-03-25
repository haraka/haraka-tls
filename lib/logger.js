'use strict'

// Minimal console-based logger shim for standalone use.
// When haraka-tls is used inside Haraka, Haraka replaces this with its own
// logger by calling logger.set_logger(haraka_logger) before any other import.

const LEVELS = ['debug', 'info', 'notice', 'warn', 'error', 'crit', 'alert', 'emerg']

let _log = {
  debug: (msg) => console.debug(msg),
  info: (msg) => console.info(msg),
  notice: (msg) => console.info(msg),
  warn: (msg) => console.warn(msg),
  error: (msg) => console.error(msg),
}

const log = {
  debug: (msg) => _log.debug(msg),
  info: (msg) => _log.info(msg),
  notice: (msg) => _log.notice(msg),
  warn: (msg) => _log.warn(msg),
  error: (msg) => _log.error(msg),

  /** Replace the backing logger (e.g. with Haraka's logger). */
  set_logger(impl) {
    _log = impl
  },

  /**
   * Add log methods (logdebug, loginfo, lognotice, logwarn, logerror, …)
   * to an object instance — mirroring Haraka's logger.add_log_methods(obj).
   */
  add_log_methods(obj) {
    if (!obj) return
    for (const level of LEVELS) {
      const fn = `log${level}`
      if (Object.hasOwn(obj, fn)) continue
      obj[fn] = (msg) => (_log[level] ? _log[level](msg) : _log.info(msg))
    }
  },
}

module.exports = log
