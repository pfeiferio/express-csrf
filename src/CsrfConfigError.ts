/**
 * Error type thrown for invalid CSRF middleware configuration.
 *
 * This error indicates a misconfiguration detected during
 * middleware initialization and should be treated as a
 * developer error (not a runtime request error).
 */
export class CsrfConfigError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CsrfConfigError'
  }
}
