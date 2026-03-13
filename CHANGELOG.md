# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-03-13

### Added

- `req.csrf.isValidToken(token: string): Promise<boolean>` — allows callers to manually validate a given CSRF token
  string. Intended for use alongside `skipValidation`, where the middleware skips automatic validation but the handler
  still wants to inspect token validity programmatically.

## [1.1.0] - 2026-03-13

### Added

- Injectable `cookieReader` option on `csrfSecretCookie` to support custom cookie parsing (e.g. signed cookies).
- Cleaned up public exports for a leaner API surface.
