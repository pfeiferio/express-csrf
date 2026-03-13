# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-03-13

### Fixed

- `guard.jsonOnly` now correctly rejects non-JSON requests even when no body parser is registered.
  Previously, `req.is()` returned `null` (not `false`) in the absence of a body parser, which caused
  the content-type check to be bypassed. The middleware now falls back to reading the raw
  `Content-Type` header directly when `req.is()` returns `null`.

## [1.2.0] - 2026-03-13

### Added

- `req.csrf.isValidToken(token: string): Promise<boolean>` — allows callers to manually validate a given CSRF token
  string. Intended for use alongside `skipValidation`, where the middleware skips automatic validation but the handler
  still wants to inspect token validity programmatically.

## [1.1.0] - 2026-03-13

### Added

- Injectable `cookieReader` option on `csrfSecretCookie` to support custom cookie parsing (e.g. signed cookies).
- Cleaned up public exports for a leaner API surface.
