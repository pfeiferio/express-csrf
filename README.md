# @pfeiferio/express-csrf

> Short-lived, single-use CSRF tokens for Express — bound to browser context, built for multi-instance deployments.
> A modern, dependency-free alternative to the deprecated [csurf](https://www.npmjs.com/package/csurf) package.

[![npm version](https://img.shields.io/npm/v/%40pfeiferio%2Fexpress-csrf.svg)](https://www.npmjs.com/package/@pfeiferio/express-csrf)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)
[![codecov](https://codecov.io/gh/pfeiferio/express-csrf/branch/main/graph/badge.svg)](https://codecov.io/gh/pfeiferio/express-csrf)

This package provides Express middleware for CSRF protection using short-lived, one-time tokens that are
cryptographically bound to the requesting browser. Tokens are flow-bound rather than session-bound, support parallel
validity, and are designed to work correctly in multi-instance deployments via an optional external store adapter.

---

## Features

- ✅ Time-limited CSRF tokens with configurable TTL
- ✅ Single-use tokens with replay protection
- ✅ Browser-bound signatures (IP prefix + User-Agent)
- ✅ Optional Origin header validation
- ✅ Optional JSON-only enforcement
- ✅ In-memory token registry with automatic cleanup
- ✅ External store adapter interface for Redis and multi-instance setups
- ✅ Graceful shutdown via `AbortSignal`
- ✅ Granular validation failure reasons for custom error handling
- ✅ Full TypeScript support
- ✅ No dependencies

---

## Security Model

- Tokens are HMAC-signed using a server-side secret.
- Each token embeds:
    - random nonce
    - expiration timestamp
    - browser signature (IP prefix + User-Agent)
- Tokens are bound to HTTP method and route scope.
- Tokens are single-use and replay-protected.

---

## Installation

```bash
npm install @pfeiferio/express-csrf
```

---

## Basic Usage

```ts
import express from 'express'
import cookieParser from 'cookie-parser'
import {csrfMiddleware} from '@pfeiferio/express-csrf'

const app = express()

app.use(cookieParser())
app.use(express.json())
app.use(csrfMiddleware({
  csrfSecretCookie: {
    name: '__csrf'
  }
}))

// CSRF token is available on GET requests
app.get('/form', (req, res) => {
  res.json({csrfToken: res.locals.csrfToken})
  // or: req.csrf.generateToken()
})

app.post('/submit', (req, res) => {
  res.json({ok: true})
})
```

The middleware automatically:

- Sets an HttpOnly CSRF secret cookie on the first request
- Generates a token on GET requests via `res.locals.csrfToken`
- Validates the token on state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`)

---

## Token Transmission

Send the token in one of the following request headers:

```
X-CSRF-Token: <token>
X-XSRF-Token: <token>
```

Or in the request body as `_csrf`.

> **Note:** Reading `_csrf` from the request body requires a body parser (e.g. `express.json()`) to be registered before
> the CSRF middleware.

---

## Multi-Instance Deployments

By default, the used-token registry is in-memory and process-local. In a multi-instance setup (PM2 cluster, Kubernetes),
a token validated on instance A could be replayed on instance B.

To prevent this, provide an external store adapter:

```ts
import {csrfMiddleware} from '@pfeiferio/express-csrf'
import type {CsrfStoreAdapter} from '@pfeiferio/express-csrf'
import {createClient} from 'redis'

const redis = createClient()
await redis.connect()

const redisStore: CsrfStoreAdapter = {
  has: async (key) => (await redis.exists(key)) === 1,
  set: async (key, ttlMs) => {
    await redis.set(key, '1', {PX: ttlMs})
  }
}

app.use(csrfMiddleware({
  csrfSecretCookie: {name: '__csrf'},
  internals: {store: redisStore}
}))
```

The store is responsible for its own TTL management — the middleware passes `ttlMs` to `set()`. An in-memory local cache
runs in parallel to reduce store lookups for already-consumed tokens.

---

## Custom Error Handling

```ts
app.use(csrfMiddleware({
  csrfSecretCookie: {name: '__csrf'},
  guard: {
    onTokenRejected: (req, res, next, result) => {
      console.warn('CSRF rejected:', result.reason)
      res.status(403).json({error: result.reason})
    }
  }
}))
```

Possible `reason` values: `missing_secret`, `origin_mismatch`, `invalid_content_type`, `missing_token`,
`invalid_structure`, `expired`, `browser_signature_mismatch`, `invalid_signature`, `token_already_used`, `unknown`.

---

## Excluding Routes

```ts
app.use(csrfMiddleware({
  csrfSecretCookie: {name: '__csrf'},
  guard: {
    // Skip all CSRF logic for static assets and Vite dev server
    exclude: (req) => req.path.includes('.') || req.path.startsWith('/@'),

    // Skip validation only for webhooks
    skipValidation: (req) => req.path.startsWith('/webhooks/'),
  }
}))
```

`exclude` skips both token creation and validation. `skipValidation` and `skipTokenCreation` allow finer control.

---

## Graceful Shutdown

> The internal cleanup timer is automatically stopped when the signal is aborted.

```ts
const controller = new AbortController()

app.use(csrfMiddleware({
  csrfSecretCookie: {name: '__csrf'},
  internals: {signal: controller.signal}
}))

process.on('SIGTERM', () => controller.abort())
```

---

## `req.csrf`

The middleware attaches a `csrf` object to every request:

```ts
req.csrf.hasSecret()              // boolean — whether a CSRF secret cookie exists
req.csrf.generateToken()          // string | false — generate a new token on demand
req.csrf.isExcluded()             // boolean
req.csrf.isTokenCreationSkipped() // boolean
req.csrf.isValidationSkipped()    // boolean
```

---

## Configuration Reference

```ts
csrfMiddleware({
  csrfToken: {
    ttl: 5 * 60 * 1000,               // Token lifetime in ms (default: 5 minutes)
    lookup: (req) => ...,              // Custom token extractor
    scopeResolver: (req) => ...,       // Custom scope binding (default: METHOD:path)
  },
  csrfSecretCookie: {
    name: '__csrf',                    // Cookie name (default: '__csrf')
    path: '/',
    ttl: 7 * 24 * 60 * 60 * 1000,    // Cookie lifetime in ms (default: 7 days)
    domain: undefined,
    secure: true,
    sameSite: 'strict',               // 'strict' | 'lax' | 'none'
  },
  guard: {
    jsonOnly: true,                   // Require application/json Content-Type
    origin: false,                    // Expected Origin header value, or false to disable
    onTokenRejected: ...,             // Custom rejection handler
    exclude: (req) => boolean,
    skipTokenCreation: (req) => boolean,
    skipValidation: (req) => boolean,
  },
  internals: {
    store: CsrfStoreAdapter,          // External store for multi-instance deployments
    cleanupProcess: (ctx, opts) => {
    },// Custom cleanup handler
    signal: AbortSignal,              // For graceful shutdown
    debug: (msg, ctx) => {
    },          // Debug logger
  }
})
```

---

## Design Goals

- **Flow-bound tokens** — tokens are scoped to a specific HTTP method and route, preventing reuse across endpoints
- **Parallel validity** — multiple tokens can be valid simultaneously, supporting SPAs with concurrent requests
- **No session dependency** — works without a session store
- **Multi-instance ready** — external store adapter keeps replay protection consistent across instances
- **Explicit over implicit** — no magic, no monkey-patching, predictable behavior

---

## License

MIT
