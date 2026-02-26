# DESIGN — httpz-csrf

Architecture and principles for a CSRF protection middleware for [httpz](https://github.com/karlseguin/http.zig).

---

## 1. Problem

A browser that holds an authenticated session cookie will attach it to every request to that origin — including requests triggered by a malicious third-party page. The server cannot distinguish a legitimate user action from a forged one by looking at cookies alone. This is Cross-Site Request Forgery (CSRF).

**What we protect against**: An attacker's page causes the victim's browser to send a state-changing request (POST, PUT, DELETE, PATCH) to our server. The browser attaches the session cookie automatically. Without CSRF protection, the server executes the action as if the user intended it.

**What we do NOT protect against**: XSS (attacker runs JavaScript on the same origin — all CSRF defences are bypassed), API-to-API calls (no browser, no cookies), or GET requests (which must be side-effect-free by design).

**The constraint**: httpz has no built-in session storage. The solution must be stateless — no server-side token store, no allocator for per-request state, no shared state between instances. It must work behind load balancers without sticky sessions.

---

## 2. Approach

Signed Double-Submit Cookie — a stateless pattern where the token is self-verifying via HMAC-SHA256.

**Core idea**: A CSRF token is set as a cookie. State-changing requests must echo the same token back in a header (or form field). The server verifies the cookie value matches the submitted value and that the HMAC signature is valid.

### Why Signed Double-Submit?

| Pattern | Server State | Subdomain-Safe | Complexity |
|---------|-------------|----------------|------------|
| Synchronizer Token | ✗ needs session | ✓ | High |
| Double-Submit Cookie | ✓ stateless | ✗ vulnerable | Low |
| **Signed Double-Submit** | **✓ stateless** | **✓ HMAC-protected** | **Medium** |

The signed variant prevents subdomain cookie injection attacks because an attacker cannot forge a valid HMAC without knowing the server secret.

### Prior art

The older generation of CSRF middleware — Rails, Express `csurf` — relies on server-side sessions to store tokens. This requires shared state, sticky sessions or a session store, and breaks horizontal scaling.

The modern pattern is stateless double-submit with a signed cookie. No session infrastructure, no shared state, works behind any load balancer.

| Middleware | Ecosystem | Approach |
|-----------|-----------|----------|
| **Django CSRF** | Python | Stateless double-submit, salted HMAC + XOR mask |
| **gorilla/csrf** | Go | Cookie-stored token, HMAC + XOR mask |
| **csrf-csrf** | Node/Express | Signed double-submit, HMAC-SHA256 |
| **httpz-csrf** (ours) | Zig/httpz | Signed double-submit, HMAC-SHA256 |
| axum-csrf | Rust/Axum | Double-submit, AES-256 encryption (confidentiality we don't need) |
| Rails CSRF | Ruby | Synchronizer token, server session (stateful) |
| csurf | Node/Express | Synchronizer token, server session (stateful, deprecated) |

Django and gorilla/csrf add a per-response XOR mask over a stable secret to resist BREACH compression attacks. We achieve the same protection more simply — every token contains a fresh 32-byte random nonce, so there is no stable byte pattern to leak.

---

## 3. Principles

- **Stateless, no allocator.** The middleware holds only its `Config`. No per-request heap allocation. Token operations are stack-only.
- **One way to do a thing.** One token format. One verification path. Header check, then form-field fallback — a single ordered lookup, not two equivalent mechanisms.
- **Explicit parameters over implicit reads.** Functions receive what they need as arguments. No re-reading request headers when the value is already computed.
- **Stdlib crypto, no custom primitives.** HMAC-SHA256, base64url, constant-time comparison — all from `std`. No hand-rolled crypto.

---

## 4. Rejected Alternatives

These were considered and intentionally dropped. Don't re-propose without new evidence.

- **Synchronizer Token Pattern.** Requires server-side session storage. Breaks horizontal scaling, adds allocator dependency, needs expiry sweeps. Dropped.
- **Plain Double-Submit Cookie (unsigned).** Vulnerable to subdomain cookie injection — attacker sets their own cookie via a sibling subdomain. No integrity guarantee. Dropped.
- **AES-GCM encrypted tokens.** Confidentiality is unnecessary — only integrity matters. Adds complexity, key rotation burden, and nonce management. Dropped.
- **SHA-256 without key.** `SHA256(nonce)` is forgeable — attacker generates their own nonce and computes the hash. No authentication without a secret. Dropped.
- **Per-request token rotation.** Breaks browser back button and multi-tab usage. Dropped.
- **HttpOnly cookie.** Would prevent JavaScript from reading the token to submit in the `X-CSRF-Token` header. Breaks the core double-submit pattern. Dropped.
- **Custom constant-time comparison.** `std.crypto.timing_safe.eql` exists in the stdlib for fixed-size arrays. Tokens are always 87 bytes. No reason to hand-roll. Dropped.
- **Builder struct for token operations.** Wrapping config + token state in a builder hides allocation and adds a type. Idiomatic Zig passes data explicitly. Dropped.

---

## 5. Token Format

```
base64url(random_bytes) "." base64url(hmac_sha256(random_bytes, secret))
```

| Component | Size | Description |
|-----------|------|-------------|
| `random_bytes` | 32 bytes (43 base64url chars) | Cryptographically random nonce from `std.crypto.random` |
| `"."` | 1 byte | Delimiter separating nonce from signature |
| `hmac_signature` | 32 bytes (43 base64url chars) | HMAC-SHA256 of the raw random bytes keyed with the server secret |

**Total token length**: 87 characters (43 + 1 + 43).

Base64url encoding (RFC 4648 §5) is used — no `+`, `/`, or `=` characters. 33% shorter than hex. Cookie-safe and header-safe without escaping.

---

## 6. Request Flow

```
                   ┌─────────────────────────────┐
                   │  Every request               │
                   └──────────────┬──────────────┘
                                  │
                                  ▼
                   ┌─────────────────────────────┐
                   │  ensureToken()               │
                   │  Valid cookie? Reuse it.     │
                   │  Otherwise: generate new.    │
                   │  Set cookie + response hdr.  │
                   └──────────────┬──────────────┘
                                  │
                                  ▼
         ┌────────────────────────┴────────────────────────┐
         │                                                 │
    Safe method                                   State-changing method
    (GET/HEAD/OPTIONS)                            (POST/PUT/DELETE/PATCH)
         │                                                 │
         ▼                                                 ▼
    Pass through                              ┌───────────────────────┐
                                              │  Origin check (opt.)  │
                                              │  Extract cookie token │
                                              │  Extract header/form  │
                                              │  Compare (fixed-size  │
                                              │    timing_safe.eql)     │
                                              │  Verify HMAC sig      │
                                              └───────────┬───────────┘
                                                          │
                                              ┌───────────┴───────────┐
                                              │                       │
                                           Valid                   Invalid
                                              │                       │
                                              ▼                       ▼
                                       executor.next()            reject()
```

### Key structural decisions

- **Safe methods get tokens; unsafe methods only validate.** `extractValidCookieToken` checks the cookie; `provideToken` generates a fresh one if needed (safe methods only). Unsafe methods without a cookie are rejected immediately — no wasted allocation, no misleading `Set-Cookie` on a 403.
- **All comparisons use stdlib `timing_safe.eql`.** Tokens are always 87 bytes; HMAC digests are always 32 bytes. Fixed-size comparison, no hand-rolled loops.

---

## 7. Configuration Surface

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `secret` | `[]const u8` | **required** | HMAC key, ≥ 32 bytes. Validated at `init` — fail fast |
| `cookie_name` | `[]const u8` | `__Host-csrf` | `__Host-` prefix for maximum cookie security |
| `header_name` | `[]const u8` | `x-csrf-token` | Request header carrying the submitted token |
| `form_field` | `[]const u8` | `_csrf` | Form field fallback (empty string disables) |
| `max_age` | `u32` | `7200` | Cookie TTL in seconds |
| `cookie_path` | `[]const u8` | `/` | Cookie path attribute |
| `secure` | `bool` | `true` | Cookie Secure flag |
| `same_site` | `SameSite` | `.lax` | Cookie SameSite attribute |
| `safe_custom` | `?[]const Method` | `null` | Additional safe methods beyond GET/HEAD/OPTIONS |
| `allowed_origins` | `?[]const []const u8` | `null` | Defence-in-depth Origin/Referer validation |
| `reject_status` | `u16` | `403` | HTTP status on rejection |
| `reject_body` | `[]const u8` | `"Forbidden: …"` | Response body on rejection |

---

## 8. Cookie Security

| Attribute | Value | Rationale |
|-----------|-------|-----------|
| `__Host-` prefix | default | Binds cookie to exact host; requires `Secure`, no `Domain`, `Path=/` |
| `Secure` | `true` | Cookie only sent over HTTPS |
| `HttpOnly` | **not set** | JS must read the cookie to submit it as a header — required by the pattern |
| `SameSite` | `Lax` | Blocks cross-site sub-requests while allowing top-level navigation |
| `Max-Age` | `7200` | Short-lived; limits token theft exposure window |
| `Path` | `/` | Applies to all routes |

**Why no HttpOnly?** The double-submit pattern requires JavaScript to read the cookie value and attach it as a request header. `HttpOnly` would prevent this. Security is maintained by same-origin policy (attacker cannot read cross-origin cookies) and HMAC signature (attacker cannot forge tokens without the secret). If an attacker can inject JS on the same origin, that's XSS — CSRF protection is already bypassed at that point.

---

## 9. Middleware Ordering

| Position | Middleware | Why |
|----------|-----------|-----|
| 1st | CORS | Must handle preflight OPTIONS before anything else |
| 2nd | Logger | Captures all requests including CSRF rejections |
| 3rd | **CSRF** | Blocks forged requests before they reach auth/handlers |
| 4th+ | Auth, etc. | Only processes requests with valid CSRF tokens |

CSRF must run before auth and business logic — otherwise an attacker can trigger authenticated actions via cross-site requests.

---

## 10. Threat Model

| Threat | Mitigation |
|--------|-----------|
| Cross-site form submission | Token in header/form must match cookie; attacker cannot read cross-origin cookies |
| Subdomain cookie injection | HMAC signature — attacker cannot forge a valid token without the secret |
| Token theft via XSS | Out of scope — XSS breaks all CSRF defences; fix XSS separately |
| Timing attack on comparison | `std.crypto.timing_safe.eql` for both token matching (87 bytes) and HMAC verification (32 bytes) |
| BREACH compression attack | Random nonce per token — each token is unique, no compressible patterns |
| Cookie tossing (subdomain) | `__Host-` prefix forces `Secure`, no `Domain`, `Path=/` — immune to tossing |
| Replay of old tokens | Tokens are valid for `max_age` seconds; short TTL limits exposure window |
| Missing Origin header | Falls back to Referer; if both absent and origin validation is enabled, rejects |

---

## 11. Design Decisions

Rationale for choices not already covered by [Principles](#3-principles) and [Rejected Alternatives](#4-rejected-alternatives).

### Single-file implementation

Follows httpz-logger's approach. The middleware is small enough (~300 lines) that splitting into multiple files adds complexity without benefit.

### Base64url (not hex)

Hex would produce 129 characters (64 + 1 + 64). Base64url produces 87 (43 + 1 + 43) — 33% shorter, cookie-safe without escaping.

### Reject = short-circuit

On CSRF failure, the middleware writes a response and returns without calling `executor.next()`. No downstream middleware or handler runs. Logging middleware (if placed earlier) still captures the 403.

### Single `ensureToken` path

One function handles all token provisioning: validate existing cookie, generate if needed, set cookie, set response header. Called once at the top of `execute`, returns the current token. No overlap, no re-reading, no hidden side effects.

### Token in response header

The token is always included as an `X-CSRF-Token` response header. This allows any JavaScript client to read the current token from the response without parsing cookies. Headers are accessible from XHR/fetch responses and work identically for all response types.

---

## 12. File Structure

```
httpz-csrf/
├── src/
│   └── root.zig           # Single-file middleware implementation
├── examples/
│   └── basic_server.zig   # Runnable example with form + API routes
├── build.zig              # Build system — module, example, tests
├── build.zig.zon          # Package manifest (httpz dependency)
├── DESIGN.md              # This file
├── README.md              # Usage documentation
├── AGENTS.md              # Operating rules
├── CHANGELOG.md           # Release history
└── LICENSE                # MIT
```

### Dependencies

| Dependency | Purpose |
|------------|---------|
| [httpz](https://github.com/karlseguin/http.zig) | Middleware interface, request/response types, testing utilities |
| `std.crypto.auth.hmac.sha256` | HMAC-SHA256 for token signing |
| `std.crypto.random` | Cryptographic random bytes for nonce generation |
| `std.crypto.timing_safe` | `timing_safe.eql` for constant-time comparison |
| `std.base64` | Base64url encoding/decoding |

No external dependencies beyond httpz. All crypto is Zig stdlib.

---

## 13. Implementation Checklist

### Phase 1 — Scaffold

- [x] `build.zig.zon` — package manifest with httpz dependency
- [x] `build.zig` — module, example executable, test step
- [x] `src/root.zig` — empty struct with `Config`, `init` (validate secret ≥ 32 bytes), `deinit` (no-op)
- [x] Verify `zig build` compiles

### Phase 2 — Token

- [x] `generateToken` — 32 random bytes → HMAC-SHA256 → base64url nonce + "." + base64url signature → `[87]u8`
- [x] `verifyToken` — split on ".", decode both halves, recompute HMAC, compare with `timing_safe.eql`
- [x] `tokensEqual` — assert both are 87 bytes, compare with `timing_safe.eql`
- [x] Tests: round-trip generate→verify, tampered nonce rejected, tampered signature rejected, wrong secret rejected, truncated rejected, empty rejected, missing delimiter rejected

### Phase 3 — Cookie

- [x] `parseCookieValue` — linear scan of `Cookie` header for a named value
- [x] `setCookie` — write `Set-Cookie` header with name, value, Path, Max-Age, Secure, SameSite (no HttpOnly)
- [x] `extractCookieToken` — read `Cookie` header → `parseCookieValue`
- [x] Tests: single cookie, multiple cookies, missing cookie, empty header, whitespace handling

### Phase 4 — Middleware core

- [x] `ensureToken` — validate existing cookie or generate fresh; set `Set-Cookie` + `X-CSRF-Token` response header; return token
- [x] `isSafeMethod` — GET/HEAD/OPTIONS return true; check `safe_custom`
- [x] `extractSubmittedToken` — check `header_name`, fallback to `form_field` if non-empty
- [x] `reject` — set `reject_status` + `reject_body`, do not call `executor.next()`
- [x] `execute` — wire it all: `ensureToken` → safe-method check → origin validation → extract cookie → extract submitted → `tokensEqual` → `verifyToken` → `executor.next()`
- [x] Tests: GET sets cookie, GET preserves valid cookie, POST valid passes, POST missing cookie rejects, POST missing header rejects, POST mismatched rejects, PUT/DELETE/PATCH validated, OPTIONS passes

### Phase 5 — Origin validation

- [x] `validateOrigin` — check `Origin` header against `allowed_origins`, fallback to `Referer`
- [x] `originMatchesAllowed` — strip path from Referer, keep scheme+host+port
- [x] Tests: matching origin passes, non-matching rejects, origin with port, referer without path, invalid referer

### Phase 6 — Example

- [x] `examples/basic_server.zig` — httpz server with CSRF middleware, a GET route that renders a form with the token, a POST route that processes it

---

## 14. Future Considerations

Not planned for v1. Noted for potential future work.

- **Token rotation**: Per-request tokens. Tradeoff: breaks back button and multi-tab.
- **Per-path exclusions**: Skip CSRF for webhooks. Workaround: separate routers with different middleware chains.
- **Token binding to session**: Include session ID in HMAC input. Requires session middleware upstream.
- **Encrypted tokens**: AES-GCM if confidentiality becomes a requirement.
