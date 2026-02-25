# DESIGN — httpz-csrf

Detailed implementation design for a CSRF (Cross-Site Request Forgery) protection middleware for [httpz](https://github.com/karlseguin/http.zig), with first-class [HTMX](https://htmx.org) support.

---

## 1. Overview

httpz-csrf is a stateless CSRF middleware that uses the **Signed Double-Submit Cookie** pattern. It requires no server-side session storage — the token is self-verifying via HMAC-SHA256.

**Core idea**: A CSRF token is set as a cookie. State-changing requests must echo the same token back in a header (or form field). The server verifies the cookie value matches the submitted value and that the HMAC signature is valid.

**HTMX-aware**: The middleware detects HTMX requests via the `HX-Request` header and adapts its behaviour — returning swappable HTML error fragments on rejection, refreshing tokens in response headers that HTMX can read, and supporting all HTMX request patterns (`hx-post`, `hx-put`, `hx-delete`, `hx-patch`, `hx-boost`).

### Why Signed Double-Submit?

| Pattern | Server State | Subdomain-Safe | Complexity |
|---------|-------------|----------------|------------|
| Synchronizer Token | ✗ needs session | ✓ | High |
| Double-Submit Cookie | ✓ stateless | ✗ vulnerable | Low |
| **Signed Double-Submit** | **✓ stateless** | **✓ HMAC-protected** | **Medium** |

The signed variant prevents subdomain cookie injection attacks because an attacker cannot forge a valid HMAC without knowing the server secret.

---

## 2. Token Format

```
base64url(random_bytes) "." base64url(hmac_sha256(random_bytes, secret))
```

| Component | Size | Description |
|-----------|------|-------------|
| `random_bytes` | 32 bytes (43 base64url chars) | Cryptographically random nonce from `std.crypto.random` |
| `"."` | 1 byte | Delimiter separating nonce from signature |
| `hmac_signature` | 32 bytes (43 base64url chars) | HMAC-SHA256 of the raw random bytes keyed with the server secret |

**Total token length**: 87 characters (43 + 1 + 43).

Base64url encoding (RFC 4648 §5) is used — no `+`, `/`, or `=` characters — safe for cookies and headers without escaping.

### Token Lifecycle

```
                   ┌─────────────────────────────┐
                   │  First request (no cookie)   │
                   └──────────────┬──────────────┘
                                  │
                                  ▼
                   ┌─────────────────────────────┐
                   │  Generate random (32 bytes)  │
                   │  Compute HMAC-SHA256         │
                   │  Token = b64(rand).b64(hmac) │
                   └──────────────┬──────────────┘
                                  │
                                  ▼
                   ┌─────────────────────────────┐
                   │  Set-Cookie: __Host-csrf=... │
                   │  X-CSRF-Token response hdr   │
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
    (no validation)                           │  Extract cookie token │
                                              │  Extract header/form  │
                                              │  Compare + verify sig │
                                              └───────────┬───────────┘
                                                          │
                                              ┌───────────┴───────────┐
                                              │                       │
                                           Valid                   Invalid
                                              │                       │
                                              ▼                       ▼
                                         Pass through            403 Forbidden
```

---

## 3. Middleware Interface

Follows the standard httpz middleware contract.

### Struct Definition

```zig
// src/root.zig

const std = @import("std");
const httpz = @import("httpz");

const HmacSha256 = std.crypto.auth.hmac.sha256.HmacSha256;

/// CSRF protection middleware for httpz.
///
/// Uses Signed Double-Submit Cookie pattern with HMAC-SHA256.

config: Config,
```

### Config

```zig
pub const Config = struct {
    /// HMAC secret key. **Required** — must be at least 32 bytes.
    /// Typically loaded from an environment variable or secret manager.
    secret: []const u8,

    /// Cookie name for the CSRF token.
    /// Uses the `__Host-` prefix by default for maximum cookie security
    /// (__Host- cookies require Secure, no Domain, Path=/).
    cookie_name: []const u8 = "__Host-csrf",

    /// Name of the request header carrying the CSRF token.
    header_name: []const u8 = "x-csrf-token",

    /// Name of the form field carrying the CSRF token (checked as fallback
    /// when the header is absent). Useful for traditional HTML form submissions.
    form_field: []const u8 = "_csrf",

    /// Cookie max-age in seconds. Default: 2 hours.
    max_age: u32 = 7200,

    /// Cookie path attribute.
    cookie_path: []const u8 = "/",

    /// Set the Secure flag on the cookie.
    /// Should be `true` in production (HTTPS). Set to `false` only for
    /// local development over plain HTTP.
    secure: bool = true,

    /// SameSite attribute for the CSRF cookie.
    same_site: SameSite = .lax,

    /// Additional safe methods beyond GET, HEAD, OPTIONS.
    /// By default only those three are considered safe.
    /// TRACE is excluded because httpz does not route it.
    safe_custom: ?[]const httpz.Method = null,

    /// When set, validates the Origin header (or Referer) against this list
    /// of allowed origins. Provides defence-in-depth on top of token checking.
    /// Example: &.{ "https://example.com", "https://app.example.com" }
    allowed_origins: ?[]const []const u8 = null,

    /// Response status code on CSRF rejection.
    reject_status: u16 = 403,

    /// Response body on CSRF rejection (used for non-HTMX requests).
    reject_body: []const u8 = "Forbidden: CSRF token missing or invalid",

    /// Response body on CSRF rejection for HTMX requests.
    /// Must be a valid HTML fragment suitable for hx-swap.
    /// Set to `null` to use `reject_body` for all requests.
    reject_body_htmx: ?[]const u8 =
        \\<div id="csrf-error" class="error" role="alert">
        \\  Session expired. Please <a href="/">reload the page</a>.
        \\</div>
    ,

    /// When true, the middleware sets HX-Retarget and HX-Reswap headers on
    /// HTMX rejection responses so the error fragment replaces a predictable
    /// target rather than the element that triggered the request.
    htmx_retarget: ?[]const u8 = "body",

    /// HX-Reswap strategy used with htmx_retarget.
    htmx_reswap: []const u8 = "innerHTML",

    pub const SameSite = enum { strict, lax, none };
};
```

### init / deinit

```zig
pub fn init(config: Config, _: httpz.MiddlewareConfig) !@This() {
    if (config.secret.len < 32) return error.SecretTooShort;
    return .{ .config = config };
}

pub fn deinit(_: *@This()) void {}
```

`init` validates the secret length at startup — fail fast rather than silently accepting a weak key.

### execute

```zig
pub fn execute(
    self: *const @This(),
    req: *httpz.Request,
    res: *httpz.Response,
    executor: anytype,
) !void {
    const is_htmx = req.header("hx-request") != null;

    // 1. Safe-method check
    if (self.isSafeMethod(req.method)) {
        self.ensureCookie(req, res);
        // For HTMX: always include the token in a response header so
        // htmx:afterSettle / htmx:configRequest can pick up fresh tokens
        // without reading the cookie directly.
        if (is_htmx) self.setTokenResponseHeader(req, res);
        return executor.next();
    }

    // 2. Origin validation (defence-in-depth, if configured)
    if (self.config.allowed_origins) |origins| {
        if (!self.validateOrigin(req, origins)) {
            return self.reject(req, res);
        }
    }

    // 3. Extract token from cookie
    const cookie_token = self.extractCookieToken(req) orelse {
        return self.reject(req, res);
    };

    // 4. Extract token from header (fallback: form field)
    const submitted_token = self.extractSubmittedToken(req) orelse {
        return self.reject(req, res);
    };

    // 5. Compare tokens (constant-time)
    if (!constantTimeEqual(cookie_token, submitted_token)) {
        return self.reject(req, res);
    }

    // 6. Verify HMAC signature
    if (!self.verifyToken(cookie_token)) {
        return self.reject(req, res);
    }

    // Token is valid — proceed to next middleware / handler.
    // For HTMX responses: include the token header so swapped-in content
    // can immediately use it without a page reload.
    if (is_htmx) self.setTokenResponseHeader(req, res);
    return executor.next();
}
```

---

## 4. Core Functions

### Token Generation

```zig
fn generateToken(self: *const @This()) [87]u8 {
    var random_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    var hmac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&hmac, &random_bytes, self.config.secret);

    var token: [87]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(token[0..43], &random_bytes);
    token[43] = '.';
    _ = std.base64.url_safe_no_pad.Encoder.encode(token[44..87], &hmac);

    return token;
}
```

### Token Verification

```zig
fn verifyToken(self: *const @This(), token: []const u8) bool {
    if (token.len != 87) return false;
    if (token[43] != '.') return false;

    // Decode nonce
    const nonce = std.base64.url_safe_no_pad.Decoder.decode(
        &nonce_buf,
        token[0..43],
    ) catch return false;

    // Decode presented signature
    const presented_sig = std.base64.url_safe_no_pad.Decoder.decode(
        &sig_buf,
        token[44..87],
    ) catch return false;

    // Recompute expected HMAC
    var expected: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected, nonce, self.config.secret);

    // Constant-time comparison
    return std.crypto.utils.timingSafeEql(
        [HmacSha256.mac_length]u8,
        presented_sig.*,
        expected,
    );
}
```

### Cookie Extraction

```zig
fn extractCookieToken(self: *const @This(), req: *httpz.Request) ?[]const u8 {
    const cookie_header = req.header("cookie") orelse return null;
    // Parse cookie_header to find self.config.cookie_name value.
    // Uses a simple linear scan — CSRF cookies are typically the only
    // middleware-set cookie, so the header is short.
    return parseCookieValue(cookie_header, self.config.cookie_name);
}
```

### Submitted Token Extraction

```zig
fn extractSubmittedToken(self: *const @This(), req: *httpz.Request) ?[]const u8 {
    // Prefer header — works for:
    //   - SPA fetch() calls that set X-CSRF-Token explicitly
    //   - HTMX requests configured via hx-headers or htmx:configRequest
    if (req.header(self.config.header_name)) |token| return token;

    // Fallback: form field — works for:
    //   - Traditional HTML <form> POST submissions
    //   - HTMX hx-post on <form> elements (htmx includes form fields)
    //   - HTMX hx-include that pulls in a hidden _csrf input
    //   - HTMX hx-vals='{"_csrf": "..."}' (serialised into body)
    if (self.config.form_field.len > 0) {
        if (req.param(self.config.form_field)) |token| return token;
    }

    return null;
}
```

### Cookie Setting

```zig
fn ensureCookie(self: *const @This(), req: *httpz.Request, res: *httpz.Response) void {
    // If a valid cookie already exists, don't regenerate.
    if (self.extractCookieToken(req)) |existing| {
        if (self.verifyToken(existing)) return;
    }

    const token = self.generateToken();
    self.setCookie(res, &token);

    // Also set the token as a response header for SPA / HTMX clients
    // that read it via JavaScript to attach on subsequent requests.
    res.header("x-csrf-token", &token);
}
```

### Token Response Header (HTMX support)

```zig
/// Sets the CSRF token as a response header on HTMX responses.
///
/// HTMX swaps HTML fragments without full page reloads, so the client
/// needs a mechanism to obtain the current token for future requests.
/// By including it in every HTMX response header, a global
/// htmx:configRequest listener can always read the latest value.
fn setTokenResponseHeader(self: *const @This(), req: *httpz.Request, res: *httpz.Response) void {
    if (self.extractCookieToken(req)) |token| {
        if (self.verifyToken(token)) {
            res.header("x-csrf-token", token);
            return;
        }
    }
    // Cookie missing or invalid — generate a fresh token.
    const token = self.generateToken();
    self.setCookie(res, &token);
    res.header("x-csrf-token", &token);
}

fn setCookie(self: *const @This(), res: *httpz.Response, token: []const u8) void {
    // Build Set-Cookie header value
    // Format: name=value; Path=/; Max-Age=7200; HttpOnly; Secure; SameSite=Lax
    //
    // Note: HttpOnly is intentionally NOT set — JavaScript must be able to read
    // the cookie value to include it in the X-CSRF-Token header. This is safe
    // because the cookie value alone cannot be exploited for CSRF (the attacker
    // would need to read it, which requires same-origin JS access).
    res.setCookie(.{
        .name = self.config.cookie_name,
        .value = token,
        .path = self.config.cookie_path,
        .max_age = self.config.max_age,
        .secure = self.config.secure,
        .same_site = switch (self.config.same_site) {
            .strict => .strict,
            .lax => .lax,
            .none => .none,
        },
    });
}
```

### Origin Validation

```zig
fn validateOrigin(
    self: *const @This(),
    req: *httpz.Request,
    allowed: []const []const u8,
) bool {
    // Prefer Origin header (set by browsers on POST/PUT/DELETE)
    const origin = req.header("origin") orelse
        // Fallback to Referer (strip path, keep scheme+host+port)
        extractOriginFromReferer(req.header("referer") orelse return false);

    for (allowed) |a| {
        if (std.mem.eql(u8, origin, a)) return true;
    }
    return false;
}
```

### Rejection

```zig
fn reject(self: *const @This(), req: *httpz.Request, res: *httpz.Response) void {
    res.status = self.config.reject_status;

    const is_htmx = req.header("hx-request") != null;

    if (is_htmx) {
        // Return an HTML fragment that HTMX can swap into the page.
        if (self.config.reject_body_htmx) |htmx_body| {
            res.body = htmx_body;
            res.header("content-type", "text/html");
        } else {
            res.body = self.config.reject_body;
        }

        // HX-Retarget: override where the error fragment is swapped.
        // Without this, HTMX would swap into the element that triggered
        // the request (e.g., a button), which is usually wrong for errors.
        if (self.config.htmx_retarget) |target| {
            res.header("hx-retarget", target);
            res.header("hx-reswap", self.config.htmx_reswap);
        }
    } else {
        res.body = self.config.reject_body;
    }

    // Do NOT call executor.next() — short-circuit the chain.
}
```

### Safe Method Check

```zig
fn isSafeMethod(self: *const @This(), method: httpz.Method) bool {
    return switch (method) {
        .GET, .HEAD, .OPTIONS => true,
        else => blk: {
            if (self.config.safe_custom) |customs| {
                for (customs) |c| {
                    if (method == c) break :blk true;
                }
            }
            break :blk false;
        },
    };
}
```

### Cookie Parser

```zig
/// Parses a `Cookie` header value to find a specific cookie by name.
/// Returns the cookie value or null if not found.
///
/// Handles the format: `name1=value1; name2=value2; name3=value3`
pub fn parseCookieValue(header: []const u8, name: []const u8) ?[]const u8 {
    var remaining = header;
    while (remaining.len > 0) {
        // Skip leading whitespace
        remaining = std.mem.trimLeft(u8, remaining, " ");

        // Find the '=' delimiter
        const eq_pos = std.mem.indexOf(u8, remaining, "=") orelse return null;
        const cookie_name = std.mem.trimRight(u8, remaining[0..eq_pos], " ");

        remaining = remaining[eq_pos + 1 ..];

        // Find the end of the value (next ';' or end of string)
        const semi_pos = std.mem.indexOf(u8, remaining, ";") orelse remaining.len;
        const cookie_value = std.mem.trim(u8, remaining[0..semi_pos], " ");

        if (std.mem.eql(u8, cookie_name, name)) {
            return cookie_value;
        }

        // Move past the semicolon
        remaining = if (semi_pos < remaining.len) remaining[semi_pos + 1 ..] else "";
    }
    return null;
}
```

### Constant-Time Comparison

```zig
/// Constant-time string equality comparison.
/// Prevents timing side-channel attacks on token comparison.
fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var result: u8 = 0;
    for (a, b) |x, y| {
        result |= x ^ y;
    }
    return result == 0;
}
```

---

## 5. Constant-Time Security

All token comparisons use constant-time operations to prevent timing side-channels:

| Operation | Function | Why |
|-----------|----------|-----|
| Token match (cookie vs header) | `constantTimeEqual` | Prevents byte-by-byte timing leak |
| HMAC verification | `std.crypto.utils.timingSafeEql` | Prevents signature forgery via timing |

The HMAC recomputation itself is inherently constant-time (SHA-256 processes fixed-size blocks).

---

## 6. Cookie Security Attributes

| Attribute | Value | Rationale |
|-----------|-------|-----------|
| `__Host-` prefix | Required | Binds cookie to the exact host origin; `Secure` required, no `Domain`, `Path=/` |
| `Secure` | `true` (default) | Cookie only sent over HTTPS |
| `HttpOnly` | **not set** | JS must read the cookie to submit it in the header — this is by design |
| `SameSite` | `Lax` (default) | Prevents cookie from being sent on cross-site sub-requests (images, frames) while allowing top-level navigation |
| `Max-Age` | `7200` (2 hours) | Short-lived; limits window of token theft |
| `Path` | `/` | Applies to all routes |

### Why no HttpOnly?

The Signed Double-Submit pattern **requires** JavaScript to read the cookie value and attach it as a request header. `HttpOnly` would prevent this. Security is maintained because:

1. An attacker on a different origin **cannot read** the cookie (same-origin policy).
2. An attacker who can inject JS on the same origin already has full control — CSRF protection is irrelevant at that point (that's an XSS problem).
3. The HMAC signature prevents token forgery even if the cookie name is known.

---

## 7. File Structure

```
httpz-csrf/
├── src/
│   └── root.zig           # Middleware implementation (single file)
├── examples/
│   └── basic_server.zig   # Runnable example with form + API routes
├── build.zig              # Build system — module, example, tests
├── build.zig.zon          # Package manifest (httpz dependency)
├── DESIGN.md              # This file
├── README.md              # Usage documentation
├── AGENTS.md              # Operating rules for humans + AI
├── CHANGELOG.md           # Release history
└── LICENSE                # MIT
```

### Source Layout (`src/root.zig`)

The entire middleware lives in a single file, consistent with httpz-logger's approach.

```
src/root.zig
├── Config struct             — All configuration options with defaults (incl. HTMX options)
├── init / deinit             — Middleware lifecycle
├── execute                   — Main entry point; detects HTMX via HX-Request header
├── generateToken             — Creates signed CSRF token
├── verifyToken               — Validates token HMAC signature
├── extractCookieToken        — Parses Cookie header for CSRF token
├── extractSubmittedToken     — Reads token from header, form field, or hx-vals
├── ensureCookie              — Sets cookie on safe-method requests if missing
├── setCookie                 — Builds and writes Set-Cookie header
├── setTokenResponseHeader    — Adds X-CSRF-Token response header for HTMX clients
├── validateOrigin            — Optional Origin/Referer checking
├── isSafeMethod              — Determines if HTTP method is safe (read-only)
├── parseCookieValue          — Cookie header parser utility
├── constantTimeEqual         — Timing-safe byte comparison
├── reject                    — HTMX-aware rejection (HTML fragment + HX-Retarget)
└── tests                     — Unit, integration, and HTMX-specific tests
```

---

## 8. Build System

### `build.zig.zon`

```zig
.{
    .name = .httpz_csrf,
    .version = "0.0.0",
    .minimum_zig_version = "0.15.2",
    .dependencies = .{
        .httpz = .{
            .url = "git+https://github.com/karlseguin/http.zig#<commit>",
            .hash = "...",
        },
    },
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
        "LICENSE",
    },
}
```

### `build.zig`

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const httpz = b.dependency("httpz", .{ .target = target, .optimize = optimize });

    const mod = b.addModule("httpz_csrf", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "httpz", .module = httpz.module("httpz") },
        },
    });

    // Example
    const example = b.addExecutable(.{
        .name = "basic_server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/basic_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "httpz", .module = httpz.module("httpz") },
                .{ .name = "httpz_csrf", .module = mod },
            },
        }),
    });
    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    run_example.step.dependOn(b.getInstallStep());
    b.step("run", "Run the example server").dependOn(&run_example.step);

    // Tests
    const tests = b.addTest(.{ .root_module = mod });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);
}
```

---

## 9. Usage Examples

### API Client (SPA / fetch)

```zig
const Csrf = @import("httpz_csrf");

// In server setup:
const csrf = try server.middleware(Csrf, .{
    .secret = std.posix.getenv("CSRF_SECRET") orelse return error.MissingSecret,
});

var router = try server.router(.{ .middlewares = &.{csrf} });
router.get("/api/profile", getProfile, .{});
router.post("/api/profile", updateProfile, .{});
```

Client-side flow:

```
1. GET /api/profile
   → Response includes Set-Cookie: __Host-csrf=<token>
   → Response includes X-CSRF-Token: <token>

2. POST /api/profile
   → Request includes Cookie: __Host-csrf=<token>  (automatic)
   → Request includes X-CSRF-Token: <token>         (JS must set this)
   → Middleware validates token → passes to handler
```

### Traditional HTML Form

```html
<form method="POST" action="/submit">
  <input type="hidden" name="_csrf" value="{{ csrf_token }}">
  <button type="submit">Submit</button>
</form>
```

The server renders the token into the form. On submission, the middleware reads it from the `_csrf` form field.

### HTMX — Recommended Patterns

HTMX makes XHR requests from HTML attributes (`hx-post`, `hx-put`, `hx-delete`, `hx-patch`). These are state-changing requests that need CSRF tokens, but HTMX does **not** include them automatically. There are three strategies, ordered by preference:

#### Strategy A: Global `htmx:configRequest` listener (recommended)

A single `<script>` block on the base layout attaches the token to every HTMX request. The middleware returns the token in the `X-CSRF-Token` response header on every response, so the listener always has the latest value.

```html
<!-- base layout: set once, works everywhere -->
<meta name="csrf-token" content="{{ csrf_token }}">

<script>
  // Read the initial token from the meta tag.
  // On every HTMX request, attach it as a header.
  document.addEventListener('htmx:configRequest', (event) => {
    event.detail.headers['x-csrf-token'] =
      document.querySelector('meta[name="csrf-token"]').content;
  });

  // After every HTMX response, update the cached token from the
  // response header (in case the server rotated it).
  document.addEventListener('htmx:afterRequest', (event) => {
    const newToken = event.detail.xhr.getResponseHeader('x-csrf-token');
    if (newToken) {
      document.querySelector('meta[name="csrf-token"]').content = newToken;
    }
  });
</script>
```

```html
<!-- any element — no per-element CSRF config needed -->
<button hx-post="/items" hx-target="#list">Add Item</button>
<button hx-delete="/items/42" hx-target="#list">Delete</button>
```

**Why this works**: `htmx:configRequest` fires before every HTMX XHR. The header is attached transparently. The `htmx:afterRequest` listener keeps the token fresh across fragment swaps without page reloads.

#### Strategy B: `hx-headers` on `<body>` (no JavaScript)

If you prefer zero custom JavaScript, HTMX's `hx-headers` attribute is inherited by all child elements:

```html
<body hx-headers='{"x-csrf-token": "{{ csrf_token }}"}'>
  <!-- All hx-post/put/delete/patch inside <body> inherit the header -->
  <button hx-post="/items" hx-target="#list">Add Item</button>
</body>
```

**Limitation**: The token is baked into the HTML at render time. If the page stays open longer than `max_age`, the token expires and requests will fail. Strategy A's `htmx:afterRequest` refresh solves this; Strategy B does not. For short-lived pages or when `max_age` is generous (e.g. 24h), this is acceptable.

#### Strategy C: Hidden form field (forms only)

For `hx-post` on `<form>` elements, HTMX automatically serialises form fields into the request body. A hidden `_csrf` field works identically to a traditional form:

```html
<form hx-post="/contacts" hx-target="#contact-list" hx-swap="outerHTML">
  <input type="hidden" name="_csrf" value="{{ csrf_token }}">
  <input name="email" type="email" placeholder="Email">
  <button type="submit">Add Contact</button>
</form>
```

**When to use**: Only works for `<form>` elements. Does not work for `hx-post` on `<button>`, `<div>`, `<tr>`, or other non-form elements (HTMX does not serialise child inputs for those). Also works with `hx-include` to pull the hidden field from elsewhere in the DOM:

```html
<!-- Token stored once, referenced by any element -->
<input type="hidden" id="csrf" name="_csrf" value="{{ csrf_token }}">

<button hx-post="/action" hx-include="#csrf" hx-target="#result">
  Do Action
</button>
```

### HTMX + `hx-boost`

`hx-boost="true"` converts regular `<a>` and `<form>` elements into AJAX requests. For boosted forms:

- **GET forms**: No CSRF validation needed (safe method).
- **POST forms**: HTMX serialises form fields including the hidden `_csrf` input, so Strategy C works. Alternatively, Strategy A's `htmx:configRequest` listener attaches the header automatically.

```html
<body hx-boost="true">
  <!-- This form is "boosted" — submitted via AJAX, not full page nav -->
  <form method="POST" action="/settings">
    <input type="hidden" name="_csrf" value="{{ csrf_token }}">
    <input name="theme" value="dark">
    <button type="submit">Save</button>
  </form>
</body>
```

The middleware does not need to distinguish boosted from non-boosted requests — both arrive as standard HTTP requests with the `HX-Request: true` header.

---

## 10. Middleware Ordering

```zig
const cors   = try server.middleware(httpz.middleware.Cors, .{ .origin = "*" });
const logger = try server.middleware(HttpLogger, .{});
const csrf   = try server.middleware(Csrf, .{ .secret = secret });
const auth   = try server.middleware(Auth, .{});

var router = try server.router(.{ .middlewares = &.{ cors, logger, csrf, auth } });
```

| Position | Middleware | Why |
|----------|-----------|-----|
| 1st | CORS | Must handle preflight OPTIONS before anything else |
| 2nd | Logger | Captures all requests including CSRF rejections |
| 3rd | **CSRF** | Blocks forged requests before they reach auth/handlers |
| 4th+ | Auth, etc. | Only processes requests with valid CSRF tokens |

CSRF **must** run before auth and business logic — otherwise an attacker can trigger authenticated actions via cross-site requests.

---

## 11. HTMX Integration Design

### Why HTMX Needs Special Attention

HTMX replaces full page loads with partial HTML fragment swaps via XHR. This creates three CSRF-specific challenges that traditional form-based or SPA-based patterns don't face:

| Challenge | Root Cause | Solution |
|-----------|-----------|----------|
| **Token delivery** | No full page reload to inject a fresh `<meta>` tag or hidden field | Middleware returns `X-CSRF-Token` response header on every HTMX response |
| **Token attachment** | HTMX attributes (`hx-post`, etc.) don't have a built-in CSRF mechanism | Global `htmx:configRequest` listener reads token and attaches header |
| **Error presentation** | Plain-text 403 body breaks the HTMX swap model | Middleware returns an HTML fragment with `HX-Retarget` / `HX-Reswap` headers |

### Request Flow (HTMX)

```
   Browser (HTMX)                      httpz + CSRF middleware
   ──────────────                      ──────────────────────
         │                                      │
         │  GET /page                           │
         │  HX-Request: true                    │
         │ ────────────────────────────────────► │
         │                                      │ ensureCookie() → Set-Cookie
         │                                      │ setTokenResponseHeader()
         │  ◄──────────────────────────────────  │
         │  200 OK                              │
         │  Set-Cookie: __Host-csrf=<token>     │
         │  X-CSRF-Token: <token>               │
         │  <html fragment>                     │
         │                                      │
         │  htmx:configRequest fires            │
         │  → reads meta tag or last known      │
         │    token from htmx:afterRequest      │
         │                                      │
         │  POST /items                         │
         │  HX-Request: true                    │
         │  Cookie: __Host-csrf=<token>         │
         │  X-CSRF-Token: <token>               │
         │ ────────────────────────────────────► │
         │                                      │ extractCookieToken()  ✓
         │                                      │ extractSubmittedToken() ✓
         │                                      │ constantTimeEqual()    ✓
         │                                      │ verifyToken()          ✓
         │                                      │ setTokenResponseHeader()
         │                                      │ executor.next()
         │  ◄──────────────────────────────────  │
         │  200 OK                              │
         │  X-CSRF-Token: <token>               │
         │  <html fragment>                     │
         │                                      │
         │  htmx:afterRequest fires             │
         │  → updates cached token              │
```

### Request Flow (HTMX — Rejection)

```
   Browser (HTMX)                      httpz + CSRF middleware
   ──────────────                      ──────────────────────
         │                                      │
         │  DELETE /items/42                    │
         │  HX-Request: true                    │
         │  Cookie: __Host-csrf=<token>         │
         │  (no X-CSRF-Token header!)           │
         │ ────────────────────────────────────► │
         │                                      │ extractSubmittedToken() → null
         │                                      │ reject()
         │  ◄──────────────────────────────────  │
         │  403 Forbidden                       │
         │  Content-Type: text/html             │
         │  HX-Retarget: body                   │
         │  HX-Reswap: innerHTML                │
         │  <div class="error">Session          │
         │   expired…</div>                     │
         │                                      │
         │  HTMX receives 403                   │
         │  → reads HX-Retarget: body           │
         │  → swaps error fragment into <body>  │
```

### HX-Retarget / HX-Reswap Behaviour

When HTMX receives a response with `HX-Retarget`, it overrides the `hx-target` that the triggering element specified. This is critical for CSRF errors:

- **Without retarget**: HTMX swaps the 403 error HTML into whatever element triggered the request (e.g., a `<button>` or `<tr>`), destroying that element's content.
- **With retarget**: The error is swapped into a predictable container (`body`, `#notifications`, etc.), keeping the page intact.

The `HX-Reswap` header controls the swap strategy (`innerHTML`, `outerHTML`, `beforeend`, etc.).

### Why `X-CSRF-Token` in Every HTMX Response

HTMX pages can stay open for hours. During that time:

1. The CSRF cookie may expire (`max_age`).
2. The server may rotate secrets (deployment).
3. Another tab may have generated a different token.

By including `X-CSRF-Token` in every HTMX response header (both safe and state-changing), the `htmx:afterRequest` listener always has the freshest token. This makes the system self-healing — the client automatically picks up new tokens without requiring a full page reload.

### HTMX Attributes Compatibility Matrix

| HTMX Pattern | Token Delivery | Works? | Notes |
|-------------|---------------|--------|-------|
| `hx-get` | N/A | ✓ | Safe method — no validation |
| `hx-post` on `<form>` | Hidden `_csrf` field | ✓ | HTMX serialises form fields |
| `hx-post` on `<button>` | `hx-headers` or `htmx:configRequest` | ✓ | Non-form elements need header-based approach |
| `hx-put` on any element | `htmx:configRequest` | ✓ | Header approach works universally |
| `hx-delete` on any element | `htmx:configRequest` | ✓ | Header approach works universally |
| `hx-patch` on any element | `htmx:configRequest` | ✓ | Header approach works universally |
| `hx-boost` on `<form method="POST">` | Hidden `_csrf` field | ✓ | Boosted forms serialize fields normally |
| `hx-boost` on `<a>` | N/A | ✓ | Links are GET — safe method |
| `hx-post` + `hx-include="#csrf"` | Included hidden field | ✓ | Pulls token from elsewhere in DOM |
| `hx-post` + `hx-vals='{"_csrf":"..."}'` | Inline value | ✓ | Serialised into request body |
| `hx-post` + `hx-headers='{"x-csrf-token":"..."}'` | Per-element header | ✓ | Works but verbose; prefer global approach |

### Server-Side Token Rendering for HTMX

The httpz handler that renders the initial page (or any HTML fragment containing forms) needs to inject the current CSRF token. The middleware makes this easy by always setting the `X-CSRF-Token` response header, but the handler can also read the cookie:

```zig
fn renderPage(req: *httpz.Request, res: *httpz.Response) !void {
    // The CSRF middleware already set the cookie and response header.
    // Read the token from the response header to embed in HTML.
    const token = res.header("x-csrf-token") orelse
        // Or extract from the cookie that was just set.
        parseCookieValue(req.header("cookie") orelse "", "__Host-csrf") orelse
        "";

    // Render HTML with the token in a <meta> tag.
    try res.writer().print(
        \\<html>
        \\<head><meta name="csrf-token" content="{s}"></head>
        \\<body hx-boost="true">
        \\  <form hx-post="/submit">
        \\    <input type="hidden" name="_csrf" value="{s}">
        \\    <button type="submit">Submit</button>
        \\  </form>
        \\</body></html>
    , .{ token, token });
}
```

---

## 12. Test Plan

### Unit Tests

| Test | Description |
|------|-------------|
| `generateToken: produces 87-char token` | Verify format: 43 chars + "." + 43 chars |
| `generateToken: unique on each call` | Two calls produce different tokens |
| `verifyToken: valid token passes` | Round-trip generate → verify |
| `verifyToken: rejects tampered nonce` | Flip a bit in the nonce portion |
| `verifyToken: rejects tampered signature` | Flip a bit in the HMAC portion |
| `verifyToken: rejects wrong secret` | Verify with different secret fails |
| `verifyToken: rejects truncated token` | Short token returns false |
| `verifyToken: rejects empty string` | Empty input returns false |
| `verifyToken: rejects missing delimiter` | No "." in token returns false |
| `parseCookieValue: single cookie` | `"name=value"` → `"value"` |
| `parseCookieValue: multiple cookies` | `"a=1; b=2; c=3"` → finds correct one |
| `parseCookieValue: missing cookie` | Returns null |
| `parseCookieValue: empty header` | Returns null |
| `parseCookieValue: whitespace handling` | `" name = value "` → trimmed |
| `constantTimeEqual: equal strings` | Returns true |
| `constantTimeEqual: unequal strings` | Returns false |
| `constantTimeEqual: different lengths` | Returns false |
| `isSafeMethod: GET/HEAD/OPTIONS` | Returns true |
| `isSafeMethod: POST/PUT/DELETE/PATCH` | Returns false |
| `isSafeMethod: custom safe methods` | Configured custom methods return true |
| `validateOrigin: matching origin` | Returns true |
| `validateOrigin: non-matching origin` | Returns false |
| `validateOrigin: referer fallback` | Uses referer when origin header missing |
| `init: rejects short secret` | Secret < 32 bytes → error.SecretTooShort |

### Middleware Integration Tests

| Test | Description |
|------|-------------|
| `GET sets CSRF cookie when none exists` | Response has Set-Cookie header with valid token |
| `GET preserves existing valid cookie` | No new Set-Cookie if cookie already valid |
| `GET regenerates cookie if signature invalid` | Tampered cookie gets replaced |
| `POST with valid token passes` | Cookie + header match → executor.next() called |
| `POST with missing cookie rejects` | No cookie → 403 |
| `POST with missing header rejects` | Cookie present, no header → 403 |
| `POST with mismatched tokens rejects` | Cookie ≠ header → 403 |
| `POST with tampered cookie rejects` | Invalid HMAC in cookie → 403 |
| `POST with form field fallback passes` | Token in _csrf field accepted |
| `PUT/DELETE/PATCH require token` | All state-changing methods validated |
| `OPTIONS passes without token` | Preflight requests are safe |
| `custom reject status` | Config .reject_status = 419 → response is 419 |
| `origin validation blocks wrong origin` | Origin header mismatch → 403 |
| `origin validation allows correct origin` | Origin matches allowed list → passes |
| `secure=false allows __Host- prefix removal` | For local dev without HTTPS |

### HTMX Integration Tests

| Test | Description |
|------|-------------|
| `HTMX GET includes X-CSRF-Token response header` | HX-Request: true GET → response has x-csrf-token header |
| `HTMX POST with x-csrf-token header passes` | Token in header (Strategy A) → executor.next() called |
| `HTMX POST with _csrf form field passes` | Token in form body (Strategy C) → executor.next() called |
| `HTMX POST rejection returns HTML fragment` | HX-Request: true + invalid token → HTML body, not plain text |
| `HTMX POST rejection sets HX-Retarget` | Response includes HX-Retarget: body header |
| `HTMX POST rejection sets HX-Reswap` | Response includes HX-Reswap: innerHTML header |
| `HTMX POST rejection sets content-type text/html` | Content-Type is text/html for HTMX errors |
| `HTMX reject_body_htmx=null uses plain reject_body` | Config null → falls back to non-HTMX body |
| `HTMX htmx_retarget=null omits HX-Retarget` | Config null → no retarget headers |
| `HTMX valid POST includes token in response header` | Successful HTMX POST → x-csrf-token in response for refresh |
| `non-HTMX POST rejection returns plain body` | No HX-Request header → plain text error body |
| `hx-boost POST with form field passes` | Boosted form with _csrf field works (HX-Request present) |
| `HTMX DELETE with header token passes` | hx-delete with x-csrf-token header works |
| `HTMX PATCH with header token passes` | hx-patch with x-csrf-token header works |

### Testing Helpers

Tests use the same pattern as httpz-logger — `httpz.testing.Testing` for request/response mocking:

```zig
const NoopExecutor = struct {
    called: bool = false,
    pub fn next(self: *NoopExecutor) !void {
        self.called = true;
    }
};
```

This lets tests assert whether the downstream handler was actually invoked.

HTMX-specific test setup helper:

```zig
/// Configures a test request to simulate an HTMX request.
fn makeHtmx(ht: *httpz.testing.Testing) void {
    ht.header("hx-request", "true");
}
```

---

## 13. Threat Model

| Threat | Mitigation |
|--------|-----------|
| Cross-site form submission | Token in header/form must match cookie; attacker cannot read cross-origin cookies |
| Cross-site HTMX trigger | HTMX XHRs are still subject to same-origin policy; attacker cannot read the cookie or response headers cross-origin to forge the `x-csrf-token` header |
| Subdomain cookie injection | HMAC signature — attacker cannot forge a valid token without the secret |
| Token theft via XSS | Out of scope — XSS breaks all CSRF defences; fix XSS separately |
| Timing attack on comparison | Constant-time comparison for both token matching and HMAC verification |
| BREACH compression attack | Random nonce per token — each token is unique, no compressible patterns |
| Cookie tossing (subdomain) | `__Host-` prefix forces `Secure`, no `Domain`, `Path=/` — immune to tossing |
| Replay of old tokens | Tokens are valid for `max_age` seconds; short TTL limits exposure window |
| Missing Origin header | Falls back to Referer; if both absent and origin validation is enabled, rejects |
| Fake HX-Request header | An attacker can send `HX-Request: true` to get the HTML error fragment instead of plain text — this is harmless; the rejection still fires and no handler runs. The header only affects the error response format, not the security decision |
| HTMX token staleness (long-lived pages) | `htmx:afterRequest` listener refreshes the token from the `X-CSRF-Token` response header after every response; Strategy A is recommended for this reason |
| HTMX hx-boost form without _csrf field | Boosted forms serialize fields like regular forms — if the hidden `_csrf` input is missing, the request is rejected. Strategy A (global header) avoids per-form token management entirely |

---

## 14. Configuration Recipes

### Production (HTTPS, strict)

```zig
try server.middleware(Csrf, .{
    .secret = loadSecret(),
    .secure = true,
    .same_site = .strict,
    .max_age = 3600,
    .allowed_origins = &.{"https://example.com"},
});
```

### Local Development (HTTP, relaxed)

```zig
try server.middleware(Csrf, .{
    .secret = "dev-secret-at-least-32-bytes-long!!",
    .cookie_name = "csrf",       // __Host- requires Secure
    .secure = false,
    .same_site = .lax,
});
```

When `secure = false`, the cookie name should drop the `__Host-` prefix since browsers require `Secure` for that prefix.

### HTMX Application (recommended)

```zig
try server.middleware(Csrf, .{
    .secret = loadSecret(),
    .secure = true,
    .same_site = .lax,
    .max_age = 86400,                // 24 hours — HTMX pages stay open long
    .htmx_retarget = "#notifications", // Swap error into a notification area
    .htmx_reswap = "innerHTML",
    .reject_body_htmx =
        \\<div class="toast toast-error" role="alert">
        \\  Your session has expired. <a href="/" hx-boost="false">Reload</a>
        \\</div>
    ,
});
```

### HTMX + Local Development

```zig
try server.middleware(Csrf, .{
    .secret = "dev-secret-at-least-32-bytes-long!!",
    .cookie_name = "csrf",         // __Host- requires Secure
    .secure = false,
    .same_site = .lax,
    .htmx_retarget = "body",
});
```

### API-Only (no form fields, no HTMX)

```zig
try server.middleware(Csrf, .{
    .secret = loadSecret(),
    .form_field = "",              // Disable form field checking
    .reject_body_htmx = null,     // No HTML fragment responses
    .htmx_retarget = null,        // No HX-Retarget headers
});
```

---

## 15. Dependencies

| Dependency | Purpose |
|------------|---------|
| [httpz](https://github.com/karlseguin/http.zig) | HTTP server framework — provides middleware interface, request/response types, testing utilities |
| `std.crypto.auth.hmac.sha256` | HMAC-SHA256 for token signing (Zig stdlib, no external dep) |
| `std.crypto.random` | Cryptographic random bytes for nonce generation (Zig stdlib) |
| `std.base64` | Base64url encoding/decoding (Zig stdlib) |

No external dependencies beyond httpz itself. All cryptographic operations use the Zig standard library.

---

## 16. Design Decisions & Rationale

### Single-file implementation

Follows httpz-logger's approach. The middleware is small enough (~300 lines) that splitting into multiple files adds complexity without benefit.

### No session storage

The Signed Double-Submit Cookie pattern is fully stateless. This means:
- No allocator needed for token storage
- No cleanup or expiry sweeps
- Scales horizontally with no shared state
- Works behind load balancers without sticky sessions

### HMAC-SHA256 (not AES, not plain hash)

- **Not plain hash**: SHA256(nonce) without a key is forgeable — attacker generates their own nonce + hash.
- **Not AES**: Encryption is unnecessary — we don't need confidentiality, only integrity.
- **HMAC-SHA256**: Purpose-built for message authentication. Zig stdlib provides it. 32-byte output fits well in cookies.

### Base64url (not hex)

- Hex encoding would produce 64 + 1 + 64 = 129 characters.
- Base64url produces 43 + 1 + 43 = 87 characters — 33% shorter.
- Base64url is cookie-safe without escaping (no `+`, `/`, `=`).

### Reject = short-circuit (no executor.next())

On CSRF failure, the middleware writes a 403 and returns **without** calling `executor.next()`. This ensures:
- No downstream middleware or handler runs on forged requests
- The response is immediate and deterministic
- Logging middleware (if placed earlier) still captures the 403

### HTMX detection via HX-Request header (not User-Agent sniffing)

HTMX sends `HX-Request: true` on every request it makes. This is the official, documented way to detect HTMX requests server-side. The middleware uses this header to:
- Choose between HTML fragment and plain-text error responses
- Set `HX-Retarget` / `HX-Reswap` headers for proper error placement
- Include `X-CSRF-Token` in response headers for token refresh

This is a **response format** decision, not a **security** decision. The same validation logic runs regardless of whether `HX-Request` is present. An attacker who fakes the header simply gets an HTML error instead of a plain-text one — the request is still rejected.

### Token in response header (not response body)

For HTMX, the token is delivered via the `X-CSRF-Token` response header rather than embedded in the response body. This is because:
- HTMX response bodies are HTML fragments swapped into the DOM — the middleware cannot inject into arbitrary HTML
- Response headers are accessible via `htmx:afterRequest` event's `event.detail.xhr.getResponseHeader()`
- Headers work identically for all response types (full pages, fragments, empty 204s)
- The handler retains full control over response body content

---

## 17. Future Considerations

These are **not** planned for v1 but noted for potential future work:

- **Token rotation**: Generate a new token on each state-changing request (per-request tokens). Tradeoff: breaks browser back-button, multi-tab usage, and HTMX's parallel request model (multiple in-flight `hx-post`s would race on tokens).
- **Per-path exclusions**: Allow specific paths (e.g., webhooks) to skip CSRF validation. Workaround: use separate routers with different middleware chains.
- **Token binding to session**: Include a session ID in the HMAC input to bind tokens to specific sessions. Requires session middleware upstream.
- **Encrypted tokens**: Use AES-GCM instead of HMAC if token confidentiality becomes a requirement.
- **HTMX extension**: Publish a companion `htmx-csrf.js` extension that auto-configures `htmx:configRequest` and `htmx:afterRequest` listeners, reducing client-side boilerplate to `<script src="htmx-csrf.js"></script>`.
- **HX-Trigger response header**: On CSRF rejection, emit `HX-Trigger: csrf-error` so HTMX apps can listen for a custom event (`htmx:csrf-error`) and show a toast/modal via their own UI framework instead of relying on `HX-Retarget` swaps.
- **Automatic `<meta>` injection**: If the response content-type is `text/html` and contains a `<head>` tag, the middleware could auto-inject `<meta name="csrf-token" content="...">`. This would eliminate manual token rendering in handlers but adds complexity and content-sniffing risks.
