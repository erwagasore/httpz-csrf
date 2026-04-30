# httpz-csrf

CSRF protection middleware for [httpz](https://github.com/karlseguin/http.zig).

Stateless Signed Double-Submit Cookie pattern powered by HMAC-SHA256. No session storage required.

Targets Zig 0.16.x and the Zig 0.16-compatible httpz API.

## Quickstart

```bash
git clone git@github.com:erwagasore/httpz-csrf.git
cd httpz-csrf
zig build              # build library + example
zig build test         # run unit tests
zig build run          # run example server on :8080
```

### As a dependency

Add to `build.zig.zon`:

```zig
.httpz_csrf = .{
    .url = "git+https://github.com/erwagasore/httpz-csrf#main", // or a Zig 0.16-compatible release tag
    .hash = "...",
},
```

Add to `build.zig`:

```zig
const httpz_csrf = b.dependency("httpz_csrf", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("httpz_csrf", httpz_csrf.module("httpz_csrf"));
```

## Usage

```zig
const std = @import("std");
const httpz = @import("httpz");
const Csrf = @import("httpz_csrf");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var server = try httpz.Server(void).init(init.io, allocator, .{ .address = .localhost(8080) }, {});
    defer {
        server.stop();
        server.deinit();
    }

    const csrf = try server.middleware(Csrf, .{
        .secret = init.environ_map.get("CSRF_SECRET") orelse return error.MissingSecret,
        .io = init.io,
    });

    var router = try server.router(.{ .middlewares = &.{csrf} });
    router.get("/", handleIndex, .{});
    router.post("/submit", handleSubmit, .{});

    try server.listen();
}
```

## Configuration

```zig
const csrf = try server.middleware(Csrf, .{
    .secret = loadSecret(),
    .io = init.io,                  // Zig 0.16 I/O interface for secure entropy
    .cookie_name = "__Host-csrf",   // Cookie name (default)
    .header_name = "x-csrf-token",  // Response/request header name (default)
    .form_field = "_csrf",          // Form field fallback (default)
    .max_age = 7200,                // Cookie TTL in seconds (default: 2h)
    .secure = true,                 // Secure flag (default)
    .same_site = .lax,              // SameSite attribute (default)
    .reject_status = 403,           // Rejection status code (default)
    .allowed_origins = null,        // Optional Origin validation
});
```

## Client flow

The middleware requires a valid CSRF cookie **before** it will accept a state-changing request. On the first GET, the middleware sets the cookie and the configured CSRF response header (`x-csrf-token` by default). The client must include this token on subsequent POST/PUT/PATCH/DELETE requests — either via the configured request header or a `_csrf` form field.

A POST without a prior GET will always receive a 403. This is by design: the client has no cookie yet, so no token can match. The expected integration pattern is:

1. **GET** the page/form — middleware sets the cookie and response header.
2. **POST** with the token — middleware validates and passes through.

For SPAs using `fetch`, read the `X-CSRF-Token` response header and send it back on mutations. For HTML forms, render the token into a hidden `<input name="_csrf">` field.

## Design

See [DESIGN.md](DESIGN.md) for architecture and principles:

- Token format and request flow
- Cookie security attributes
- Threat model
- Design decisions and rejected alternatives

## Structure

See [AGENTS.md](AGENTS.md#repo-map) for the full repo map.

## License

MIT
