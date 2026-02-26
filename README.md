# httpz-csrf

CSRF protection middleware for [httpz](https://github.com/karlseguin/http.zig).

Stateless Signed Double-Submit Cookie pattern powered by HMAC-SHA256. No session storage required.

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
    .url = "git+https://github.com/erwagasore/httpz-csrf#main",
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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var server = try httpz.Server(void).init(allocator, .{ .port = 8080 }, {});
    defer server.deinit();
    defer server.stop();

    const csrf = try server.middleware(Csrf, .{
        .secret = std.posix.getenv("CSRF_SECRET") orelse return error.MissingSecret,
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
    .cookie_name = "__Host-csrf",   // Cookie name (default)
    .header_name = "x-csrf-token",  // Request header name (default)
    .form_field = "_csrf",          // Form field fallback (default)
    .max_age = 7200,                // Cookie TTL in seconds (default: 2h)
    .secure = true,                 // Secure flag (default)
    .same_site = .lax,              // SameSite attribute (default)
    .reject_status = 403,           // Rejection status code (default)
    .allowed_origins = null,        // Optional Origin validation
});
```

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
