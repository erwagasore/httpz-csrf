//! CSRF protection middleware for httpz.
//!
//! Stateless Signed Double-Submit Cookie pattern with HMAC-SHA256.
//! See DESIGN.md for architecture and principles.

const std = @import("std");
const httpz = @import("httpz");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Configuration for the CSRF middleware.
pub const Config = struct {
    /// HMAC secret key. Must be at least 32 bytes.
    secret: []const u8,

    /// Cookie name for the CSRF token.
    cookie_name: []const u8 = "__Host-csrf",

    /// Request header carrying the submitted token.
    header_name: []const u8 = "x-csrf-token",

    /// Form field fallback. Empty string disables.
    form_field: []const u8 = "_csrf",

    /// Cookie max-age in seconds.
    max_age: u32 = 7200,

    /// Cookie path attribute.
    cookie_path: []const u8 = "/",

    /// Cookie Secure flag.
    secure: bool = true,

    /// Cookie SameSite attribute.
    same_site: SameSite = .lax,

    /// Additional safe methods beyond GET, HEAD, OPTIONS.
    safe_custom: ?[]const httpz.Method = null,

    /// Allowed origins for Origin/Referer validation. Null disables.
    allowed_origins: ?[]const []const u8 = null,

    /// HTTP status on rejection.
    reject_status: u16 = 403,

    /// Response body on rejection.
    reject_body: []const u8 = "Forbidden: CSRF token missing or invalid",

    pub const SameSite = enum { strict, lax, none };
};

config: Config,

/// Initialise the middleware. Validates the secret length.
pub fn init(config: Config, _: httpz.MiddlewareConfig) !@This() {
    if (config.secret.len < 32) return error.SecretTooShort;
    return .{ .config = config };
}

pub fn deinit(_: *@This()) void {}

/// Middleware execution — called by httpz for each request.
pub fn execute(self: *const @This(), req: *httpz.Request, res: *httpz.Response, executor: anytype) !void {
    // 1. Ensure a valid token exists (cookie + response header).
    const token = try self.ensureToken(req, res);

    // 2. Safe methods — nothing to validate.
    if (self.isSafeMethod(req.method)) return executor.next();

    // 3. Origin validation (defence-in-depth, if configured).
    if (self.config.allowed_origins) |origins| {
        if (!self.validateOrigin(req, origins)) return self.reject(res);
    }

    // 4. Token must exist in cookie.
    const cookie_token = token orelse return self.reject(res);

    // 5. Extract submitted token from header (fallback: form field).
    const submitted_token = self.extractSubmittedToken(req) orelse return self.reject(res);

    // 6. Compare tokens (constant-time, fixed-size).
    if (!tokensEqual(cookie_token, submitted_token)) return self.reject(res);

    // 7. Verify HMAC signature.
    if (!self.verifyToken(cookie_token)) return self.reject(res);

    return executor.next();
}

// ============================================================================
// Middleware helpers
// ============================================================================

/// Ensure a valid token exists. One function, one path:
///   1. Valid cookie exists → reuse it, set response header, return slice.
///   2. Otherwise → generate new token, set cookie + response header, return null.
///
/// Returns null when a fresh token was issued — callers cannot match against it
/// because the client never saw it. This avoids returning a pointer to stack memory.
fn ensureToken(self: *const @This(), req: *httpz.Request, res: *httpz.Response) !?[]const u8 {
    if (self.extractCookieToken(req)) |existing| {
        if (self.verifyToken(existing)) {
            // existing points into the request's header buffer — stable for this request.
            res.header("x-csrf-token", existing);
            return existing;
        }
    }
    // Stack-local token — must dupe into the response arena before passing to headers.
    const token = self.generateToken();
    const duped = try res.arena.dupe(u8, &token);
    self.setCookie(res, duped);
    res.header("x-csrf-token", duped);
    return null;
}

fn isSafeMethod(self: *const @This(), method: httpz.Method) bool {
    return switch (method) {
        .GET, .HEAD, .OPTIONS => true,
        else => {
            if (self.config.safe_custom) |customs| {
                for (customs) |c| {
                    if (method == c) return true;
                }
            }
            return false;
        },
    };
}

fn extractSubmittedToken(self: *const @This(), req: *httpz.Request) ?[]const u8 {
    if (req.header(self.config.header_name)) |token| return token;
    if (self.config.form_field.len > 0) {
        if (req.param(self.config.form_field)) |token| return token;
    }
    return null;
}

fn reject(self: *const @This(), res: *httpz.Response) void {
    res.status = self.config.reject_status;
    res.body = self.config.reject_body;
}

fn validateOrigin(self: *const @This(), req: *httpz.Request, allowed: []const []const u8) bool {
    _ = self;
    const origin = req.header("origin") orelse {
        const referer = req.header("referer") orelse return false;
        return originMatchesAllowed(referer, allowed);
    };
    for (allowed) |a| {
        if (std.mem.eql(u8, origin, a)) return true;
    }
    return false;
}

/// Extract origin (scheme+host+port) from a Referer URL and match against allowed list.
fn originMatchesAllowed(referer: []const u8, allowed: []const []const u8) bool {
    // Find the end of the origin: after "scheme://host" and optional ":port"
    const scheme_end = std.mem.indexOf(u8, referer, "://") orelse return false;
    const after_scheme = referer[scheme_end + 3 ..];
    // Origin ends at the first "/" after the host, or end of string.
    const path_start = std.mem.indexOf(u8, after_scheme, "/") orelse after_scheme.len;
    const origin = referer[0 .. scheme_end + 3 + path_start];

    for (allowed) |a| {
        if (std.mem.eql(u8, origin, a)) return true;
    }
    return false;
}

// ============================================================================
// Token operations
// ============================================================================

const token_len = 87; // 43 (nonce) + 1 (".") + 43 (signature)
const nonce_len = 32;
const encoded_nonce_len = 43;
const encoded_sig_len = 43;

/// Generate a signed CSRF token: base64url(random) "." base64url(hmac).
fn generateToken(self: *const @This()) [token_len]u8 {
    var random_bytes: [nonce_len]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    var sig: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&sig, &random_bytes, self.config.secret);

    var token: [token_len]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(token[0..encoded_nonce_len], &random_bytes);
    token[encoded_nonce_len] = '.';
    _ = std.base64.url_safe_no_pad.Encoder.encode(token[encoded_nonce_len + 1 ..], &sig);

    return token;
}

/// Verify a token's HMAC signature.
fn verifyToken(self: *const @This(), token: []const u8) bool {
    if (token.len != token_len) return false;
    if (token[encoded_nonce_len] != '.') return false;

    var nonce: [nonce_len]u8 = undefined;
    std.base64.url_safe_no_pad.Decoder.decode(&nonce, token[0..encoded_nonce_len]) catch return false;

    var presented: [HmacSha256.mac_length]u8 = undefined;
    std.base64.url_safe_no_pad.Decoder.decode(&presented, token[encoded_nonce_len + 1 ..]) catch return false;

    var expected: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected, &nonce, self.config.secret);

    return std.crypto.timing_safe.eql([HmacSha256.mac_length]u8, presented, expected);
}

/// Constant-time comparison for two tokens. Both must be 87 bytes.
fn tokensEqual(a: []const u8, b: []const u8) bool {
    if (a.len != token_len or b.len != token_len) return false;
    return std.crypto.timing_safe.eql([token_len]u8, a[0..token_len].*, b[0..token_len].*);
}

// ============================================================================
// Cookie operations
// ============================================================================

/// Parse a `Cookie` header to find a named value.
/// Format: `name1=value1; name2=value2; name3=value3`
pub fn parseCookieValue(header: []const u8, name: []const u8) ?[]const u8 {
    var remaining = header;
    while (remaining.len > 0) {
        remaining = std.mem.trimLeft(u8, remaining, " ");

        const eq_pos = std.mem.indexOf(u8, remaining, "=") orelse return null;
        const cookie_name = std.mem.trimRight(u8, remaining[0..eq_pos], " ");

        remaining = remaining[eq_pos + 1 ..];

        const semi_pos = std.mem.indexOf(u8, remaining, ";") orelse remaining.len;
        const cookie_value = std.mem.trim(u8, remaining[0..semi_pos], " ");

        if (std.mem.eql(u8, cookie_name, name)) {
            return cookie_value;
        }

        remaining = if (semi_pos < remaining.len) remaining[semi_pos + 1 ..] else "";
    }
    return null;
}

/// Extract the CSRF token from the Cookie header.
fn extractCookieToken(self: *const @This(), req: *httpz.Request) ?[]const u8 {
    const cookie_header = req.header("cookie") orelse return null;
    return parseCookieValue(cookie_header, self.config.cookie_name);
}

/// Write a Set-Cookie header for the CSRF token.
fn setCookie(self: *const @This(), res: *httpz.Response, token: []const u8) void {
    const value = std.fmt.allocPrint(res.arena, "{s}={s}; Path={s}; Max-Age={d}; SameSite={s}{s}", .{
        self.config.cookie_name,
        token,
        self.config.cookie_path,
        self.config.max_age,
        switch (self.config.same_site) {
            .strict => "Strict",
            .lax => "Lax",
            .none => "None",
        },
        if (self.config.secure) "; Secure" else "",
    }) catch return;
    res.header("set-cookie", value);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

const test_secret = "test-secret-key-that-is-at-least-32-bytes!!";

fn testInstance() @This() {
    return .{ .config = .{ .secret = test_secret } };
}

// -- generateToken -----------------------------------------------------------

test "generateToken: produces 87-char token with delimiter" {
    const mw = testInstance();
    const token = mw.generateToken();
    try testing.expectEqual(@as(usize, token_len), token.len);
    try testing.expectEqual(@as(u8, '.'), token[encoded_nonce_len]);
}

test "generateToken: unique on each call" {
    const mw = testInstance();
    const a = mw.generateToken();
    const b = mw.generateToken();
    try testing.expect(!std.mem.eql(u8, &a, &b));
}

// -- verifyToken -------------------------------------------------------------

test "verifyToken: valid token passes" {
    const mw = testInstance();
    const token = mw.generateToken();
    try testing.expect(mw.verifyToken(&token));
}

test "verifyToken: rejects tampered nonce" {
    const mw = testInstance();
    var token = mw.generateToken();
    token[0] ^= 0xFF;
    try testing.expect(!mw.verifyToken(&token));
}

test "verifyToken: rejects tampered signature" {
    const mw = testInstance();
    var token = mw.generateToken();
    token[token_len - 1] ^= 0xFF;
    try testing.expect(!mw.verifyToken(&token));
}

test "verifyToken: rejects wrong secret" {
    const mw = testInstance();
    const token = mw.generateToken();

    const other: @This() = .{ .config = .{ .secret = "different-secret-also-at-least-32-bytes!" } };
    try testing.expect(!other.verifyToken(&token));
}

test "verifyToken: rejects truncated token" {
    const mw = testInstance();
    const token = mw.generateToken();
    try testing.expect(!mw.verifyToken(token[0..50]));
}

test "verifyToken: rejects empty string" {
    const mw = testInstance();
    try testing.expect(!mw.verifyToken(""));
}

test "verifyToken: rejects missing delimiter" {
    const mw = testInstance();
    var token = mw.generateToken();
    token[encoded_nonce_len] = 'X';
    try testing.expect(!mw.verifyToken(&token));
}

// -- tokensEqual -------------------------------------------------------------

test "tokensEqual: equal 87-byte tokens" {
    const mw = testInstance();
    const token = mw.generateToken();
    try testing.expect(tokensEqual(&token, &token));
}

test "tokensEqual: unequal 87-byte tokens" {
    const mw = testInstance();
    const a = mw.generateToken();
    const b = mw.generateToken();
    try testing.expect(!tokensEqual(&a, &b));
}

test "tokensEqual: wrong length returns false" {
    try testing.expect(!tokensEqual("short", "short"));
    try testing.expect(!tokensEqual("", ""));
}

// -- parseCookieValue --------------------------------------------------------

test "parseCookieValue: single cookie" {
    try testing.expectEqualStrings("bar", parseCookieValue("foo=bar", "foo").?);
}

test "parseCookieValue: multiple cookies" {
    const header = "a=1; b=2; c=3";
    try testing.expectEqualStrings("1", parseCookieValue(header, "a").?);
    try testing.expectEqualStrings("2", parseCookieValue(header, "b").?);
    try testing.expectEqualStrings("3", parseCookieValue(header, "c").?);
}

test "parseCookieValue: missing cookie" {
    try testing.expect(parseCookieValue("a=1; b=2", "z") == null);
}

test "parseCookieValue: empty header" {
    try testing.expect(parseCookieValue("", "foo") == null);
}

test "parseCookieValue: whitespace handling" {
    try testing.expectEqualStrings("val", parseCookieValue("  name = val ; other = x", "name").?);
}

// -- Middleware integration --------------------------------------------------

fn initHt() httpz.testing.Testing {
    return httpz.testing.init(.{});
}

const NoopExecutor = struct {
    called: bool = false,
    pub fn next(self: *NoopExecutor) !void {
        self.called = true;
    }
};

test "middleware: GET sets CSRF cookie when none exists" {
    var ht = initHt();
    defer ht.deinit();
    ht.url("/");

    const mw = testInstance();
    var exec = NoopExecutor{};
    try mw.execute(ht.req, ht.res, &exec);

    try testing.expect(exec.called);
    // Should have set-cookie and x-csrf-token headers.
    try testing.expect(ht.res.headers.get("set-cookie") != null);
    try testing.expect(ht.res.headers.get("x-csrf-token") != null);
}

test "middleware: GET preserves existing valid cookie" {
    const mw = testInstance();
    const token = mw.generateToken();

    var ht = initHt();
    defer ht.deinit();
    ht.url("/");
    ht.header("cookie", "__Host-csrf=" ++ &token);

    var exec = NoopExecutor{};
    try mw.execute(ht.req, ht.res, &exec);

    try testing.expect(exec.called);
    // Should NOT set a new cookie (token is valid).
    try testing.expect(ht.res.headers.get("set-cookie") == null);
    // Should still set the response header.
    try testing.expect(ht.res.headers.get("x-csrf-token") != null);
}

test "middleware: POST with valid token passes" {
    const mw = testInstance();
    const token = mw.generateToken();

    var ht = initHt();
    defer ht.deinit();
    ht.req.method = .POST;
    ht.url("/submit");
    ht.header("cookie", "__Host-csrf=" ++ &token);
    ht.header("x-csrf-token", &token);

    var exec = NoopExecutor{};
    try mw.execute(ht.req, ht.res, &exec);

    try testing.expect(exec.called);
}

test "middleware: POST with missing cookie rejects" {
    const mw = testInstance();

    var ht = initHt();
    defer ht.deinit();
    ht.req.method = .POST;
    ht.url("/submit");

    var exec = NoopExecutor{};
    try mw.execute(ht.req, ht.res, &exec);

    try testing.expect(!exec.called);
    try testing.expectEqual(@as(u16, 403), ht.res.status);
}

test "middleware: POST with missing header rejects" {
    const mw = testInstance();
    const token = mw.generateToken();

    var ht = initHt();
    defer ht.deinit();
    ht.req.method = .POST;
    ht.url("/submit");
    ht.header("cookie", "__Host-csrf=" ++ &token);

    var exec = NoopExecutor{};
    try mw.execute(ht.req, ht.res, &exec);

    try testing.expect(!exec.called);
    try testing.expectEqual(@as(u16, 403), ht.res.status);
}

test "middleware: POST with mismatched tokens rejects" {
    const mw = testInstance();
    const token_a = mw.generateToken();
    const token_b = mw.generateToken();

    var ht = initHt();
    defer ht.deinit();
    ht.req.method = .POST;
    ht.url("/submit");
    ht.header("cookie", "__Host-csrf=" ++ &token_a);
    ht.header("x-csrf-token", &token_b);

    var exec = NoopExecutor{};
    try mw.execute(ht.req, ht.res, &exec);

    try testing.expect(!exec.called);
    try testing.expectEqual(@as(u16, 403), ht.res.status);
}

test "middleware: PUT requires token" {
    const mw = testInstance();

    var ht = initHt();
    defer ht.deinit();
    ht.req.method = .PUT;
    ht.url("/resource");

    var exec = NoopExecutor{};
    try mw.execute(ht.req, ht.res, &exec);

    try testing.expect(!exec.called);
    try testing.expectEqual(@as(u16, 403), ht.res.status);
}

test "middleware: DELETE requires token" {
    const mw = testInstance();

    var ht = initHt();
    defer ht.deinit();
    ht.req.method = .DELETE;
    ht.url("/resource/1");

    var exec = NoopExecutor{};
    try mw.execute(ht.req, ht.res, &exec);

    try testing.expect(!exec.called);
    try testing.expectEqual(@as(u16, 403), ht.res.status);
}

test "middleware: PATCH requires token" {
    const mw = testInstance();

    var ht = initHt();
    defer ht.deinit();
    ht.req.method = .PATCH;
    ht.url("/resource/1");

    var exec = NoopExecutor{};
    try mw.execute(ht.req, ht.res, &exec);

    try testing.expect(!exec.called);
    try testing.expectEqual(@as(u16, 403), ht.res.status);
}

test "middleware: OPTIONS passes without token" {
    const mw = testInstance();

    var ht = initHt();
    defer ht.deinit();
    ht.req.method = .OPTIONS;
    ht.url("/submit");

    var exec = NoopExecutor{};
    try mw.execute(ht.req, ht.res, &exec);

    try testing.expect(exec.called);
}

// -- Origin validation -------------------------------------------------------

test "originMatchesAllowed: matching origin" {
    const allowed = [_][]const u8{"https://example.com"};
    try testing.expect(originMatchesAllowed("https://example.com/path", &allowed));
}

test "originMatchesAllowed: non-matching origin" {
    const allowed = [_][]const u8{"https://example.com"};
    try testing.expect(!originMatchesAllowed("https://evil.com/path", &allowed));
}

test "originMatchesAllowed: origin with port" {
    const allowed = [_][]const u8{"https://example.com:8080"};
    try testing.expect(originMatchesAllowed("https://example.com:8080/api/data", &allowed));
}

test "originMatchesAllowed: referer without path" {
    const allowed = [_][]const u8{"https://example.com"};
    try testing.expect(originMatchesAllowed("https://example.com", &allowed));
}

test "originMatchesAllowed: invalid referer" {
    const allowed = [_][]const u8{"https://example.com"};
    try testing.expect(!originMatchesAllowed("not-a-url", &allowed));
}
