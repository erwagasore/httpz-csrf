const std = @import("std");
const httpz = @import("httpz");
const Csrf = @import("httpz_csrf");

const PORT = 8080;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var server = try httpz.Server(void).init(allocator, .{
        .port = PORT,
        .request = .{ .max_form_count = 16 },
    }, {});
    defer server.deinit();
    defer server.stop();

    // ⚠ DO NOT use a hardcoded secret in production — load from environment.
    const csrf = try server.middleware(Csrf, .{
        .secret = "this-is-a-dev-secret-at-least-32b!",
        .secure = false, // dev only — no HTTPS
        .cookie_name = "csrf", // no __Host- prefix without Secure
    });

    var router = try server.router(.{ .middlewares = &.{csrf} });
    router.get("/", getForm, .{});
    router.post("/submit", postSubmit, .{});

    std.debug.print("listening http://localhost:{d}/\n", .{PORT});
    try server.listen();
}

fn getForm(_: *httpz.Request, res: *httpz.Response) !void {
    const token = res.headers.get("x-csrf-token") orelse "MISSING";
    res.content_type = .HTML;
    res.body = std.fmt.allocPrint(res.arena,
        \\<!DOCTYPE html>
        \\<html><body>
        \\<h1>CSRF Demo</h1>
        \\<form method="POST" action="/submit">
        \\  <input type="hidden" name="_csrf" value="{s}">
        \\  <input type="text" name="message" placeholder="Type something">
        \\  <button type="submit">Submit</button>
        \\</form>
        \\</body></html>
    , .{token}) catch return;
}

fn postSubmit(req: *httpz.Request, res: *httpz.Response) !void {
    const fd = try req.formData();
    const message = fd.get("message") orelse "(empty)";
    res.content_type = .HTML;
    res.body = std.fmt.allocPrint(res.arena,
        \\<!DOCTYPE html>
        \\<html><body>
        \\<h1>Success!</h1>
        \\<p>You said: {s}</p>
        \\<a href="/">Back</a>
        \\</body></html>
    , .{message}) catch return;
}
