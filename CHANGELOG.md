# Changelog

All notable changes to this project will be documented in this file.

## [0.1.2] — 2026-02-25

### Fixes

- Use `req.formData()` instead of `req.query()` in example POST handler — query reads URL params, not form body
- Use httpz native `res.setCookie()` API instead of manual header formatting — properly propagates allocation errors
- Unsafe methods without a cookie now reject immediately without generating a token — no wasted arena allocation or misleading `Set-Cookie` on 403 responses

### Other

- Make `parseCookieValue` private (internal use only)
- Remove unused `self` parameter from `validateOrigin`
- Remove unused `encoded_sig_len` constant
- Fix API names in DESIGN.md (`timing_safe.eql` not `timingSafeEql`)
- Pin dependency snippet in README to release tag instead of `#main`
- Add tests for `safe_custom` config, origin validation integration, and no `Set-Cookie` on rejected requests (37 → 41 tests)

## [0.1.1] — 2026-02-25

### Fixes

- Use `formData().get()` instead of `param()` for form field token extraction — `param()` reads URL route parameters, not POST body fields, so every form-based CSRF submission was silently rejected

### Other

- Validate `__Host-` cookie prefix invariants at init (`Secure=true`, `Path=/`)
- Document expected client flow (GET first, then POST) in README
- Add form field fallback and config validation tests

## [0.1.0] — 2026-02-25

### Features

- Stateless CSRF protection middleware using Signed Double-Submit Cookie pattern with HMAC-SHA256
- Token generation with 32-byte random nonce and base64url encoding (87 chars)
- Constant-time token verification via `timing_safe.eql`
- Cookie management with configurable name, path, max-age, Secure, and SameSite attributes
- Origin/Referer validation (opt-in defence-in-depth)
- Configurable rejection status and body
- Safe method detection with custom method support
- Token extraction from header (`x-csrf-token`) with form field (`_csrf`) fallback
- Example server with form-based CSRF flow
