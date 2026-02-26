# Changelog

All notable changes to this project will be documented in this file.

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
