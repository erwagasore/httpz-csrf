# AGENTS — httpz-csrf

Operating rules for humans + AI.

## Workflow

- Never commit to `main`/`master`.
- Always start on a new branch.
- Only push after the user approves.
- Merge via PR.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/).

- fix → patch
- feat → minor
- feat! / BREAKING CHANGE → major
- chore, docs, refactor, test, ci, style, perf → no version change

## Releases

- Semantic versioning.
- Versions derived from Conventional Commits.
- Release performed locally via `/create-release` (no CI required).
- Manifest (if present) is source of truth.
- Tags: vX.Y.Z

## Repo map

| Path | Description |
|------|-------------|
| `src/root.zig` | Middleware implementation — config, execute, token gen/verify, cookie handling |
| `examples/basic_server.zig` | Runnable example server with CSRF-protected routes |
| `build.zig` | Build system — library module, example executable, test step |
| `build.zig.zon` | Package manifest with httpz dependency |
| `DESIGN.md` | Architecture and principles (token format, threat model, design decisions) |
| `docs/index.md` | Documentation index with links to all project docs |
| `CHANGELOG.md` | Release history |
| `LICENSE` | MIT licence |

## Merge strategy

- Prefer squash merge.
- PR title must be a valid Conventional Commit.

## Definition of done

- Works locally.
- Tests updated if behaviour changed.
- CHANGELOG updated when user-facing.
- No secrets committed.

## Orientation

- **Entry point**: `src/root.zig` — single-file middleware implementation.
- **Domain**: Stateless CSRF protection middleware for the Zig [httpz](https://github.com/karlseguin/http.zig) framework. Signed Double-Submit Cookie pattern with HMAC-SHA256.
- **Stack**: Zig 0.15+, httpz.
