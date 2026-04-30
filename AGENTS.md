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
| `src/root.zig` | Single-file middleware — Config, execute, token gen/verify, cookie, origin validation (42 tests) |
| `examples/basic_server.zig` | Runnable demo — CSRF-protected form with GET + POST routes |
| `build.zig` | Build system — library module, example executable, test step |
| `build.zig.zon` | Package manifest (Zig 0.16.0, httpz dependency) |
| `DESIGN.md` | Architecture — token format, threat model, request flow, rejected alternatives, implementation checklist |
| `README.md` | Usage, configuration, client flow, dependency setup |
| `AGENTS.md` | This file — operating rules, repo map, orientation |
| `docs/index.md` | Documentation index |
| `CHANGELOG.md` | Release history (semver, conventional commits) |
| `LICENSE` | MIT |
| `.gitignore` | Ignores zig-out/, .zig-cache/, zig-pkg/ |

## Merge strategy

- Prefer squash merge.
- PR title must be a valid Conventional Commit.

## Definition of done

- Works locally.
- Tests updated if behaviour changed.
- CHANGELOG updated when user-facing.
- No secrets committed.

## Orientation

- **Entry point**: `src/root.zig` — single-file middleware (42 tests inline).
- **Domain**: Stateless CSRF protection middleware for the Zig [httpz](https://github.com/karlseguin/http.zig) framework. Signed Double-Submit Cookie pattern with HMAC-SHA256.
- **Stack**: Zig 0.16.x, httpz.
- **Current version**: 1.0.0.
