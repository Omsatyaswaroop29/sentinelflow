# SentinelFlow — Project Guidance

This is **SentinelFlow**, the vendor-neutral governance layer for enterprise AI agents. It discovers, monitors, and governs AI agents across every framework — Claude Code, Cursor, Codex, LangChain, CrewAI, and beyond.

## Architecture

SentinelFlow is a pnpm monorepo with 5 packages:

- `@sentinelflow/core` — Universal agent schema, registry types, local SQLite storage
- `@sentinelflow/parsers` — Framework-specific agent configuration parsers
- `@sentinelflow/scanner` — Static analysis governance rules engine (9 rules, 5 categories)
- `@sentinelflow/interceptors` — Runtime monitoring SDK (Phase 2)
- `sentinelflow` — CLI tool (`sentinelflow scan`, `sentinelflow init`, `sentinelflow registry`)

## Development Workflow

1. Always run `pnpm build` before testing — packages depend on each other's compiled output
2. Run `pnpm test` to execute the full test suite
3. Follow TDD: write failing tests first, then implement, then refactor
4. Every new scanner rule needs at minimum 3 test cases: a positive detection, a negative (clean), and an edge case

## Code Standards

- TypeScript strict mode — no `any` types, no `@ts-ignore`
- Immutability — never mutate function arguments; return new objects
- Small files — 200–400 lines typical, 800 max
- Feature-organized — group by capability, not by type
- Error handling at every level — never swallow errors silently

## Key Design Decisions

- **Agent schema is the heart** — `packages/core/src/schema/agent.ts` defines the universal agent identity. Every parser normalizes into this schema. Every rule evaluates against it. Every interceptor emits events referencing it.
- **Rules are pure functions** — each rule receives a `RuleContext` and returns `Finding[]`. No side effects, no state mutation. This makes them easy to test and compose.
- **Parsers are pluggable** — adding a new framework means implementing the `FrameworkParser` interface and registering it in `auto-detect.ts`.
- **Registry is swappable** — `IRegistry` interface abstracts storage. `LocalRegistry` uses JSON files. Future: SQLite, Postgres, cloud API.

## Secret Management

NEVER hardcode secrets. Use environment variables. If you find a secret in code, rotate it immediately.

## Package Manager

This project uses pnpm. Run `pnpm install` to install dependencies. The `pnpm-workspace.yaml` defines the monorepo structure.

## Testing

Run tests with `pnpm test` (uses Vitest). Target 80%+ coverage. Every scanner rule must have tests in `packages/scanner/src/rules/__tests__/`.

## Build

`pnpm build` compiles all packages via Turborepo. Build order respects package dependencies: core → parsers → scanner → interceptors → cli.

---

## Package Manager Strategy

SentinelFlow uses a **dual-mode architecture**: pnpm internally for development, package-manager-agnostic externally for distribution.

**For contributors (internal):** The monorepo requires pnpm. The root `package.json` declares `packageManager: pnpm@9.15.0`, `.npmrc` has `engine-strict=true`, and Turborepo orchestrates builds. Always use `pnpm install`, `pnpm build`, `pnpm test`.

**For users (published npm package):** The CLI is bundled with esbuild into a single ~600KB JavaScript file with ZERO runtime dependencies. `npx sentinelflow scan .` works identically with npm, yarn, pnpm, or bun. The only optional dependency is `better-sqlite3` (native C++ addon for SQLite event storage), which degrades gracefully to JSONL-only if unavailable.

**Why this matters:** Meta uses Yarn, OpenAI uses a mix of Yarn and pnpm, Anthropic uses Yarn, Apple uses npm. A governance tool that requires pnpm would face adoption barriers at every one of these organizations. The single-file bundle eliminates all package resolution issues.

**Critical rules for the published package:**
- The `packages/cli/package.json` must NEVER contain `packageManager`, `pnpm` overrides, or `workspace:*` in any non-dev field
- The `files` field must be an explicit allowlist: `["dist/bundle.js", "README.md", "LICENSE"]`
- `better-sqlite3` must be `optionalDependencies`, not `dependencies`
- All other packages (commander, yaml, toml, etc.) must be bundled by esbuild, not listed as runtime deps
- Run `node scripts/prepublish-check.js` before every `npm publish`

---

## Publishing Playbook

1. Build: `pnpm build`
2. Test: `pnpm test` (all unit tests)
3. Golden paths: `bash scripts/golden-path-test.sh` (repeat for cursor, copilot, codex)
4. Pre-publish check: `node scripts/prepublish-check.js`
5. Pack and inspect: `cd packages/cli && npm pack && tar -tzf sentinelflow-*.tgz`
6. Test the packed tarball: `npx ./sentinelflow-*.tgz --help`
7. Publish: `npm publish --access public`
8. Verify: `npx sentinelflow@latest --version`
