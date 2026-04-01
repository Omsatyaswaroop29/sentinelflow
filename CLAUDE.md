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

`pnpm build` compiles all packages via Turborepo. Build order respects package dependencies: core → parsers → scanner → cli.
