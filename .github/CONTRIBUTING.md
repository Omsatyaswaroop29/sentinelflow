# Contributing to SentinelFlow

Thank you for helping build the governance layer for AI agents.

## Ways to Contribute

### Add a Framework Parser

The highest-impact contribution. Each parser lets SentinelFlow discover agents from a new framework.

1. Create `packages/parsers/src/<framework>.ts`
2. Implement the `FrameworkParser` interface
3. Register in `packages/parsers/src/auto-detect.ts`
4. Add test fixtures in `packages/parsers/src/__tests__/fixtures/`
5. Update the Supported Frameworks table in README.md

**Needed:** Cursor, Codex, LangChain, CrewAI, AutoGen, Copilot Studio

### Add a Governance Rule

Rules are pure functions — the easiest type of contribution.

1. Create or extend a file in `packages/scanner/src/rules/`
2. Implement the `ScanRule` interface
3. Register in `packages/scanner/src/rules/index.ts`
4. Write 3+ tests (positive detection, negative/clean, edge case)
5. Update the Governance Rules table in README.md

**Rule ID format:** `SF-<CATEGORY>-<NUMBER>`
Categories: SEC, PERM, GUARD, ID, COST, TOPO, MCP, COMPLY

### Bug Reports

Open an issue with:
- SentinelFlow version (`sentinelflow --version`)
- Node.js version
- Operating system
- Steps to reproduce
- Expected vs actual behavior

### Documentation

- Fix typos or unclear explanations
- Add examples to docs/
- Translate the README

## Development Setup

```bash
git clone https://github.com/omswaroop/sentinelflow.git
cd sentinelflow
pnpm install
pnpm build
pnpm test
```

## Code Standards

- TypeScript strict mode — no `any`, no `@ts-ignore`
- Immutability — never mutate function arguments
- Small files — 200–400 lines, 800 max
- Every public function needs JSDoc
- 80%+ test coverage

## Pull Request Process

1. Fork and create a branch from `main`
2. Write tests before implementation
3. Run `pnpm build && pnpm test && pnpm lint`
4. Submit PR with a clear description of what and why
5. One approval required for merge

## License

By contributing, you agree that your contributions will be licensed under MIT.
