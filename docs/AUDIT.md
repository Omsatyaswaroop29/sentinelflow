# SentinelFlow Enterprise Quality Audit

**Date:** March 31, 2026
**Auditor:** Claude (with Om Satya Swaroop)
**Status:** 14 issues found — all addressed below

---

## CRITICAL Issues (Will cause build/runtime failures)

### C1: Module System Mismatch
**Found:** tsconfig uses `"module": "Node16"` requiring `.js` import extensions (ESM), but no package.json has `"type": "module"`, and `local.ts` uses CommonJS `require()`.
**Impact:** Build will compile but runtime will fail with module resolution errors.
**Fix:** Standardize on CommonJS — the most compatible choice for CLI tools and npm packages. Change tsconfig to `"module": "commonjs"`, `"moduleResolution": "node"`, remove all `.js` extensions from imports, replace `require()` with proper `import` statements.

### C2: Zero Test Coverage
**Found:** No test files exist anywhere in the project.
**Impact:** No confidence that any code works. Unacceptable for enterprise.
**Fix:** Add comprehensive test suites for: schema factories, Claude Code parser, every scanner rule, the scan engine, reporters, CLI commands. Minimum 80% coverage target. Add vitest configuration.

### C3: CLI Missing Shebang + Module Compatibility
**Found:** CLI entry point has shebang `#!/usr/bin/env node` but no proper ESM/CJS configuration, and the `bin` field in package.json may not resolve correctly.
**Impact:** `npx sentinelflow scan` will fail.
**Fix:** Ensure CLI compiles to CommonJS, add proper bin configuration, test `npx` execution.

---

## HIGH Issues (Will cause incorrect behavior)

### H1: Bare `catch (e)` Error Handling
**Found:** 4 instances in claude-code.ts where errors are caught as untyped `e` and converted to string with `${e}`.
**Impact:** Swallows stack traces, makes debugging impossible. Error messages may be `[object Object]`.
**Fix:** Type errors as `unknown`, use `e instanceof Error ? e.message : String(e)` pattern consistently. Create `SentinelFlowError` base class.

### H2: Naive YAML Frontmatter Parsing
**Found:** claude-code.ts parses YAML frontmatter with regex (`/^(\w[\w-]*):\s*(.+)/`). This fails for multi-line values, nested objects, quoted strings with colons, and arrays.
**Impact:** Agent definitions with complex frontmatter will be silently mis-parsed.
**Fix:** Use the `gray-matter` package (already in parsers/package.json dependencies) for proper frontmatter extraction, then use the `yaml` package for parsing.

### H3: Local Registry Concurrent Write Safety
**Found:** JSON-file registry uses `readFileSync`/`writeFileSync` with no locking. Two simultaneous scans can corrupt data.
**Impact:** Data loss in multi-terminal or CI environments.
**Fix:** Add simple file locking via `.lock` file pattern, or use `proper-lockfile` package. For v0.1, add a warning comment and ensure atomic writes via write-to-temp-then-rename pattern.

### H4: SARIF Output Not Implemented
**Found:** README promises SARIF output for GitHub Security integration, but no SARIF formatter exists.
**Impact:** Broken promise in documentation. CI/CD integration guidance won't work.
**Fix:** Implement SARIF 2.1.0 formatter in reporter.ts.

### H5: Scanner Framework Filter Not Applied
**Found:** Rules have a `frameworks` field ("all" or specific list), but the engine doesn't filter rules by framework.
**Impact:** Framework-specific rules run against all agents regardless of framework.
**Fix:** Add framework filtering in the scan engine before rule evaluation.

---

## MEDIUM Issues (Reduce quality/maintainability)

### M1: No Input Validation on CLI Arguments
**Found:** CLI accepts `--format`, `--min-severity`, `--rules` without validating values.
**Impact:** Invalid format string produces silent failure. Bad severity value skips all rules.
**Fix:** Add validation with clear error messages for each argument.

### M2: No Graceful Handling of Empty Projects
**Found:** Scanning a directory with no agent frameworks produces unclear output.
**Impact:** First-time users get confused by "0 agents" with no helpful guidance.
**Fix:** Detect empty scans and print helpful message: "No agent frameworks detected. SentinelFlow supports: Claude Code, LangChain, ..."

### M3: Missing Vitest Configuration
**Found:** vitest is in devDependencies but no vitest.config.ts exists.
**Impact:** `pnpm test` runs with default settings, may miss files or have wrong coverage paths.
**Fix:** Add vitest.config.ts at root and per-package.

### M4: No TypeScript Strict Configuration Verification
**Found:** tsconfig.base.json has `"strict": true` but individual packages don't verify they inherit it correctly.
**Impact:** A package could accidentally override strict mode.
**Fix:** Add `"noUncheckedIndexedAccess": true` and `"exactOptionalPropertyTypes": true` for maximum type safety.

---

## LOW Issues (Nice to have)

### L1: No Prettier Configuration
**Found:** package.json references prettier but no `.prettierrc` exists.
**Impact:** Inconsistent formatting across files.
**Fix:** Add `.prettierrc` with consistent settings.

### L2: Missing `.npmignore` or `files` Field
**Found:** packages don't specify which files to include in npm publish.
**Impact:** npm publish will include test files, source maps, and other unnecessary files.
**Fix:** Add `"files": ["dist"]` to each package.json.

---

## Fix Priority Order

1. C1 (Module system) — everything depends on this
2. C3 (CLI compatibility) — users can't run the tool without this
3. H1 (Error handling) — bad errors = bad trust
4. H2 (YAML parsing) — parser accuracy is core functionality
5. H5 (Framework filter) — rules must run correctly
6. C2 (Tests) — verify all fixes work
7. H4 (SARIF output) — complete the CI/CD story
8. M1-M4 (Quality improvements) — polish
9. L1-L2 (Nice to have) — final touches
