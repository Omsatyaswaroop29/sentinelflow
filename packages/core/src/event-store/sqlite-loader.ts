/**
 * @module @sentinelflow/core/event-store/sqlite-loader
 *
 * Lazy loader for the optional `better-sqlite3` native dependency.
 *
 * better-sqlite3 is an optionalDependency because it requires native
 * compilation and isn't available in every environment (restrictive CI
 * runners, some Windows setups, certain sandboxes). A top-level
 * `import Database from "better-sqlite3"` makes that failure eager: once
 * esbuild bundles it, merely importing @sentinelflow/core crashes the
 * whole process before any command-specific code runs, regardless of
 * whether that command needs SQLite. This module makes the load lazy and
 * catchable — the native module is only require()'d the first time
 * something actually constructs an EventStoreWriter/Reader.
 */

import type BetterSqlite3Ctor from "better-sqlite3";

type BetterSqlite3Module = typeof BetterSqlite3Ctor;

let cached: BetterSqlite3Module | null | undefined;

/**
 * Reset the memoized load result. Test-only: lets tests simulate the
 * dependency becoming available/unavailable across cases without
 * fighting bundler-level mocking of native addons (better-sqlite3 is a
 * native module that most bundler/test-runner mock systems externalize,
 * bypassing module-graph mocks entirely).
 */
export function _resetForTests(): void {
  cached = undefined;
}

export function loadBetterSqlite3(
  requireFn: NodeJS.Require = require
): BetterSqlite3Module | null {
  if (cached !== undefined) return cached;
  try {
    cached = requireFn("better-sqlite3") as BetterSqlite3Module;
  } catch {
    cached = null;
  }
  return cached;
}

export function isSqliteAvailable(): boolean {
  return loadBetterSqlite3() !== null;
}
