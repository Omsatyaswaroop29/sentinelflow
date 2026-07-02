/**
 * Regression tests for the better-sqlite3 lazy-loader.
 *
 * Reproduces the launch-blocking bug where a static top-level
 * `import Database from "better-sqlite3"` in writer.ts/queries.ts got
 * compiled by esbuild into an eager require() in dist/bundle.js — so
 * merely importing @sentinelflow/core (e.g. from `sentinelflow scan`,
 * which never touches the event store) crashed the whole CLI in any
 * environment missing the optional native dependency.
 *
 * better-sqlite3 is a native addon that bundler/test-runner mock systems
 * (vi.mock included) typically externalize, bypassing module-graph mocks
 * entirely. Instead of fighting that, loadBetterSqlite3() accepts an
 * injectable require function so tests can deterministically simulate
 * "dependency missing" without touching the real node_modules tree.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { loadBetterSqlite3, isSqliteAvailable, _resetForTests } from "../event-store/sqlite-loader";
import { EventStoreWriter } from "../event-store/writer";
import { EventStoreReader } from "../event-store/queries";

const throwingRequire = (() => {
  throw new Error("Cannot find module 'better-sqlite3'");
}) as unknown as NodeJS.Require;

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sf-nosqlite-"));
}

describe("sqlite-loader when better-sqlite3 is unavailable", () => {
  beforeEach(() => _resetForTests());
  afterEach(() => _resetForTests());

  it("returns null instead of throwing", () => {
    expect(loadBetterSqlite3(throwingRequire)).toBeNull();
    expect(isSqliteAvailable()).toBe(false);
  });

  it("caches the failed result instead of re-attempting require on every call", () => {
    let attempts = 0;
    const countingThrowingRequire = ((() => {
      attempts++;
      throw new Error("Cannot find module 'better-sqlite3'");
    }) as unknown) as NodeJS.Require;

    loadBetterSqlite3(countingThrowingRequire);
    loadBetterSqlite3(countingThrowingRequire);
    loadBetterSqlite3(countingThrowingRequire);
    expect(attempts).toBe(1);
  });

  it("EventStoreWriter throws a clear, catchable error instead of an uncaught module-resolution crash", () => {
    loadBetterSqlite3(throwingRequire); // populate the cached "unavailable" result
    const dir = createTempDir();
    try {
      expect(() => new EventStoreWriter({ projectDir: dir })).toThrow(
        /better-sqlite3 is not available/
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("EventStoreReader throws a clear, catchable error instead of an uncaught module-resolution crash", () => {
    loadBetterSqlite3(throwingRequire); // populate the cached "unavailable" result
    const dir = createTempDir();
    const dbPath = path.join(dir, "fake.db");
    fs.writeFileSync(dbPath, ""); // satisfy the "does the file exist" check
    try {
      expect(() => new EventStoreReader({ projectDir: dir, dbPath })).toThrow(
        /better-sqlite3 is not available/
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("sqlite-loader when better-sqlite3 is available", () => {
  beforeEach(() => _resetForTests());
  afterEach(() => _resetForTests());

  it("loads the real module and reports available", () => {
    expect(loadBetterSqlite3()).not.toBeNull();
    expect(isSqliteAvailable()).toBe(true);
  });
});
