/**
 * Regression test for hardcoded version-string drift.
 *
 * Three independent places used to hardcode a product version string
 * ("0.3.1" in index.ts, "0.2.0" in scan.ts, "0.3.0" in the scanner's
 * reporter.ts) that silently fell behind package.json across releases.
 * CLI_VERSION is now the single source of truth, read directly from
 * package.json, so `--version` and banner text can never drift again.
 */

import { describe, it, expect } from "vitest";
import { CLI_VERSION } from "../version";
// eslint-disable-next-line @typescript-eslint/no-require-imports
const packageJson = require("../../package.json") as { version: string };

describe("CLI_VERSION", () => {
  it("matches package.json exactly", () => {
    expect(CLI_VERSION).toBe(packageJson.version);
  });

  it("is a valid semver string", () => {
    expect(CLI_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
