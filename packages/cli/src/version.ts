/**
 * @module sentinelflow/version
 *
 * Single source of truth for the CLI's displayed version, read directly
 * from package.json at load time so `--version` and banner text can
 * never drift from what was actually published to npm.
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports
export const CLI_VERSION: string = (require("../package.json") as { version: string }).version;
