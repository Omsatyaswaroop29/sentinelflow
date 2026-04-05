/**
 * Bundle the SentinelFlow CLI into a single file for npm publishing.
 *
 * Problem: The monorepo uses pnpm workspace:* references which npm
 * can't resolve. Solution: esbuild bundles all internal packages
 * AND their pure-JS dependencies into one file.
 *
 * Only truly external packages (native addons, direct CLI deps):
 *   - better-sqlite3: native C++ addon, can't be bundled
 *   - commander: CLI framework, always installed as a direct dep
 *
 * Everything else (gray-matter, yaml, toml, uuid) gets bundled in
 * so there are zero runtime resolution issues.
 */

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const cliDist = path.join(root, "packages", "cli", "dist");
const bundlePath = path.join(cliDist, "bundle.js");

// Resolve esbuild binary from the local node_modules — never rely on PATH.
// Works with pnpm's hoisted layout where binaries live in node_modules/esbuild/bin/
const esbuildBin = path.join(root, "node_modules", "esbuild", "bin", "esbuild");

if (!fs.existsSync(esbuildBin)) {
  console.error("ERROR: esbuild not found at", esbuildBin);
  console.error("Run 'pnpm install' first.");
  process.exit(1);
}

const entryPoint = path.join(cliDist, "index.js");
if (!fs.existsSync(entryPoint)) {
  console.error("ERROR: CLI entry point not found at", entryPoint);
  console.error("Run TypeScript compilation first.");
  process.exit(1);
}

try {
  // Execute the esbuild native binary directly — do NOT prefix with `node`.
  // Since esbuild v0.18+, node_modules/esbuild/bin/esbuild is a native ARM64/x64
  // binary, not a JS file. Passing it as an argument to node produces:
  //   "SyntaxError: Invalid or unexpected token" on byte 1 of the binary.
  execFileSync(
    esbuildBin,
    [
      entryPoint,
      "--bundle",
      "--platform=node",
      "--target=node20",
      `--outfile=${bundlePath}`,
      "--external:better-sqlite3",
      "--external:commander",
    ],
    { stdio: "inherit" }
  );

  // Strip any shebangs esbuild may have preserved, prepend exactly one
  let content = fs.readFileSync(bundlePath, "utf-8");
  content = content.replace(/^#!.*\n/gm, "");
  content = "#!/usr/bin/env node\n" + content;
  fs.writeFileSync(bundlePath, content);

  console.log("Bundle created: packages/cli/dist/bundle.js");
} catch (error) {
  console.error("Bundle failed:", error.message);
  process.exit(1);
}
