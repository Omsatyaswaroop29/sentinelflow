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

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const cliDist = path.join(__dirname, "..", "packages", "cli", "dist");
const bundlePath = path.join(cliDist, "bundle.js");

try {
  execSync(
    `npx esbuild ${path.join(cliDist, "index.js")} ` +
      `--bundle ` +
      `--platform=node ` +
      `--target=node20 ` +
      `--outfile=${bundlePath} ` +
      `--external:better-sqlite3 ` +
      `--external:commander`,
    { stdio: "inherit" }
  );

  // Strip any shebangs esbuild may have preserved, prepend exactly one
  let content = fs.readFileSync(bundlePath, "utf-8");
  content = content.replace(/^#!.*\n/gm, "");
  content = "#!/usr/bin/env node\n" + content;
  fs.writeFileSync(bundlePath, content);

  console.log("✓ Bundle created: packages/cli/dist/bundle.js");
} catch (error) {
  console.error("Bundle failed:", error.message);
  process.exit(1);
}
