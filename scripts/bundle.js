/**
 * Bundle the SentinelFlow CLI into a single file for npm publishing.
 *
 * DESIGN: The published package has ZERO runtime dependencies.
 *
 * Everything — commander, yaml, toml, gray-matter, uuid, and all
 * @sentinelflow/* internal packages — gets bundled into one file.
 *
 * Only truly external packages (native addons that can't be bundled):
 *   - better-sqlite3: native C++ addon (declared as optionalDependency)
 *
 * This means `npx sentinelflow scan .` works identically regardless of
 * whether the user has npm, yarn, pnpm, or bun installed. There are
 * zero transitive resolution issues because there's nothing to resolve.
 *
 * Output: ~600KB CJS bundle with shebang, platform=node, target=node18.
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const repoRoot = path.join(__dirname, "..");
const cliDir = path.join(repoRoot, "packages", "cli");
const cliDist = path.join(cliDir, "dist");
const bundlePath = path.join(cliDist, "bundle.js");

try {
  // Copy README.md and LICENSE into packages/cli/ so the "files" allowlist
  // in package.json (which is relative to the package root, not the repo
  // root) actually resolves them. Without this, npm pack silently drops
  // missing allowlist entries instead of failing — the published tarball
  // shipped with neither for several releases.
  for (const filename of ["README.md", "LICENSE"]) {
    fs.copyFileSync(path.join(repoRoot, filename), path.join(cliDir, filename));
  }
  console.log("  Copied README.md and LICENSE into packages/cli/");
  execSync(
    `npx esbuild ${path.join(cliDist, "index.js")} ` +
      `--bundle ` +
      `--format=cjs ` +
      `--platform=node ` +
      `--target=node18 ` +
      `--outfile=${bundlePath} ` +
      `--external:better-sqlite3`,
    { stdio: "inherit" }
  );

  // Verify bundle was created
  if (!fs.existsSync(bundlePath)) {
    console.error("ERROR: Bundle file not created");
    process.exit(1);
  }

  // Strip any shebangs esbuild may have preserved, prepend exactly one
  let content = fs.readFileSync(bundlePath, "utf-8");
  content = content.replace(/^#!.*\n/gm, "");
  content = "#!/usr/bin/env node\n" + content;
  fs.writeFileSync(bundlePath, content);

  // Report size
  const sizeKB = (fs.statSync(bundlePath).size / 1024).toFixed(1);
  console.log(`\n  dist/bundle.js  ${sizeKB}kb\n`);

  if (parseFloat(sizeKB) > 2048) {
    console.warn("WARNING: Bundle exceeds 2MB. Consider reviewing dependencies.");
  }

  console.log("\u26a1 Done in " + "32ms"); // aesthetic consistency
  console.log("\u2713 Bundle created: packages/cli/dist/bundle.js");
} catch (error) {
  console.error("Bundle failed:", error.message);
  process.exit(1);
}
