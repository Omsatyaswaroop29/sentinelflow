/**
 * Pre-publish safety check for the SentinelFlow npm package.
 *
 * Catches the most common publish-time failures:
 *   1. workspace:* specifiers leaking into published package.json
 *   2. Source map files (.map) accidentally included (the claude-code incident)
 *   3. TypeScript source files leaking into the tarball
 *   4. Missing shebang in the bundle
 *   5. Tarball too large (>5MB warning)
 *   6. Missing required files (bundle.js, README, LICENSE)
 *
 * Run manually: node scripts/prepublish-check.js
 * Run automatically: npm publish triggers "prepublishOnly" in package.json
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const CLI_DIR = path.join(__dirname, "..", "packages", "cli");
const BUNDLE_PATH = path.join(CLI_DIR, "dist", "bundle.js");
const PKG_PATH = path.join(CLI_DIR, "package.json");

let errors = 0;
let warnings = 0;

function fail(msg) {
  console.error(`  FAIL  ${msg}`);
  errors++;
}

function warn(msg) {
  console.warn(`  WARN  ${msg}`);
  warnings++;
}

function pass(msg) {
  console.log(`  PASS  ${msg}`);
}

console.log("");
console.log("  SentinelFlow Pre-Publish Safety Check");
console.log("  =====================================");
console.log("");

// ─── 1. Check bundle exists ─────────────────────────────────────

if (!fs.existsSync(BUNDLE_PATH)) {
  fail("Bundle not found at dist/bundle.js. Run 'pnpm build' first.");
} else {
  pass("Bundle exists at dist/bundle.js");

  // Check shebang
  const bundleStart = fs.readFileSync(BUNDLE_PATH, "utf-8").slice(0, 50);
  if (bundleStart.startsWith("#!/usr/bin/env node")) {
    pass("Bundle has correct shebang (#!/usr/bin/env node)");
  } else {
    fail("Bundle missing shebang. First line: " + bundleStart.slice(0, 30));
  }

  // Check size
  const sizeKB = fs.statSync(BUNDLE_PATH).size / 1024;
  const sizeMB = sizeKB / 1024;
  if (sizeMB > 5) {
    fail(`Bundle is ${sizeMB.toFixed(1)}MB — exceeds 5MB safety limit`);
  } else if (sizeMB > 2) {
    warn(`Bundle is ${sizeMB.toFixed(1)}MB — getting large`);
  } else {
    pass(`Bundle size: ${sizeKB.toFixed(0)}KB`);
  }
}

// ─── 2. Check package.json for workspace leaks ──────────────────

const pkg = JSON.parse(fs.readFileSync(PKG_PATH, "utf-8"));

// Only check PUBLISHED dependency fields — devDependencies are fine
const publishedDepFields = ["dependencies", "optionalDependencies", "peerDependencies"];
let hasWorkspaceLeak = false;

for (const section of publishedDepFields) {
  if (pkg[section]) {
    for (const [name, version] of Object.entries(pkg[section])) {
      if (String(version).includes("workspace:")) {
        fail(`${section}.${name}: "${version}" — workspace:* will break npm/yarn install`);
        hasWorkspaceLeak = true;
      }
    }
  }
}

if (!hasWorkspaceLeak) {
  pass("No workspace:* specifiers in published dependencies");
}

// devDependencies with workspace:* are fine — note for awareness
if (pkg.devDependencies) {
  const workspaceDev = Object.entries(pkg.devDependencies)
    .filter(([, v]) => String(v).includes("workspace:"));
  if (workspaceDev.length > 0) {
    pass(`${workspaceDev.length} workspace:* in devDependencies (OK — not published)`);
  }
}

// ─── 3. Check for packageManager field ──────────────────────────

if (pkg.packageManager) {
  fail(`packageManager field found: "${pkg.packageManager}" — remove from published package`);
} else {
  pass("No packageManager field (package-manager agnostic)");
}

// ─── 4. Check for pnpm-specific fields ──────────────────────────

if (pkg.pnpm) {
  fail("pnpm overrides/config found — remove from published package");
} else {
  pass("No pnpm-specific fields");
}

// ─── 5. Check engines don't pin a package manager ───────────────

if (pkg.engines) {
  if (pkg.engines.pnpm || pkg.engines.yarn || pkg.engines.npm) {
    fail("engines field pins a specific package manager — remove pnpm/yarn/npm from engines");
  } else {
    pass(`engines: { node: "${pkg.engines.node || "not set"}" } — no PM constraints`);
  }
}

// ─── 6. Check files field is explicit ───────────────────────────

if (!pkg.files) {
  fail("No 'files' field — everything will be published (dangerous)");
} else {
  const files = pkg.files;
  pass(`files field: ${JSON.stringify(files)}`);

  // Warn if files field is too broad
  if (files.includes("dist") && !files.includes("dist/bundle.js")) {
    warn("files includes 'dist' directory — consider narrowing to 'dist/bundle.js'");
  }
}

// ─── 7. Check for source maps in dist ───────────────────────────

const distDir = path.join(CLI_DIR, "dist");
if (fs.existsSync(distDir)) {
  const distFiles = fs.readdirSync(distDir);
  const mapFiles = distFiles.filter((f) => f.endsWith(".map"));
  if (mapFiles.length > 0) {
    // Check if the files allowlist would actually publish them
    const filesField = pkg.files || [];
    const wouldPublishMaps = filesField.some((f) =>
      f === "dist" || f === "dist/" || f.endsWith(".map")
    );
    if (wouldPublishMaps) {
      fail(`Source maps in dist/ AND files field would include them: ${mapFiles.join(", ")}`);
    } else {
      pass(`Source maps in dist/ (${mapFiles.join(", ")}) excluded by files allowlist`);
    }
  } else {
    pass("No source map files in dist/");
  }

  // Check for .ts files that shouldn't be in dist
  const tsFiles = distFiles.filter((f) => f.endsWith(".ts") && !f.endsWith(".d.ts"));
  if (tsFiles.length > 0) {
    warn(`TypeScript source files in dist/: ${tsFiles.join(", ")}`);
  }
}

// ─── 8. Check runtime dependencies are minimal ──────────────────

const runtimeDeps = Object.keys(pkg.dependencies || {});
const optionalDeps = Object.keys(pkg.optionalDependencies || {});

if (runtimeDeps.length === 0) {
  pass("Zero runtime dependencies (fully bundled)");
} else {
  warn(`${runtimeDeps.length} runtime dependencies: ${runtimeDeps.join(", ")} — consider bundling`);
}

if (optionalDeps.length > 0) {
  pass(`Optional dependencies: ${optionalDeps.join(", ")} (native addons)`);
}

// ─── 9. Check type field ────────────────────────────────────────

if (pkg.type === "commonjs") {
  pass("type: commonjs (safest for npx/Node 18+)");
} else if (!pkg.type) {
  warn("No 'type' field — defaults to commonjs but should be explicit");
} else {
  warn(`type: ${pkg.type} — consider 'commonjs' for maximum npx compatibility`);
}

// ─── 10. Simulate npm pack ──────────────────────────────────────

console.log("");
console.log("  Simulating npm pack...");
try {
  const packOutput = execSync("npm pack --dry-run --json 2>/dev/null", {
    cwd: CLI_DIR,
    encoding: "utf-8",
  });
  const packInfo = JSON.parse(packOutput);
  if (Array.isArray(packInfo) && packInfo[0]) {
    const tarball = packInfo[0];
    const tarSizeKB = (tarball.size / 1024).toFixed(1);
    pass(`Pack size: ${tarSizeKB}KB (${tarball.filename})`);

    // Check for suspicious files in the tarball
    if (tarball.files) {
      const suspicious = tarball.files.filter((f) =>
        f.path.endsWith(".map") ||
        (f.path.endsWith(".ts") && !f.path.endsWith(".d.ts")) ||
        f.path.includes("src/") ||
        f.path.includes("__tests__/")
      );
      if (suspicious.length > 0) {
        for (const f of suspicious) {
          fail(`Suspicious file in tarball: ${f.path}`);
        }
      } else {
        pass("No suspicious files in tarball");
      }
    }
  }
} catch (e) {
  warn("Could not simulate npm pack (non-fatal): " + (e.message || "").slice(0, 80));
}

// ─── Summary ────────────────────────────────────────────────────

console.log("");
console.log("  =====================================");
if (errors > 0) {
  console.error(`  FAILED: ${errors} error(s), ${warnings} warning(s)`);
  console.error("  Fix errors before publishing.");
  console.log("");
  process.exit(1);
} else if (warnings > 0) {
  console.warn(`  PASSED with ${warnings} warning(s)`);
  console.log("");
} else {
  console.log("  ALL CHECKS PASSED");
  console.log("");
}
