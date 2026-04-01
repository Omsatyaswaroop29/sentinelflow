/**
 * sentinelflow init [path]
 *
 * Initializes SentinelFlow governance in a project by creating
 * the .sentinelflow/ directory and a default manifest.
 */

import * as fs from "fs";
import * as path from "path";

const DEFAULT_MANIFEST = `# SentinelFlow Configuration
# https://github.com/omswaroop/sentinelflow

# Governance settings for this project
governance:
  # Who is responsible for AI agents in this project?
  default_owner: ""
  default_team: ""

  # Minimum scan requirements
  require_scan_before_commit: false
  min_severity_to_block: "critical"

  # Compliance standards to enforce
  compliance:
    # - eu-ai-act
    # - soc2
    # - hipaa
    # - iso-42001

# Scanner settings
scanner:
  # Rules to skip (by ID)
  skip_rules: []

  # Additional paths to scan for agent configs
  include_paths: []

  # Paths to exclude from scanning
  exclude_paths:
    - node_modules
    - .git
    - dist
    - build

# Registry settings
registry:
  # Where to store the registry (local = SQLite file)
  backend: local

  # SentinelFlow Cloud URL (for team sync, Phase 2+)
  # cloud_url: https://api.sentinelflow.ai
  # cloud_token: $SENTINELFLOW_TOKEN
`;

export async function initCommand(targetPath: string): Promise<void> {
  const rootDir = path.resolve(targetPath);
  const sfDir = path.join(rootDir, ".sentinelflow");

  if (fs.existsSync(sfDir)) {
    console.log("\n  SentinelFlow already initialized in this project.");
    console.log(`  Config: ${sfDir}/config.yaml`);
    console.log("  Run 'sentinelflow scan' to scan for agents.\n");
    return;
  }

  // Create .sentinelflow/ directory
  fs.mkdirSync(sfDir, { recursive: true });
  fs.mkdirSync(path.join(sfDir, "reports"), { recursive: true });

  // Write default config
  fs.writeFileSync(
    path.join(sfDir, "config.yaml"),
    DEFAULT_MANIFEST,
    "utf-8"
  );

  // Add to .gitignore if it exists
  const gitignorePath = path.join(rootDir, ".gitignore");
  if (fs.existsSync(gitignorePath)) {
    const gitignore = fs.readFileSync(gitignorePath, "utf-8");
    if (!gitignore.includes(".sentinelflow/registry")) {
      fs.appendFileSync(
        gitignorePath,
        "\n# SentinelFlow local registry (config is committed, data is not)\n" +
          ".sentinelflow/agents.json\n" +
          ".sentinelflow/reports.json\n" +
          ".sentinelflow/events.json\n" +
          ".sentinelflow/registry.db\n"
      );
    }
  }

  console.log(`
  \x1b[32m✓\x1b[0m SentinelFlow initialized!

  Created:
    ${sfDir}/config.yaml     — Governance configuration
    ${sfDir}/reports/         — Scan report storage

  Next steps:
    1. Edit .sentinelflow/config.yaml to set your team info
    2. Run \x1b[1msentinelflow scan\x1b[0m to discover agents
    3. Review findings and register agents

  Learn more: https://github.com/omswaroop/sentinelflow
`);
}
