/**
 * @module @sentinelflow/parsers/auto-detect
 *
 * Scans a project directory and detects which agent frameworks are present.
 * Returns the appropriate parsers in priority order.
 *
 * Supported frameworks:
 *   1. Claude Code     — .claude/, CLAUDE.md, AGENTS.md
 *   2. Cursor          — .cursor/, .cursorrules
 *   3. Codex/OpenCode  — .codex/, codex.md, .opencode/, .agents/
 *   4. LangChain       — pyproject.toml/requirements.txt with langchain
 *   5. CrewAI          — crew.yaml, agents.yaml, crewai in deps
 *   6. Kiro            — .kiro/, kiro.md
 */

import type { FrameworkParser, ConfigFile } from "./interface";
import { ClaudeCodeParser } from "./claude-code";
import { CursorParser } from "./cursor";
import { CodexParser } from "./codex";
import { LangChainParser } from "./langchain";
import { CrewAIParser } from "./crewai";
import { KiroParser } from "./kiro";

/** All registered parsers — detection runs in this order */
function getAllParsers(): FrameworkParser[] {
  return [
    new ClaudeCodeParser(),
    new CursorParser(),
    new CodexParser(),
    new LangChainParser(),
    new CrewAIParser(),
    new KiroParser(),
  ];
}

export interface DetectionResult {
  detected: FrameworkParser[];
  all_parsers: FrameworkParser[];
}

/**
 * Detect which frameworks are present in the given directory.
 */
export async function detectFrameworks(
  rootDir: string
): Promise<DetectionResult> {
  const allParsers = getAllParsers();
  const detected: FrameworkParser[] = [];

  for (const parser of allParsers) {
    if (await parser.detect(rootDir)) {
      detected.push(parser);
    }
  }

  return { detected, all_parsers: allParsers };
}

/**
 * Parse all detected frameworks and merge results.
 */
export async function parseAll(rootDir: string): Promise<{
  agents: import("@sentinelflow/core").SentinelFlowAgent[];
  config_files: ConfigFile[];
  frameworks: string[];
  warnings: string[];
}> {
  const { detected } = await detectFrameworks(rootDir);

  const allAgents: import("@sentinelflow/core").SentinelFlowAgent[] = [];
  const allConfigFiles: ConfigFile[] = [];
  const allWarnings: string[] = [];
  const frameworks: string[] = [];

  for (const parser of detected) {
    const result = await parser.parse(rootDir);
    allAgents.push(...result.agents);
    allConfigFiles.push(...result.config_files);
    allWarnings.push(...result.warnings);
    frameworks.push(parser.displayName);
  }

  return {
    agents: allAgents,
    config_files: allConfigFiles,
    frameworks,
    warnings: allWarnings,
  };
}
