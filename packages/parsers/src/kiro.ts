/**
 * @module @sentinelflow/parsers/kiro
 *
 * Parses Kiro IDE agent configurations from:
 *   1. .kiro/ — Kiro config directory
 *   2. .kiro/steering/ — Steering files (behavioral rules)
 *   3. .kiro/specs/ — Feature specifications
 *   4. kiro.md — Project-level instructions
 *
 * Kiro is AWS's AI IDE that uses a spec-driven development approach
 * with steering files for behavioral rules and specs for feature
 * requirements. Each steering file is a governance-relevant artifact.
 */

import * as fs from "fs";
import * as path from "path";
import matter from "gray-matter";
import {
  createAgent,
  type SentinelFlowAgent,
} from "@sentinelflow/core";
import type { FrameworkParser, ParseResult, ConfigFile } from "./interface";

function safeReadFile(filePath: string): string | null {
  try {
    if (!fs.existsSync(filePath)) return null;
    return fs.readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}

function safeListDir(dirPath: string, extensions: string[]): string[] {
  try {
    if (!fs.existsSync(dirPath) || !fs.statSync(dirPath).isDirectory()) return [];
    return fs.readdirSync(dirPath).filter((f: string) =>
      extensions.some((ext) => f.endsWith(ext))
    );
  } catch {
    return [];
  }
}

export class KiroParser implements FrameworkParser {
  readonly framework = "custom" as const; // Kiro maps to "custom" in our framework enum
  readonly displayName = "Kiro";
  readonly markers = [".kiro", "kiro.md"];

  async detect(rootDir: string): Promise<boolean> {
    return (
      fs.existsSync(path.join(rootDir, ".kiro")) ||
      fs.existsSync(path.join(rootDir, "kiro.md"))
    );
  }

  async parse(rootDir: string): Promise<ParseResult> {
    const agents: SentinelFlowAgent[] = [];
    const configFiles: ConfigFile[] = [];
    const warnings: string[] = [];

    // 1. Parse .kiro/steering/*.md files
    const steeringDir = path.join(rootDir, ".kiro", "steering");
    for (const file of safeListDir(steeringDir, [".md"])) {
      const filePath = path.join(steeringDir, file);
      const content = safeReadFile(filePath);
      if (!content) continue;
      configFiles.push({ path: filePath, content, framework: "custom" });

      try {
        const parsed = matter(content);
        const data = parsed.data as Record<string, unknown>;
        const name = typeof data.name === "string"
          ? data.name
          : path.basename(file, ".md");

        agents.push(createAgent({
          name: `kiro-steering-${name}`,
          framework: "custom",
          description: typeof data.description === "string"
            ? data.description
            : parsed.content.trim().slice(0, 200),
          source_file: filePath,
        }));
      } catch (error: unknown) {
        warnings.push(`Could not parse ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    // 2. Parse .kiro/specs/*.md
    const specsDir = path.join(rootDir, ".kiro", "specs");
    for (const file of safeListDir(specsDir, [".md"])) {
      const filePath = path.join(specsDir, file);
      const content = safeReadFile(filePath);
      if (content) {
        configFiles.push({ path: filePath, content, framework: "custom" });
      }
    }

    // 3. Collect kiro.md
    const kiroMdPath = path.join(rootDir, "kiro.md");
    const kiroMd = safeReadFile(kiroMdPath);
    if (kiroMd) {
      configFiles.push({ path: kiroMdPath, content: kiroMd, framework: "custom" });
    }

    if (agents.length === 0 && configFiles.length > 0) {
      agents.push(createAgent({
        name: "kiro-default",
        framework: "custom",
        description: "Kiro IDE project configuration",
        source_file: configFiles[0]?.path,
      }));
    }

    return { agents, config_files: configFiles, warnings };
  }
}
