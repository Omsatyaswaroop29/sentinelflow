/**
 * @module @sentinelflow/parsers
 *
 * Every framework parser implements this interface. Parsers are responsible
 * for detecting whether a framework is present in a project and extracting
 * agent definitions into the universal SentinelFlow schema.
 */

import type { SentinelFlowAgent, AgentFramework } from "@sentinelflow/core";

export interface ParseResult {
  /** Agents discovered and normalized */
  agents: SentinelFlowAgent[];
  /** All config files that were read during parsing */
  config_files: ConfigFile[];
  /** Non-fatal parsing issues */
  warnings: string[];
}

export interface ConfigFile {
  path: string;
  content: string;
  framework: AgentFramework;
}

export interface FrameworkParser {
  /** Which framework this parser handles */
  readonly framework: AgentFramework;

  /** Human-readable name for CLI output */
  readonly displayName: string;

  /** Files/directories that indicate this framework is present */
  readonly markers: string[];

  /** Check if this framework is present in the given directory */
  detect(rootDir: string): Promise<boolean>;

  /** Parse all agents found and return normalized schema */
  parse(rootDir: string): Promise<ParseResult>;
}
