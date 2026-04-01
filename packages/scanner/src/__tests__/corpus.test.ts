/**
 * Corpus validation tests — parsers must not crash on real-world fixtures.
 * Finding counts must stay within expected ranges.
 */
import { describe, it, expect } from "vitest";
import * as path from "path";
import * as fs from "fs";

// Import scan from engine directly since we're in the same package
import { scan } from "../engine";

const FIXTURES_DIR = path.resolve(__dirname, "../../../../tests/corpus/fixtures");

interface FixtureExpectation {
  name: string;
  dir: string;
  min_agents: number;
  max_agents: number;
  min_findings: number;
  max_findings: number;
}

const FIXTURES: FixtureExpectation[] = [
  {
    name: "claude-code-basic",
    dir: path.join(FIXTURES_DIR, "claude-code-basic"),
    min_agents: 1,
    max_agents: 5,
    min_findings: 2,
    max_findings: 40,
  },
  {
    name: "cursor-mdc",
    dir: path.join(FIXTURES_DIR, "cursor-mdc"),
    min_agents: 1,
    max_agents: 5,
    min_findings: 0,
    max_findings: 25,
  },
  {
    name: "langchain-agent",
    dir: path.join(FIXTURES_DIR, "langchain-agent"),
    min_agents: 1,
    max_agents: 4,
    min_findings: 1,
    max_findings: 25,
  },
  {
    name: "crewai-crew",
    dir: path.join(FIXTURES_DIR, "crewai-crew"),
    min_agents: 1,
    max_agents: 5,
    min_findings: 1,
    max_findings: 25,
  },
  {
    name: "multi-framework",
    dir: path.join(FIXTURES_DIR, "multi-framework"),
    min_agents: 1,
    max_agents: 8,
    min_findings: 2,
    max_findings: 40,
  },
  {
    name: "malformed-configs (crash resistance)",
    dir: path.join(FIXTURES_DIR, "malformed"),
    min_agents: 0,
    max_agents: 3,
    min_findings: 0,
    max_findings: 25,
  },
];

describe("Corpus validation", () => {
  for (const fixture of FIXTURES) {
    describe(fixture.name, () => {
      it("parser does not crash", async () => {
        if (!fs.existsSync(fixture.dir)) return; // Skip if fixture missing
        const result = await scan({ rootDir: fixture.dir, updateRegistry: false });
        expect(result).toBeDefined();
        expect(result.report).toBeDefined();
      });

      it(`discovers ${fixture.min_agents}-${fixture.max_agents} agents`, async () => {
        if (!fs.existsSync(fixture.dir)) return;
        const result = await scan({ rootDir: fixture.dir, updateRegistry: false });
        expect(result.agents.length).toBeGreaterThanOrEqual(fixture.min_agents);
        expect(result.agents.length).toBeLessThanOrEqual(fixture.max_agents);
      });

      it(`produces ${fixture.min_findings}-${fixture.max_findings} findings`, async () => {
        if (!fs.existsSync(fixture.dir)) return;
        const result = await scan({ rootDir: fixture.dir, updateRegistry: false });
        expect(result.report.findings.length).toBeGreaterThanOrEqual(fixture.min_findings);
        expect(result.report.findings.length).toBeLessThanOrEqual(fixture.max_findings);
      });
    });
  }
});
