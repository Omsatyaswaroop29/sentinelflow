import { describe, it, expect } from "vitest";
import type { ConfigFile } from "@sentinelflow/parsers";
import type { RuleContext, EnterpriseFinding } from "../interface";
import {
  hardcodedCredentials,
  isPlaceholderSecret,
  isInExampleContext,
} from "../access-control";

// ─── Helpers ────────────────────────────────────────────────────

function file(filePath: string, content: string): ConfigFile {
  return { path: filePath, content, framework: "claude-code" };
}

function ctx(files: ConfigFile[]): RuleContext {
  return { agents: [], config_files: files, root_dir: "/test" };
}

function scan(files: ConfigFile[]): EnterpriseFinding[] {
  return hardcodedCredentials.evaluate(ctx(files));
}

// ─── The seven real ECC false positives (must NOT fire) ─────────
//
// These are the exact lines SF-AC-001 flagged as "critical" when scanning
// the public affaan-m/ECC repo. Every one is a placeholder or a teaching
// example, not a live secret. This block is the regression guard: if any of
// these starts flagging again, precision has regressed.

describe("SF-AC-001 precision — the seven ECC false positives", () => {
  it("does NOT flag `sk-abc123` labeled // BAD (teaching example)", () => {
    const f = scan([file("agents/code-reviewer.md", `  const apiKey = "sk-abc123";           // BAD`)]);
    expect(f).toHaveLength(0);
  });

  it("does NOT flag user:password@localhost connection strings", () => {
    const f = scan([file("agents/opensource-forker.md",
      `DATABASE_URL=postgresql://user:password@localhost:5432/mydb\nREDIS_URL=redis://localhost:6379`)]);
    expect(f).toHaveLength(0);
  });

  it("does NOT flag `sk-proj-xxxxx` placeholder (cursor rules)", () => {
    const f = scan([file(".cursor/rules/typescript-security.md", `const apiKey = "sk-proj-xxxxx"`)]);
    expect(f).toHaveLength(0);
  });

  it("does NOT flag `sk-proj-xxxxx` placeholder (opencode instructions)", () => {
    const f = scan([file(".opencode/instructions/INSTRUCTIONS.md", `const apiKey = "sk-proj-xxxxx"`)]);
    expect(f).toHaveLength(0);
  });

  it("does NOT flag `sk-proj-xxxxx` / `mypassword123` placeholders (kiro steering)", () => {
    const f = scan([file(".kiro/steering/typescript-security.md",
      `const apiKey = "sk-proj-xxxxx"\nconst dbPassword = "mypassword123"`)]);
    expect(f).toHaveLength(0);
  });

  it("produces ZERO findings across all seven ECC lines combined", () => {
    const f = scan([
      file("agents/code-reviewer.md", `  const apiKey = "sk-abc123";           // BAD`),
      file("agents/opensource-forker.md",
        `DATABASE_URL=postgresql://user:password@localhost:5432/mydb\nREDIS_URL=redis://localhost:6379`),
      file(".cursor/rules/typescript-security.md", `const apiKey = "sk-proj-xxxxx"`),
      file(".opencode/instructions/INSTRUCTIONS.md", `const apiKey = "sk-proj-xxxxx"`),
      file(".kiro/steering/typescript-security.md",
        `const apiKey = "sk-proj-xxxxx"\nconst dbPassword = "mypassword123"`),
    ]);
    expect(f).toHaveLength(0);
  });
});

// ─── Real secrets (MUST still fire) ─────────────────────────────
//
// The failure mode of a precision fix is over-correcting into a scanner that
// misses real leaks — worse than crying wolf. These assert the guards did not
// blunt genuine detection.

describe("SF-AC-001 precision — real secrets still caught", () => {
  it("flags a real-format AWS access key id", () => {
    const f = scan([file("agents/deploy.md", `AWS_ACCESS_KEY_ID=AKIA1B2C3D4E5F6G7H8I`)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("flags a live-looking production postgres connection string", () => {
    const f = scan([file("agents/db.md",
      `DATABASE_URL=postgresql://admin:Xk9f2QpL7w@prod-db.acmecorp.io:5432/main`)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("flags a real-format GitHub token", () => {
    const f = scan([file("agents/ci.md", `token: ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8`)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("flags a genuine-shaped Anthropic key that is NOT a placeholder", () => {
    const realish = "sk-ant-" + "a1B2c3D4".repeat(11); // 88 chars, no repeats/placeholders
    const f = scan([file("agents/llm.md", `ANTHROPIC_API_KEY=${realish}`)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("flags a hardcoded password that is not an obvious placeholder", () => {
    const f = scan([file("agents/svc.md", `password: "Tr0ub4dor&3xK"`)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
});

// ─── Helper unit tests (fast, precise) ──────────────────────────

describe("isPlaceholderSecret", () => {
  it("catches localhost connection strings", () => {
    expect(isPlaceholderSecret("postgresql://user:password@localhost:5432/mydb")).toBe(true);
    expect(isPlaceholderSecret("redis://localhost:6379")).toBe(true);
  });
  it("catches xxxxx / repeated-char masks", () => {
    expect(isPlaceholderSecret("sk-proj-xxxxx")).toBe(true);
    expect(isPlaceholderSecret("aaaa")).toBe(true);
  });
  it("catches dictionary placeholders", () => {
    expect(isPlaceholderSecret("sk-abc123")).toBe(true);
    expect(isPlaceholderSecret("mypassword123")).toBe(true);
    expect(isPlaceholderSecret("changeme")).toBe(true);
  });
  it("catches structural markers", () => {
    expect(isPlaceholderSecret("<YOUR_KEY>")).toBe(true);
    expect(isPlaceholderSecret("${API_KEY}")).toBe(true);
  });
  it("does NOT flag a real production postgres URL", () => {
    expect(isPlaceholderSecret("postgresql://admin:Xk9f2QpL7w@prod-db.acmecorp.io:5432/main")).toBe(false);
  });
  it("does NOT flag a real AWS key id", () => {
    expect(isPlaceholderSecret("AKIA1B2C3D4E5F6G7H8I")).toBe(false);
  });
});

describe("isInExampleContext", () => {
  it("detects // BAD on the same line", () => {
    const content = `const apiKey = "sk-abc123"; // BAD`;
    const idx = content.indexOf("sk-abc123");
    expect(isInExampleContext(content, idx)).toBe(true);
  });
  it("detects a 'never do this' marker on the line above", () => {
    const content = `// Never hardcode secrets:\nconst apiKey = "realvalue"`;
    const idx = content.indexOf("realvalue");
    expect(isInExampleContext(content, idx)).toBe(true);
  });
  it("returns false for a plain assignment with no example marker", () => {
    const content = `const apiKey = "realvalue"`;
    const idx = content.indexOf("realvalue");
    expect(isInExampleContext(content, idx)).toBe(false);
  });
});
