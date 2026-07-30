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
    const f = scan([file("agents/svc.md", `password: "Wq7rZ9kLmP2xY"`)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("isPlaceholderSecret does NOT suppress that real password", () => {
    expect(isPlaceholderSecret("Wq7rZ9kLmP2xY")).toBe(false);
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

// ─── False-NEGATIVE guards: aggressive suppression must NOT hide real secrets ───
//
// The dangerous failure mode of a precision fix is over-correcting so that a
// real secret which merely *contains* a placeholder-ish substring (foo, bar,
// test, a run of repeats) gets silently ignored. A missed real leak is worse
// than a false alarm. These assert the whole-token matching holds the line.

describe("SF-AC-001 — real secrets containing placeholder-ish substrings STILL fire", () => {
  it("flags a real AWS key that contains the substring FOO", () => {
    // AKIA + exactly 16 upper/digit chars; embeds FOO — must NOT be suppressed.
    // (FOO12345QSTUVWXY = 16 chars.)
    const f = scan([file("agents/x.md", `key = "AKIAFOO12345QSTUVWXY"`)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("flags a real-format key containing TEST as a substring", () => {
    const realish = "sk-ant-" + "aTESTb9c2".repeat(10); // 90 chars, embeds 'test'
    const f = scan([file("agents/x.md", `ANTHROPIC_API_KEY=${realish}`)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("flags a real secret containing a 4-char repeat run (7777)", () => {
    const realish = "sk-" + "aB3d7777eF9gH2jK".repeat(2); // repeats by chance, not a mask
    const f = scan([file("agents/x.md", `api_key: "${realish}"`)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it("flags a real internal DB connection string (@db, @host with a real password)", () => {
    const f = scan([file("agents/x.md",
      `DATABASE_URL=postgresql://admin:Xk9f2QpL7wZ@db:5432/production`)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });
});

describe("isPlaceholderSecret — false-negative regression guards", () => {
  it("does NOT treat a long real key as a placeholder just for containing 'foo'", () => {
    expect(isPlaceholderSecret("AKIAFOO12345QSTUVWXY")).toBe(false);
  });
  it("does NOT suppress a key with a chance 4-char repeat", () => {
    expect(isPlaceholderSecret("aB3d7777eF9gH2jKaB3d7777eF9gH2jK")).toBe(false);
  });
  it("does NOT suppress a real password just because 'test' appears mid-string", () => {
    expect(isPlaceholderSecret("Wq7testWithEntropy93x")).toBe(false);
  });
  it("STILL suppresses when the whole value is a dictionary token", () => {
    expect(isPlaceholderSecret("test")).toBe(true);
    expect(isPlaceholderSecret("foo")).toBe(true);
    expect(isPlaceholderSecret("mypassword123")).toBe(true);
  });
  it("STILL suppresses a dictionary token inside a dashed placeholder", () => {
    expect(isPlaceholderSecret("sk-proj-xxxxx")).toBe(true);
  });
  it("does NOT suppress a real internal-service DB URL with a real password", () => {
    expect(isPlaceholderSecret("postgresql://admin:Xk9f2QpL7wZ@db:5432/production")).toBe(false);
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
