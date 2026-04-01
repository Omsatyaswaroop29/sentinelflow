import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { LocalRegistry } from "../registry/local";
import { createAgent } from "../schema/agent";

describe("LocalRegistry", () => {
  let tmpDir: string;
  let registry: LocalRegistry;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sf-test-"));
    registry = new LocalRegistry(tmpDir);
    await registry.initialize();
  });

  afterEach(async () => {
    await registry.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe("initialization", () => {
    it("creates .sentinelflow directory on init", () => {
      expect(fs.existsSync(path.join(tmpDir, ".sentinelflow"))).toBe(true);
    });

    it("is idempotent — multiple init calls don't fail", async () => {
      await registry.initialize();
      await registry.initialize();
      expect(await registry.countAgents()).toBe(0);
    });

    it("loads existing data on init", async () => {
      const agent = createAgent({ name: "persisted", framework: "claude-code" });
      await registry.upsertAgent(agent);
      await registry.close();

      // Create new registry instance pointing to same directory
      const registry2 = new LocalRegistry(tmpDir);
      await registry2.initialize();
      const loaded = await registry2.getAgent(agent.id);
      expect(loaded).not.toBeNull();
      expect(loaded?.name).toBe("persisted");
      await registry2.close();
    });
  });

  describe("agent CRUD", () => {
    it("upserts and retrieves an agent by ID", async () => {
      const agent = createAgent({ name: "test-agent", framework: "claude-code" });
      await registry.upsertAgent(agent);

      const retrieved = await registry.getAgent(agent.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.name).toBe("test-agent");
      expect(retrieved?.framework).toBe("claude-code");
    });

    it("upserts and retrieves an agent by name + framework", async () => {
      const agent = createAgent({ name: "my-agent", framework: "langchain" });
      await registry.upsertAgent(agent);

      const found = await registry.getAgentByName("my-agent", "langchain");
      expect(found).not.toBeNull();
      expect(found?.id).toBe(agent.id);
    });

    it("returns null for non-existent agent", async () => {
      const result = await registry.getAgent("non-existent-id");
      expect(result).toBeNull();
    });

    it("returns null for wrong framework in name lookup", async () => {
      const agent = createAgent({ name: "my-agent", framework: "claude-code" });
      await registry.upsertAgent(agent);

      const found = await registry.getAgentByName("my-agent", "langchain");
      expect(found).toBeNull();
    });

    it("updates existing agent on re-upsert", async () => {
      const agent = createAgent({ name: "test", framework: "claude-code" });
      await registry.upsertAgent(agent);

      agent.description = "updated description";
      await registry.upsertAgent(agent);

      const retrieved = await registry.getAgent(agent.id);
      expect(retrieved?.description).toBe("updated description");
      expect(await registry.countAgents()).toBe(1); // Not duplicated
    });

    it("updates updated_at timestamp on upsert", async () => {
      const agent = createAgent({ name: "test", framework: "claude-code" });
      const originalTime = agent.updated_at;

      // Small delay to ensure different timestamp
      await new Promise((r) => setTimeout(r, 10));
      await registry.upsertAgent(agent);

      const retrieved = await registry.getAgent(agent.id);
      expect(retrieved?.updated_at).not.toBe(originalTime);
    });

    it("deletes an agent", async () => {
      const agent = createAgent({ name: "to-delete", framework: "claude-code" });
      await registry.upsertAgent(agent);
      expect(await registry.countAgents()).toBe(1);

      await registry.deleteAgent(agent.id);
      expect(await registry.countAgents()).toBe(0);
      expect(await registry.getAgent(agent.id)).toBeNull();
    });

    it("throws when deleting non-existent agent", async () => {
      await expect(registry.deleteAgent("fake-id")).rejects.toThrow(
        "Agent not found"
      );
    });

    it("counts agents correctly", async () => {
      expect(await registry.countAgents()).toBe(0);

      await registry.upsertAgent(createAgent({ name: "a", framework: "claude-code" }));
      await registry.upsertAgent(createAgent({ name: "b", framework: "langchain" }));
      await registry.upsertAgent(createAgent({ name: "c", framework: "cursor" }));

      expect(await registry.countAgents()).toBe(3);
    });
  });

  describe("listAgents with filters", () => {
    beforeEach(async () => {
      await registry.upsertAgent(
        createAgent({
          name: "agent-a",
          framework: "claude-code",
          owner: "alice",
          team: "frontend",
          governance: { status: "approved", risk_level: "low" },
        })
      );
      await registry.upsertAgent(
        createAgent({
          name: "agent-b",
          framework: "langchain",
          owner: "bob",
          team: "backend",
          governance: { status: "discovered", risk_level: "high" },
        })
      );
      await registry.upsertAgent(
        createAgent({
          name: "agent-c",
          framework: "claude-code",
          owner: "alice",
          team: "frontend",
          governance: { status: "approved", risk_level: "medium" },
        })
      );
    });

    it("lists all agents without filters", async () => {
      const all = await registry.listAgents();
      expect(all).toHaveLength(3);
    });

    it("filters by framework", async () => {
      const results = await registry.listAgents({ framework: "claude-code" });
      expect(results).toHaveLength(2);
      expect(results.every((a) => a.framework === "claude-code")).toBe(true);
    });

    it("filters by governance status", async () => {
      const results = await registry.listAgents({ status: "approved" });
      expect(results).toHaveLength(2);
    });

    it("filters by risk level", async () => {
      const results = await registry.listAgents({ risk_level: "high" });
      expect(results).toHaveLength(1);
      expect(results[0]?.name).toBe("agent-b");
    });

    it("filters by owner", async () => {
      const results = await registry.listAgents({ owner: "alice" });
      expect(results).toHaveLength(2);
    });

    it("respects limit and offset", async () => {
      const page1 = await registry.listAgents({ limit: 2, offset: 0 });
      const page2 = await registry.listAgents({ limit: 2, offset: 2 });

      expect(page1).toHaveLength(2);
      expect(page2).toHaveLength(1);
    });
  });

  describe("error handling", () => {
    it("throws when operating on uninitialized registry", async () => {
      const uninit = new LocalRegistry(tmpDir);
      // Don't call initialize()
      await expect(uninit.countAgents()).rejects.toThrow("not initialized");
    });
  });
});
