/**
 * Integration tests for the full SecretsEngine lifecycle.
 *
 * These tests use isolated temporary directories to avoid interference.
 */

import { Database } from "bun:sqlite";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { KeyNotFoundError, SecretsEngine } from "../src/index.ts";
import { CONSTANTS } from "../src/types.ts";

let testDir: string;

beforeEach(async () => {
  testDir = await mkdtemp(join(tmpdir(), "secrets-engine-test-"));
});

afterEach(async () => {
  await rm(testDir, { recursive: true, force: true }).catch(() => {});
});

/**
 * Helper function to force a WAL checkpoint using a separate SQLite connection.
 * Used in regression tests to deterministically trigger checkpoint-related race conditions.
 */
function forceCheckpoint(dbPath: string): void {
  const db = new Database(dbPath);
  try {
    db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
  } finally {
    db.close();
  }
}

describe("SecretsEngine.open", () => {
  test("creates a new store with no errors", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    expect(engine).toBeDefined();
    expect(engine.size).toBe(0);
    await engine.close();
  });

  test("reopens an existing store", async () => {
    const engine1 = await SecretsEngine.open({ path: testDir });
    await engine1.set("test.key", "test-value");
    await engine1.close();

    const engine2 = await SecretsEngine.open({ path: testDir });
    const value = await engine2.get("test.key");

    expect(value).toBe("test-value");
    await engine2.close();
  });

  test("preserves secrets across reopens", async () => {
    const engine1 = await SecretsEngine.open({ path: testDir });
    await engine1.set("key.a", "value-a");
    await engine1.set("key.b", "value-b");
    await engine1.set("key.c", "value-c");
    await engine1.close();

    const engine2 = await SecretsEngine.open({ path: testDir });

    expect(await engine2.get("key.a")).toBe("value-a");
    expect(await engine2.get("key.b")).toBe("value-b");
    expect(await engine2.get("key.c")).toBe("value-c");
    expect(engine2.size).toBe(3);
    await engine2.close();
  });

  test("integrity verification succeeds after WAL checkpoint on reopen", async () => {
    // Regression test for WAL checkpoint race condition
    // Deterministically forces the condition by manually checkpointing the WAL
    // between close and reopen to ensure the test reliably validates the fix
    const dbPath = join(testDir, CONSTANTS.DB_NAME);

    const engine1 = await SecretsEngine.open({ path: testDir });
    await engine1.set("test.key", "test-value");
    await engine1.close();

    // Force a checkpoint using a separate connection to deterministically
    // trigger the race condition that this fix addresses
    forceCheckpoint(dbPath);

    // This should not throw IntegrityError
    const engine2 = await SecretsEngine.open({ path: testDir });
    expect(await engine2.get("test.key")).toBe("test-value");

    // Update the value and reopen again with another forced checkpoint
    await engine2.set("test.key", "updated-value");
    await engine2.close();

    forceCheckpoint(dbPath);

    // This should also not throw IntegrityError
    const engine3 = await SecretsEngine.open({ path: testDir });
    expect(await engine3.get("test.key")).toBe("updated-value");
    await engine3.close();
  });
});

describe("set / get", () => {
  test("stores and retrieves a secret", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await engine.set("openai.apiKey", "sk-abc123");
    const value = await engine.get("openai.apiKey");

    expect(value).toBe("sk-abc123");
    await engine.close();
  });

  test("returns null for non-existent key", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    const value = await engine.get("nonexistent");

    expect(value).toBeNull();
    await engine.close();
  });

  test("overwrites existing key", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await engine.set("key", "original");
    await engine.set("key", "updated");
    const value = await engine.get("key");

    expect(value).toBe("updated");
    await engine.close();
  });

  test("handles empty string values", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await engine.set("empty", "");
    const value = await engine.get("empty");

    expect(value).toBe("");
    await engine.close();
  });

  test("handles unicode values", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    const unicode = "🔐 senha secreta 日本語";
    await engine.set("unicode.key", unicode);
    const value = await engine.get("unicode.key");

    expect(value).toBe(unicode);
    await engine.close();
  });

  test("handles long values", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    const longValue = "x".repeat(10_000);
    await engine.set("long.key", longValue);
    const value = await engine.get("long.key");

    expect(value).toBe(longValue);
    await engine.close();
  });
});

describe("getOrThrow", () => {
  test("returns value for existing key", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await engine.set("exists", "value");
    const value = await engine.getOrThrow("exists");

    expect(value).toBe("value");
    await engine.close();
  });

  test("throws KeyNotFoundError for missing key", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await expect(engine.getOrThrow("missing")).rejects.toThrow(KeyNotFoundError);
    await engine.close();
  });
});

describe("has", () => {
  test("returns true for existing key", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await engine.set("exists", "value");

    expect(await engine.has("exists")).toBe(true);
    await engine.close();
  });

  test("returns false for non-existent key", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    expect(await engine.has("missing")).toBe(false);
    await engine.close();
  });
});

describe("delete", () => {
  test("removes an existing key", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await engine.set("to-delete", "value");
    const deleted = await engine.delete("to-delete");

    expect(deleted).toBe(true);
    expect(await engine.has("to-delete")).toBe(false);
    expect(await engine.get("to-delete")).toBeNull();
    await engine.close();
  });

  test("returns false for non-existent key", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    const deleted = await engine.delete("nonexistent");

    expect(deleted).toBe(false);
    await engine.close();
  });

  test("persists deletion across reopens", async () => {
    const engine1 = await SecretsEngine.open({ path: testDir });
    await engine1.set("key", "value");
    await engine1.delete("key");
    await engine1.close();

    const engine2 = await SecretsEngine.open({ path: testDir });

    expect(await engine2.has("key")).toBe(false);
    await engine2.close();
  });
});

describe("keys", () => {
  test("returns empty array for empty store", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    const keys = await engine.keys();

    expect(keys).toEqual([]);
    await engine.close();
  });

  test("returns all keys sorted", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await engine.set("c.key", "v");
    await engine.set("a.key", "v");
    await engine.set("b.key", "v");

    const keys = await engine.keys();

    expect(keys).toEqual(["a.key", "b.key", "c.key"]);
    await engine.close();
  });

  test("filters keys by glob pattern", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await engine.set("openai.apiKey", "sk-1");
    await engine.set("openai.orgId", "org-1");
    await engine.set("anthropic.apiKey", "sk-2");

    const openaiKeys = await engine.keys("openai.*");

    expect(openaiKeys).toEqual(["openai.apiKey", "openai.orgId"]);
    await engine.close();
  });

  test("returns empty for non-matching pattern", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await engine.set("openai.apiKey", "sk-1");

    const keys = await engine.keys("nonexistent.*");

    expect(keys).toEqual([]);
    await engine.close();
  });
});

describe("destroy", () => {
  test("removes the entire storage directory", async () => {
    const engine = await SecretsEngine.open({ path: testDir });
    await engine.set("key", "value");

    await engine.destroy();

    const { existsSync } = await import("node:fs");
    expect(existsSync(testDir)).toBe(false);
  });
});

describe("size", () => {
  test("reflects number of stored secrets", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    expect(engine.size).toBe(0);

    await engine.set("a", "1");
    expect(engine.size).toBe(1);

    await engine.set("b", "2");
    expect(engine.size).toBe(2);

    await engine.delete("a");
    expect(engine.size).toBe(1);

    await engine.close();
  });
});

describe("storagePath", () => {
  test("returns the configured path", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    expect(engine.storagePath).toBe(testDir);
    await engine.close();
  });
});

describe("closed instance guard", () => {
  test("throws on operations after close()", async () => {
    const engine = await SecretsEngine.open({ path: testDir });
    await engine.close();

    expect(engine.get("key")).rejects.toThrow("closed");
    expect(engine.set("key", "value")).rejects.toThrow("closed");
    expect(engine.has("key")).rejects.toThrow("closed");
    expect(engine.delete("key")).rejects.toThrow("closed");
    expect(engine.keys()).rejects.toThrow("closed");
  });
});

describe("dot-notation namespacing", () => {
  test("supports multi-level nesting", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await engine.set("provider.openai.v1.apiKey", "sk-deep");
    const value = await engine.get("provider.openai.v1.apiKey");

    expect(value).toBe("sk-deep");
    await engine.close();
  });

  test("treats different namespaces as independent", async () => {
    const engine = await SecretsEngine.open({ path: testDir });

    await engine.set("openai.apiKey", "sk-openai");
    await engine.set("anthropic.apiKey", "sk-anthropic");

    expect(await engine.get("openai.apiKey")).toBe("sk-openai");
    expect(await engine.get("anthropic.apiKey")).toBe("sk-anthropic");
    await engine.close();
  });
});
