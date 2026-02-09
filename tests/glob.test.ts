/**
 * Tests for the glob pattern matching module.
 */

import { describe, expect, test } from "bun:test";
import { filterKeys, matchGlob } from "../src/glob.ts";

describe("matchGlob", () => {
  test("matches exact key name", () => {
    expect(matchGlob("openai.apiKey", "openai.apiKey")).toBe(true);
  });

  test("rejects non-matching exact key", () => {
    expect(matchGlob("openai.apiKey", "anthropic.apiKey")).toBe(false);
  });

  test("matches wildcard at end", () => {
    expect(matchGlob("openai.*", "openai.apiKey")).toBe(true);
    expect(matchGlob("openai.*", "openai.orgId")).toBe(true);
  });

  test("wildcard does not cross dot boundaries", () => {
    expect(matchGlob("openai.*", "openai.nested.key")).toBe(false);
  });

  test("matches wildcard at start", () => {
    expect(matchGlob("*.apiKey", "openai.apiKey")).toBe(true);
    expect(matchGlob("*.apiKey", "anthropic.apiKey")).toBe(true);
  });

  test("matches wildcard in middle", () => {
    expect(matchGlob("openai.*.secret", "openai.v1.secret")).toBe(true);
    expect(matchGlob("openai.*.secret", "openai.v2.secret")).toBe(true);
  });

  test("rejects partial matches", () => {
    expect(matchGlob("openai.*", "openai")).toBe(false);
    expect(matchGlob("openai", "openai.apiKey")).toBe(false);
  });

  test("handles multi-segment keys", () => {
    expect(matchGlob("aws.*.secret", "aws.prod.secret")).toBe(true);
    expect(matchGlob("aws.*.*", "aws.prod.secret")).toBe(true);
  });

  test("handles special regex characters in key names", () => {
    expect(matchGlob("key+name.value", "key+name.value")).toBe(true);
    expect(matchGlob("key(1).value", "key(1).value")).toBe(true);
  });
});

describe("filterKeys", () => {
  const keys = [
    "openai.apiKey",
    "openai.orgId",
    "anthropic.apiKey",
    "aws.prod.secret",
    "aws.staging.secret",
    "standalone",
  ];

  test("filters by namespace wildcard", () => {
    expect(filterKeys(keys, "openai.*")).toEqual(["openai.apiKey", "openai.orgId"]);
  });

  test("filters by suffix wildcard", () => {
    expect(filterKeys(keys, "*.apiKey")).toEqual(["openai.apiKey", "anthropic.apiKey"]);
  });

  test("returns empty for no matches", () => {
    expect(filterKeys(keys, "nonexistent.*")).toEqual([]);
  });

  test("returns all matching multi-segment keys", () => {
    expect(filterKeys(keys, "aws.*.*")).toEqual(["aws.prod.secret", "aws.staging.secret"]);
  });
});
