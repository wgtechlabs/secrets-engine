/**
 * Tests for the error classes.
 */

import { describe, expect, test } from "bun:test";
import {
  DecryptionError,
  InitializationError,
  IntegrityError,
  KeyNotFoundError,
  SecretsEngineError,
  SecurityError,
} from "../src/errors.ts";

describe("SecretsEngineError hierarchy", () => {
  test("SecurityError is instance of SecretsEngineError and Error", () => {
    const err = new SecurityError("test", "0o700", "0o777", "/tmp");

    expect(err).toBeInstanceOf(SecurityError);
    expect(err).toBeInstanceOf(SecretsEngineError);
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe("SECURITY_ERROR");
    expect(err.name).toBe("SecurityError");
    expect(err.expectedPermission).toBe("0o700");
    expect(err.actualPermission).toBe("0o777");
    expect(err.path).toBe("/tmp");
  });

  test("IntegrityError has correct code and default message", () => {
    const err = new IntegrityError();

    expect(err.code).toBe("INTEGRITY_ERROR");
    expect(err.message).toContain("integrity check failed");
  });

  test("IntegrityError accepts custom message", () => {
    const err = new IntegrityError("custom");

    expect(err.message).toBe("custom");
  });

  test("KeyNotFoundError includes key name in message", () => {
    const err = new KeyNotFoundError("openai.apiKey");

    expect(err.code).toBe("KEY_NOT_FOUND");
    expect(err.message).toContain("openai.apiKey");
  });

  test("DecryptionError includes truncated key hash", () => {
    const err = new DecryptionError("bad data", "abcdef1234567890extra");

    expect(err.code).toBe("DECRYPTION_ERROR");
    expect(err.message).toContain("abcdef1234567890");
    expect(err.keyHash).toBe("abcdef1234567890extra");
  });

  test("DecryptionError works without key hash", () => {
    const err = new DecryptionError("unknown error");

    expect(err.message).toContain("unknown error");
    expect(err.keyHash).toBeUndefined();
  });

  test("InitializationError preserves cause", () => {
    const cause = new Error("EACCES");
    const err = new InitializationError("cannot create dir", cause);

    expect(err.code).toBe("INITIALIZATION_ERROR");
    expect(err.cause).toBe(cause);
  });
});
