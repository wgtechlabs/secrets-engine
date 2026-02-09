/**
 * Tests for the crypto module — master key derivation, encryption, decryption, HMAC.
 */

import { describe, expect, test } from "bun:test";
import { decrypt, deriveMasterKey, encrypt, generateSalt, hmac, sha256 } from "../src/crypto.ts";
import { DecryptionError } from "../src/errors.ts";

describe("deriveMasterKey", () => {
  test("produces a 32-byte key", () => {
    const salt = generateSalt();
    const key = deriveMasterKey("host:mac:user", Buffer.alloc(32, 0xaa), salt);

    expect(key).toBeInstanceOf(Buffer);
    expect(key.length).toBe(32);
  });

  test("produces deterministic output for same inputs", () => {
    const salt = generateSalt();
    const keyfile = Buffer.alloc(32, 0xbb);

    const key1 = deriveMasterKey("host:mac:user", keyfile, salt);
    const key2 = deriveMasterKey("host:mac:user", keyfile, salt);

    expect(key1.equals(key2)).toBe(true);
  });

  test("produces different output for different machine IDs", () => {
    const salt = generateSalt();
    const keyfile = Buffer.alloc(32, 0xcc);

    const key1 = deriveMasterKey("hostA:mac:user", keyfile, salt);
    const key2 = deriveMasterKey("hostB:mac:user", keyfile, salt);

    expect(key1.equals(key2)).toBe(false);
  });

  test("produces different output for different keyfiles", () => {
    const salt = generateSalt();

    const key1 = deriveMasterKey("host:mac:user", Buffer.alloc(32, 0x01), salt);
    const key2 = deriveMasterKey("host:mac:user", Buffer.alloc(32, 0x02), salt);

    expect(key1.equals(key2)).toBe(false);
  });

  test("produces different output for different salts", () => {
    const keyfile = Buffer.alloc(32, 0xdd);

    const key1 = deriveMasterKey("host:mac:user", keyfile, generateSalt());
    const key2 = deriveMasterKey("host:mac:user", keyfile, generateSalt());

    expect(key1.equals(key2)).toBe(false);
  });
});

describe("encrypt / decrypt", () => {
  const masterKey = deriveMasterKey("test:machine:id", Buffer.alloc(32, 0xff), generateSalt());

  test("round-trips a simple string", () => {
    const plaintext = "sk-abc123";
    const { iv, ciphertext } = encrypt(masterKey, plaintext);
    const result = decrypt(masterKey, iv, ciphertext);

    expect(result).toBe(plaintext);
  });

  test("round-trips an empty string", () => {
    const { iv, ciphertext } = encrypt(masterKey, "");
    const result = decrypt(masterKey, iv, ciphertext);

    expect(result).toBe("");
  });

  test("round-trips unicode content", () => {
    const plaintext = "日本語テスト 🔐🔑";
    const { iv, ciphertext } = encrypt(masterKey, plaintext);
    const result = decrypt(masterKey, iv, ciphertext);

    expect(result).toBe(plaintext);
  });

  test("round-trips long values", () => {
    const plaintext = "x".repeat(10_000);
    const { iv, ciphertext } = encrypt(masterKey, plaintext);
    const result = decrypt(masterKey, iv, ciphertext);

    expect(result).toBe(plaintext);
  });

  test("produces unique IVs per encryption call", () => {
    const { iv: iv1 } = encrypt(masterKey, "same-plaintext");
    const { iv: iv2 } = encrypt(masterKey, "same-plaintext");

    expect(iv1.equals(iv2)).toBe(false);
  });

  test("produces different ciphertext for same plaintext (due to unique IVs)", () => {
    const { ciphertext: c1 } = encrypt(masterKey, "identical");
    const { ciphertext: c2 } = encrypt(masterKey, "identical");

    expect(c1.equals(c2)).toBe(false);
  });

  test("throws DecryptionError on tampered ciphertext", () => {
    const { iv, ciphertext } = encrypt(masterKey, "secret-value");

    // Flip a byte in the ciphertext
    const tampered = Buffer.from(ciphertext);
    const firstByte = tampered[0] ?? 0;
    tampered[0] = firstByte ^ 0xff;

    expect(() => decrypt(masterKey, iv, tampered)).toThrow(DecryptionError);
  });

  test("throws DecryptionError on wrong key", () => {
    const wrongKey = deriveMasterKey("wrong:machine:id", Buffer.alloc(32, 0x00), generateSalt());
    const { iv, ciphertext } = encrypt(masterKey, "secret");

    expect(() => decrypt(wrongKey, iv, ciphertext)).toThrow(DecryptionError);
  });

  test("throws DecryptionError when ciphertext is too short", () => {
    const iv = Buffer.alloc(12);

    expect(() => decrypt(masterKey, iv, Buffer.alloc(5))).toThrow(DecryptionError);
  });
});

describe("hmac", () => {
  const masterKey = Buffer.alloc(32, 0xaa);

  test("produces a hex string", () => {
    const result = hmac(masterKey, "openai.apiKey");

    expect(typeof result).toBe("string");
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  test("produces deterministic output", () => {
    const h1 = hmac(masterKey, "test-key");
    const h2 = hmac(masterKey, "test-key");

    expect(h1).toBe(h2);
  });

  test("produces different output for different inputs", () => {
    const h1 = hmac(masterKey, "key-a");
    const h2 = hmac(masterKey, "key-b");

    expect(h1).not.toBe(h2);
  });

  test("produces different output for different keys", () => {
    const h1 = hmac(Buffer.alloc(32, 0x01), "same-input");
    const h2 = hmac(Buffer.alloc(32, 0x02), "same-input");

    expect(h1).not.toBe(h2);
  });
});

describe("sha256", () => {
  test("produces a 32-byte hash", () => {
    const result = sha256(Buffer.from("test-data"));

    expect(result).toBeInstanceOf(Buffer);
    expect(result.length).toBe(32);
  });

  test("produces deterministic output", () => {
    const data = Buffer.from("deterministic");
    const h1 = sha256(data);
    const h2 = sha256(data);

    expect(h1.equals(h2)).toBe(true);
  });
});

describe("generateSalt", () => {
  test("produces a 32-byte salt", () => {
    const salt = generateSalt();

    expect(salt).toBeInstanceOf(Buffer);
    expect(salt.length).toBe(32);
  });

  test("produces unique salts", () => {
    const s1 = generateSalt();
    const s2 = generateSalt();

    expect(s1.equals(s2)).toBe(false);
  });
});
