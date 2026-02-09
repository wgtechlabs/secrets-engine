/**
 * Cryptographic primitives — master key derivation, AES-256-GCM encrypt/decrypt, HMAC.
 *
 * All crypto operations are centralized here. Nothing outside this module
 * should touch `node:crypto` directly.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { DecryptionError } from "./errors.ts";
import { CONSTANTS } from "./types.ts";

// ---------------------------------------------------------------------------
// Master Key Derivation
// ---------------------------------------------------------------------------

/**
 * Derive the 256-bit master key using scrypt.
 *
 * ```
 * password = machineId + keyfileContents
 * master_key = scrypt(password, salt, { N: 2^17, r: 8, p: 1 })
 * ```
 */
export function deriveMasterKey(machineId: string, keyfile: Buffer, salt: Buffer): Buffer {
  const password = Buffer.concat([Buffer.from(machineId, "utf-8"), keyfile]);

  return scryptSync(password, salt, CONSTANTS.KEY_LENGTH, {
    N: CONSTANTS.SCRYPT_N,
    r: CONSTANTS.SCRYPT_R,
    p: CONSTANTS.SCRYPT_P,
    maxmem: 256 * CONSTANTS.SCRYPT_N * CONSTANTS.SCRYPT_R,
  }) as Buffer;
}

// ---------------------------------------------------------------------------
// AES-256-GCM Encryption / Decryption
// ---------------------------------------------------------------------------

/** Encrypted payload: IV + ciphertext + auth tag. */
export interface EncryptedPayload {
  readonly iv: Buffer;
  readonly ciphertext: Buffer;
}

/**
 * Encrypt plaintext using AES-256-GCM with a unique random IV.
 *
 * Returns the IV and ciphertext (with auth tag appended) as separate buffers
 * so they can be stored in distinct database columns.
 */
export function encrypt(masterKey: Buffer, plaintext: string): EncryptedPayload {
  const iv = randomBytes(CONSTANTS.IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", masterKey, iv);

  const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);

  const authTag = cipher.getAuthTag();

  return {
    iv,
    ciphertext: Buffer.concat([encrypted, authTag]),
  };
}

/**
 * Decrypt an AES-256-GCM ciphertext.
 *
 * Expects the auth tag to be appended to the ciphertext (last 16 bytes).
 * Throws {@link DecryptionError} on any failure.
 */
export function decrypt(
  masterKey: Buffer,
  iv: Buffer,
  ciphertext: Buffer,
  keyHash?: string,
): string {
  if (ciphertext.length < CONSTANTS.AUTH_TAG_LENGTH) {
    throw new DecryptionError("Ciphertext too short to contain auth tag", keyHash);
  }

  const authTag = ciphertext.subarray(ciphertext.length - CONSTANTS.AUTH_TAG_LENGTH);
  const encrypted = ciphertext.subarray(0, ciphertext.length - CONSTANTS.AUTH_TAG_LENGTH);

  try {
    const decipher = createDecipheriv("aes-256-gcm", masterKey, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf-8");
  } catch (error) {
    throw new DecryptionError(
      error instanceof Error ? error.message : "Unknown decryption error",
      keyHash,
    );
  }
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

/**
 * Compute HMAC-SHA256 of data using the master key.
 * Used for:
 * - Key name hashing (database primary key)
 * - Database integrity verification
 */
export function hmac(masterKey: Buffer, data: string | Buffer): string {
  return createHmac("sha256", masterKey).update(data).digest("hex");
}

// ---------------------------------------------------------------------------
// SHA-256 Hashing
// ---------------------------------------------------------------------------

/**
 * Compute SHA-256 hash of arbitrary data.
 * Used primarily for generating the database content hash for integrity checks.
 */
export function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

// ---------------------------------------------------------------------------
// Random Bytes
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically secure random salt.
 */
export function generateSalt(): Buffer {
  return randomBytes(CONSTANTS.SALT_LENGTH);
}
