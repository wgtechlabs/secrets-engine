/**
 * SecretsEngine — the public-facing class that orchestrates all subsystems.
 *
 * Lifecycle:
 *   open() → verify permissions → derive master key → verify integrity
 *           → build key index → ready
 *
 * All public methods are async to allow for future storage adapter extensibility.
 */

import { readdir, rm, unlink } from "node:fs/promises";
import { join } from "node:path";
import { decrypt, deriveMasterKey, encrypt, generateSalt, hmac } from "./crypto.ts";
import { DecryptionError, KeyNotFoundError } from "./errors.ts";
import { filterKeys } from "./glob.ts";
import { updateIntegrity, verifyIntegrity } from "./integrity.ts";
import {
  ensureDirectory,
  ensureKeyfile,
  getMachineIdentity,
  readMetaFile,
  resolveStoragePath,
} from "./platform.ts";
import { SecretStore } from "./store.ts";
import type { OpenOptions } from "./types.ts";

/**
 * Secure, machine-bound secrets manager.
 *
 * @example
 * ```ts
 * const secrets = await SecretsEngine.open();
 * await secrets.set("openai.apiKey", "sk-...");
 * const key = await secrets.get("openai.apiKey");
 * ```
 */
export class SecretsEngine {
  /** Master encryption key (derived via scrypt). */
  private readonly masterKey: Buffer;

  /** Low-level SQLite store. */
  private readonly store: SecretStore;

  /** Absolute path to the storage directory. */
  private readonly dirPath: string;

  /** Salt used for key derivation (hex-encoded). */
  private readonly salt: string;

  /** In-memory index: key_hash → plaintext key name. */
  private readonly keyIndex: Map<string, string> = new Map();

  /** Whether this instance has been closed. */
  private closed = false;

  // -----------------------------------------------------------------------
  // Private constructor — use `SecretsEngine.open()` instead
  // -----------------------------------------------------------------------

  private constructor(masterKey: Buffer, store: SecretStore, dirPath: string, salt: string) {
    this.masterKey = masterKey;
    this.store = store;
    this.dirPath = dirPath;
    this.salt = salt;
  }

  // -----------------------------------------------------------------------
  // Factory
  // -----------------------------------------------------------------------

  /**
   * Open or create a secrets store.
   *
   * Resolution priority:
   * 1. Explicit `path` option (highest)
   * 2. `location: "xdg"` → XDG config directory
   * 3. Home directory default → `~/.secrets-engine/`
   *
   * On open, the SDK:
   * - Verifies file permissions (refuses if insecure)
   * - Derives the master key from machine ID + keyfile via scrypt
   * - Verifies database integrity via HMAC
   * - Decrypts all key names into an in-memory index
   */
  static async open(options?: OpenOptions): Promise<SecretsEngine> {
    const dirPath = resolveStoragePath(options);

    // 1. Ensure storage directory exists with correct permissions
    await ensureDirectory(dirPath);

    // 2. Read or create the random keyfile
    const keyfile = await ensureKeyfile(dirPath);

    // 3. Resolve salt (existing store or fresh)
    const { salt, isNewStore } = await resolveSalt(dirPath);

    // 4. Derive master key via scrypt
    const machineId = getMachineIdentity();
    const masterKey = deriveMasterKey(machineId, keyfile, Buffer.from(salt, "hex"));

    // 5. Open SQLite database
    const store = SecretStore.open(dirPath);

    try {
      // 6. Verify integrity (skip for brand-new stores)
      if (!isNewStore) {
        await verifyIntegrity(masterKey, store.filePath, dirPath, () => store.checkpoint());
      }

      // 7. Build the instance
      const engine = new SecretsEngine(masterKey, store, dirPath, salt);

      // 8. Build in-memory key index
      engine.buildKeyIndex();

      // 9. Write initial integrity HMAC for new stores
      if (isNewStore) {
        await updateIntegrity(masterKey, store.filePath, dirPath, salt, () => store.checkpoint());
      }

      return engine;
    } catch (error) {
      // Cleanup: close the store if initialization fails
      store.close();
      throw error;
    }
  }

  // -----------------------------------------------------------------------
  // Core API
  // -----------------------------------------------------------------------

  /**
   * Retrieve a decrypted secret value by key.
   *
   * @param key - Dot-notation key name (e.g. `"openai.apiKey"`)
   * @returns The decrypted value, or `null` if the key does not exist
   */
  async get(key: string): Promise<string | null> {
    this.ensureOpen();

    const keyHash = this.hashKey(key);
    const entry = this.store.findByHash(keyHash);

    if (!entry) {
      return null;
    }

    return decrypt(this.masterKey, Buffer.from(entry.iv), Buffer.from(entry.cipher), keyHash);
  }

  /**
   * Retrieve a decrypted secret value, throwing if it does not exist.
   *
   * @param key - Dot-notation key name
   * @throws {KeyNotFoundError} if the key is not in the store
   */
  async getOrThrow(key: string): Promise<string> {
    const value = await this.get(key);
    if (value === null) {
      throw new KeyNotFoundError(key);
    }
    return value;
  }

  /**
   * Store an encrypted secret.
   *
   * @param key - Dot-notation key name (e.g. `"openai.apiKey"`)
   * @param value - Plaintext secret value
   */
  async set(key: string, value: string): Promise<void> {
    this.ensureOpen();

    const keyHash = this.hashKey(key);
    const encryptedKey = encrypt(this.masterKey, key);
    const encryptedValue = encrypt(this.masterKey, value);

    // Pack the key's IV into the key_enc blob: [12-byte IV | ciphertext + authTag]
    const keyEncPacked = Buffer.concat([encryptedKey.iv, encryptedKey.ciphertext]);

    this.store.upsert({
      key_hash: keyHash,
      key_enc: keyEncPacked,
      iv: encryptedValue.iv,
      cipher: encryptedValue.ciphertext,
    });

    // Update in-memory key index
    this.keyIndex.set(keyHash, key);

    // Update integrity HMAC (without checkpoint to avoid write amplification)
    await updateIntegrity(this.masterKey, this.store.filePath, this.dirPath, this.salt);
  }

  /**
   * Check whether a key exists in the store.
   * Uses HMAC hash lookup — no decryption required.
   */
  async has(key: string): Promise<boolean> {
    this.ensureOpen();
    return this.keyIndex.has(this.hashKey(key));
  }

  /**
   * Remove a secret from the store.
   *
   * @returns `true` if the key existed and was deleted, `false` otherwise
   */
  async delete(key: string): Promise<boolean> {
    this.ensureOpen();

    const keyHash = this.hashKey(key);
    const deleted = this.store.deleteByHash(keyHash);

    if (deleted) {
      this.keyIndex.delete(keyHash);
      // Update integrity HMAC (without checkpoint to avoid write amplification)
      await updateIntegrity(this.masterKey, this.store.filePath, this.dirPath, this.salt);
    }

    return deleted;
  }

  /**
   * List all key names, optionally filtered by a glob pattern.
   *
   * Reads from the in-memory index — instant, no DB query.
   *
   * @param pattern - Optional glob pattern (e.g. `"openai.*"`)
   */
  async keys(pattern?: string): Promise<string[]> {
    this.ensureOpen();

    const allKeys = Array.from(this.keyIndex.values());

    if (!pattern) {
      return allKeys.sort();
    }

    return filterKeys(allKeys, pattern).sort();
  }

  /**
   * Securely delete the entire store — database, keyfile, metadata, and directory.
   *
   * **This operation is irreversible.**
   */
  async destroy(): Promise<void> {
    this.ensureOpen();

    // Checkpoint WAL and switch to DELETE mode to release WAL/SHM file handles
    this.store.checkpoint();
    this.store.close();
    this.keyIndex.clear();
    this.closed = true;

    // Allow OS to release file handles
    await new Promise((resolve) => setTimeout(resolve, 150));

    // Remove individual files first (more reliable on Windows than recursive rm)
    await removeDirectoryContents(this.dirPath);
  }

  /**
   * Close the database connection and release resources.
   * Checkpoints the WAL and updates integrity HMAC before closing.
   * The instance cannot be used after calling `close()`.
   */
  async close(): Promise<void> {
    if (!this.closed) {
      // Checkpoint WAL to ensure all data is flushed to the main database file
      this.store.checkpoint();

      // Update integrity HMAC to reflect the final checkpointed state
      await updateIntegrity(this.masterKey, this.store.filePath, this.dirPath, this.salt);

      this.store.close();
      this.keyIndex.clear();
      this.closed = true;
    }
  }

  // -----------------------------------------------------------------------
  // Diagnostics
  // -----------------------------------------------------------------------

  /** Number of secrets currently stored. */
  get size(): number {
    this.ensureOpen();
    return this.keyIndex.size;
  }

  /** Absolute path to the storage directory. */
  get storagePath(): string {
    return this.dirPath;
  }

  // -----------------------------------------------------------------------
  // Private Methods
  // -----------------------------------------------------------------------

  /**
   * Build the in-memory key index by decrypting all stored key names.
   * Called once during `open()`.
   */
  private buildKeyIndex(): void {
    const entries = this.store.findAll();

    for (const entry of entries) {
      try {
        // Unpack key_enc: first 12 bytes = key IV, remainder = ciphertext + authTag
        const keyEncBuf = Buffer.from(entry.key_enc);
        const keyIv = keyEncBuf.subarray(0, 12);
        const keyCipher = keyEncBuf.subarray(12);

        const keyName = decrypt(this.masterKey, keyIv, keyCipher, entry.key_hash);
        this.keyIndex.set(entry.key_hash, keyName);
      } catch (error) {
        if (error instanceof DecryptionError) {
          // Log but don't throw — a single corrupted entry shouldn't prevent opening
          console.warn(
            `[secrets-engine] Skipping corrupted entry: ${entry.key_hash.slice(0, 16)}…`,
          );
          continue;
        }
        throw error;
      }
    }
  }

  /**
   * Compute the HMAC-SHA256 hash of a key name.
   * This hash is the database primary key.
   */
  private hashKey(key: string): string {
    return hmac(this.masterKey, key);
  }

  /**
   * Guard against operations on a closed instance.
   */
  private ensureOpen(): void {
    if (this.closed) {
      throw new Error("SecretsEngine instance is closed");
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Resolve the salt — read from existing `meta.json` or generate a new one.
 */
async function resolveSalt(dirPath: string): Promise<{ salt: string; isNewStore: boolean }> {
  const metaRaw = await readMetaFile(dirPath);

  if (metaRaw) {
    try {
      const meta = JSON.parse(metaRaw) as { salt?: string };
      if (meta.salt) {
        return { salt: meta.salt, isNewStore: false };
      }
    } catch {
      // Corrupted meta.json — treat as new store
    }
  }

  const salt = generateSalt().toString("hex");
  return { salt, isNewStore: true };
}

/**
 * Remove directory contents and the directory itself with retry logic.
 * More reliable than recursive `rm` on Windows where SQLite WAL files
 * may briefly retain OS-level handles after close.
 */
async function removeDirectoryContents(dirPath: string): Promise<void> {
  const maxRetries = 5;
  const retryDelay = 200;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const entries = await readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dirPath, entry.name);
        if (entry.isDirectory()) {
          await rm(fullPath, { recursive: true, force: true });
        } else {
          await unlink(fullPath);
        }
      }

      await rm(dirPath, { force: true, recursive: true });
      return;
    } catch (error: unknown) {
      const isRetryable =
        error instanceof Error &&
        "code" in error &&
        ((error as NodeJS.ErrnoException).code === "EBUSY" ||
          (error as NodeJS.ErrnoException).code === "EPERM");

      if (!isRetryable || attempt === maxRetries - 1) {
        throw error;
      }

      await new Promise((resolve) => setTimeout(resolve, retryDelay * (attempt + 1)));
    }
  }
}
