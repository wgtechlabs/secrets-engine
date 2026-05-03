/**
 * SecretsEngine — the public-facing class that orchestrates all subsystems.
 *
 * Lifecycle:
 *   open() → verify permissions → derive master key → verify integrity
 *           → build key index → ready
 *
 * All public methods are async to allow for future storage adapter extensibility.
 */

import { access, readdir, rm, unlink } from "node:fs/promises";
import { join } from "node:path";
import { decrypt, deriveMasterKey, encrypt, generateSalt, hmac } from "./crypto.ts";
import {
  DecryptionError,
  InitializationError,
  IntegrityError,
  KeyNotFoundError,
} from "./errors.ts";
import { filterKeys } from "./glob.ts";
import { readStoreMeta, updateIntegrity, verifyIntegrity } from "./integrity.ts";
import {
  ensureDirectory,
  ensureKeyfile,
  getMachineIdentityProfile,
  resolveStoragePath,
} from "./platform.ts";
import { SecretStore } from "./store.ts";
import { CONSTANTS } from "./types.ts";
import type { MachineBindingMeta, OpenOptions, ResetOptions, StoreMeta } from "./types.ts";

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

  /** Machine identity metadata stored alongside integrity information. */
  private readonly machineBinding?: MachineBindingMeta;

  /** In-memory index: key_hash → plaintext key name. */
  private readonly keyIndex: Map<string, string> = new Map();

  /** Whether this instance has been closed. */
  private closed = false;

  // -----------------------------------------------------------------------
  // Private constructor — use `SecretsEngine.open()` instead
  // -----------------------------------------------------------------------

  private constructor(
    masterKey: Buffer,
    store: SecretStore,
    dirPath: string,
    salt: string,
    machineBinding?: MachineBindingMeta,
  ) {
    this.masterKey = masterKey;
    this.store = store;
    this.dirPath = dirPath;
    this.salt = salt;
    this.machineBinding = machineBinding;
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

    // 3. Resolve metadata state (existing store or fresh)
    const storeState = await resolveStoreState(dirPath);
    const machineIdentity = getMachineIdentityProfile();

    // 4. Open SQLite database
    const store = await SecretStore.open(dirPath);

    try {
      const { masterKey, machineBinding } = storeState.isNewStore
        ? {
            masterKey: deriveMasterKey(
              machineIdentity.canonical,
              keyfile,
              Buffer.from(storeState.salt, "hex"),
            ),
            machineBinding: createMachineBinding(machineIdentity),
          }
        : await resolveExistingStoreMasterKey(
            keyfile,
            storeState.meta,
            machineIdentity,
            store.filePath,
            () => store.checkpoint(),
          );

      // 5. Build the instance
      const engine = new SecretsEngine(masterKey, store, dirPath, storeState.salt, machineBinding);

      // 6. Build in-memory key index
      engine.buildKeyIndex();

      // 7. Write initial integrity HMAC for new stores
      if (storeState.isNewStore) {
        await updateIntegrity(masterKey, store.filePath, dirPath, storeState.salt, {
          checkpoint: () => store.checkpoint(),
          machineBinding,
        });
      }

      return engine;
    } catch (error) {
      await cleanupFailedOpen(store);
      throw error;
    }
  }

  /**
   * Destroy a store at a path without requiring a successful `open()` first.
   * Refuses to delete directories that do not look like a secrets-engine store.
   */
  static async destroyAtPath(options?: OpenOptions): Promise<void> {
    const dirPath = resolveStoragePath(options);
    await assertRecoveryTarget(dirPath, "destroy");
    await releaseDetachedStore(dirPath);
    await removeDirectoryContents(dirPath);
  }

  /**
   * Reset a store at a path, then immediately reopen it as an empty store.
   * Refuses to delete directories that do not look like a secrets-engine store.
   */
  static async resetAtPath(options?: ResetOptions): Promise<SecretsEngine> {
    const dirPath = resolveStoragePath(options);
    const preserveDirectory = options?.preserveDirectory ?? true;

    await assertRecoveryTarget(dirPath, "reset");
    await releaseDetachedStore(dirPath);
    await removeDirectoryContents(dirPath, preserveDirectory);

    return await SecretsEngine.open(options);
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

    // Update integrity HMAC, checkpointing first to keep store.db and meta.json in sync
    await updateIntegrity(this.masterKey, this.store.filePath, this.dirPath, this.salt, {
      checkpoint: () => this.store.checkpoint(),
      machineBinding: this.machineBinding,
    });
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
      await updateIntegrity(this.masterKey, this.store.filePath, this.dirPath, this.salt, {
        checkpoint: () => this.store.checkpoint(),
        machineBinding: this.machineBinding,
      });
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

    await closeStoreForCleanup(this.store);
    this.keyIndex.clear();
    this.closed = true;

    await removeDirectoryContents(this.dirPath);
  }

  /**
   * Close the database connection and release resources.
   * Checkpoints the WAL and updates integrity HMAC before closing.
   * The instance cannot be used after calling `close()`.
   */
  async close(): Promise<void> {
    if (!this.closed) {
      try {
        this.store.checkpoint();
        await updateIntegrity(this.masterKey, this.store.filePath, this.dirPath, this.salt, {
          machineBinding: this.machineBinding,
        });
      } finally {
        this.store.close();
        this.keyIndex.clear();
        this.closed = true;
      }
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

type StoreState =
  | { readonly isNewStore: true; readonly salt: string }
  | { readonly isNewStore: false; readonly meta: StoreMeta; readonly salt: string };

async function resolveStoreState(dirPath: string): Promise<StoreState> {
  const dbPath = join(dirPath, CONSTANTS.DB_NAME);
  const [meta, dbExists] = await Promise.all([readStoreMeta(dirPath), pathExists(dbPath)]);

  if (!meta) {
    if (!dbExists) {
      return { isNewStore: true, salt: generateSalt().toString("hex") };
    }

    throw new IntegrityError("Metadata file (meta.json) is missing", "METADATA_MISSING");
  }

  if (!dbExists) {
    throw new IntegrityError(`Database file (${CONSTANTS.DB_NAME}) is missing`, "DATABASE_MISSING");
  }

  return { isNewStore: false, meta, salt: meta.salt };
}

async function resolveExistingStoreMasterKey(
  keyfile: Buffer,
  meta: StoreMeta,
  machineIdentity: ReturnType<typeof getMachineIdentityProfile>,
  dbFilePath: string,
  checkpoint: () => void,
): Promise<{ masterKey: Buffer; machineBinding?: MachineBindingMeta }> {
  const salt = Buffer.from(meta.salt, "hex");
  let lastMismatch: IntegrityError | undefined;

  for (const candidate of machineIdentity.candidates) {
    const masterKey = deriveMasterKey(candidate, keyfile, salt);

    try {
      await verifyIntegrity(masterKey, dbFilePath, meta, checkpoint);
      return {
        masterKey,
        machineBinding:
          candidate === machineIdentity.canonical
            ? createMachineBinding(machineIdentity)
            : meta.machineBinding,
      };
    } catch (error) {
      if (error instanceof IntegrityError && error.subcode === "INTEGRITY_MISMATCH") {
        lastMismatch = error;
        continue;
      }

      throw error;
    }
  }

  if (
    meta.machineBinding?.strategy === CONSTANTS.MACHINE_BINDING_STRATEGY &&
    meta.machineBinding.fingerprint !== machineIdentity.fingerprint
  ) {
    throw new IntegrityError(
      "Machine identity changed and the store can no longer be unlocked. Use resetAtPath() or destroyAtPath() to recover.",
      "MACHINE_IDENTITY_CHANGED",
    );
  }

  throw lastMismatch ?? new IntegrityError();
}

function createMachineBinding(
  machineIdentity: ReturnType<typeof getMachineIdentityProfile>,
): MachineBindingMeta {
  return {
    strategy: machineIdentity.strategy,
    fingerprint: machineIdentity.fingerprint,
  };
}

async function cleanupFailedOpen(store: SecretStore): Promise<void> {
  await closeStoreForCleanup(store);
}

async function closeStoreForCleanup(store: SecretStore): Promise<void> {
  try {
    store.checkpoint();
  } catch {
    // Preserve the original open/destroy error if cleanup checkpointing fails.
  }

  try {
    store.close();
  } catch {
    // Preserve the original open/destroy error if close itself fails.
  }

  await waitForHandleRelease();
}

async function assertRecoveryTarget(
  dirPath: string,
  operation: "destroy" | "reset",
): Promise<void> {
  if (!(await pathExists(dirPath))) {
    return;
  }

  const storeMarkers = await Promise.all([
    pathExists(join(dirPath, CONSTANTS.KEYFILE_NAME)),
    pathExists(join(dirPath, CONSTANTS.DB_NAME)),
    pathExists(join(dirPath, CONSTANTS.META_NAME)),
  ]);

  const markerCount = storeMarkers.filter(Boolean).length;
  if (markerCount >= 2) {
    return;
  }

  throw new InitializationError(
    `Refusing to ${operation} path \"${dirPath}\" because it does not look like a secrets-engine store`,
  );
}

async function releaseDetachedStore(dirPath: string): Promise<void> {
  const dbPath = join(dirPath, CONSTANTS.DB_NAME);
  if (!(await pathExists(dbPath))) {
    return;
  }

  let store: SecretStore;
  try {
    store = await SecretStore.open(dirPath);
  } catch {
    return;
  }

  await closeStoreForCleanup(store);
}

async function waitForHandleRelease(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 150));
}

/**
 * Remove directory contents and optionally the directory itself with retry logic.
 * More reliable than recursive `rm` on Windows where SQLite WAL files may briefly
 * retain OS-level handles after close.
 */
async function removeDirectoryContents(dirPath: string, preserveDirectory = false): Promise<void> {
  if (!(await pathExists(dirPath))) {
    return;
  }

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

      if (!preserveDirectory) {
        await rm(dirPath, { force: true, recursive: true });
      }

      return;
    } catch (error: unknown) {
      if (
        error instanceof Error &&
        "code" in error &&
        (error as NodeJS.ErrnoException).code === "ENOENT"
      ) {
        return;
      }

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

async function pathExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}
