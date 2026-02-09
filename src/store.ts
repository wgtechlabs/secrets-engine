/**
 * SQLite storage layer — wraps `bun:sqlite` with the encrypted secrets schema.
 *
 * This module owns all database I/O. No SQL escapes this file.
 */

import { Database } from "bun:sqlite";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { InitializationError } from "./errors.ts";
import { CONSTANTS } from "./types.ts";
import type { EncryptedEntry } from "./types.ts";

// ---------------------------------------------------------------------------
// Schema DDL
// ---------------------------------------------------------------------------

const CREATE_SECRETS_TABLE = `
  CREATE TABLE IF NOT EXISTS secrets (
    key_hash  TEXT PRIMARY KEY,
    key_enc   BLOB NOT NULL,
    iv        BLOB NOT NULL,
    cipher    BLOB NOT NULL,
    created   INTEGER NOT NULL,
    updated   INTEGER NOT NULL
  ) STRICT;
`;

const CREATE_META_TABLE = `
  CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  ) STRICT;
`;

// ---------------------------------------------------------------------------
// Store Class
// ---------------------------------------------------------------------------

/**
 * Low-level SQLite store for encrypted secret entries.
 *
 * All methods are synchronous because `bun:sqlite` is synchronous.
 * The higher-level SecretsEngine wraps these with async semantics where needed.
 */
export class SecretStore {
  private readonly db: Database;

  private constructor(db: Database) {
    this.db = db;
  }

  /**
   * Open (or create) the SQLite database at the given directory.
   * Enables WAL mode and initializes the schema.
   */
  static open(dirPath: string): SecretStore {
    const dbPath = join(dirPath, CONSTANTS.DB_NAME);

    try {
      const db = new Database(dbPath, { create: true });

      db.exec("PRAGMA journal_mode = WAL;");
      db.exec("PRAGMA foreign_keys = ON;");
      db.exec("PRAGMA busy_timeout = 5000;");
      db.exec(CREATE_SECRETS_TABLE);
      db.exec(CREATE_META_TABLE);

      return new SecretStore(db);
    } catch (error) {
      throw new InitializationError(`Cannot open database at "${dbPath}"`, error);
    }
  }

  // -----------------------------------------------------------------------
  // CRUD Operations
  // -----------------------------------------------------------------------

  /** Upsert an encrypted secret entry. Timestamps are managed internally. */
  upsert(entry: Pick<EncryptedEntry, "key_hash" | "key_enc" | "iv" | "cipher">): void {
    const now = Math.floor(Date.now() / 1000);

    const stmt = this.db.prepare(`
      INSERT INTO secrets (key_hash, key_enc, iv, cipher, created, updated)
      VALUES ($key_hash, $key_enc, $iv, $cipher, $created, $updated)
      ON CONFLICT(key_hash) DO UPDATE SET
        key_enc = excluded.key_enc,
        iv      = excluded.iv,
        cipher  = excluded.cipher,
        updated = excluded.updated
    `);

    stmt.run({
      $key_hash: entry.key_hash,
      $key_enc: entry.key_enc,
      $iv: entry.iv,
      $cipher: entry.cipher,
      $created: now,
      $updated: now,
    });
  }

  /** Retrieve a single entry by key hash. Returns `null` if not found. */
  findByHash(keyHash: string): EncryptedEntry | null {
    const stmt = this.db.prepare(
      "SELECT key_hash, key_enc, iv, cipher, created, updated FROM secrets WHERE key_hash = ?",
    );
    const row = stmt.get(keyHash) as EncryptedEntry | null;
    return row ?? null;
  }

  /** Retrieve all entries. Used on `open()` for building the key index. */
  findAll(): EncryptedEntry[] {
    const stmt = this.db.prepare(
      "SELECT key_hash, key_enc, iv, cipher, created, updated FROM secrets",
    );
    return stmt.all() as EncryptedEntry[];
  }

  /** Delete an entry by key hash. Returns `true` if a row was deleted. */
  deleteByHash(keyHash: string): boolean {
    const stmt = this.db.prepare("DELETE FROM secrets WHERE key_hash = ?");
    const result = stmt.run(keyHash);
    return result.changes > 0;
  }

  /** Delete all entries. Used by `destroy()`. */
  deleteAll(): void {
    this.db.exec("DELETE FROM secrets");
  }

  /** Get the total number of stored secrets. */
  count(): number {
    const stmt = this.db.prepare("SELECT COUNT(*) as count FROM secrets");
    const row = stmt.get() as { count: number };
    return row.count;
  }

  // -----------------------------------------------------------------------
  // Database File Access
  // -----------------------------------------------------------------------

  /**
   * Read the raw database file bytes for integrity hashing.
   * Uses a filesystem read (not SQLite export) for an exact byte-level hash.
   */
  async readRawBytes(): Promise<Buffer> {
    return Buffer.from(await readFile(this.db.filename));
  }

  /** Full filesystem path to the SQLite database file. */
  get filePath(): string {
    return this.db.filename;
  }

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  /**
   * Checkpoint the WAL file to ensure all data is flushed to the main database.
   * Call before closing if you intend to delete the database files afterward.
   */
  checkpoint(): void {
    this.db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
  }

  /** Close the SQLite database connection. */
  close(): void {
    this.db.close();
  }
}
