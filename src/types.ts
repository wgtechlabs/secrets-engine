/**
 * Shared type definitions for the SecretsEngine SDK.
 */

/** Storage location presets. */
export type StorageLocation = "home" | "xdg";

/** Options for {@link SecretsEngine.open}. */
export interface OpenOptions {
  /** Explicit absolute path to the storage directory. Highest priority. */
  readonly path?: string;
  /** Preset storage location. `"xdg"` resolves to XDG config dir. */
  readonly location?: StorageLocation;
}

/** Internal representation of an encrypted secret row. */
export interface EncryptedEntry {
  readonly key_hash: string;
  readonly key_enc: Buffer;
  readonly iv: Buffer;
  readonly cipher: Buffer;
  readonly created: number;
  readonly updated: number;
}

/** Metadata stored in meta.json. */
export interface StoreMeta {
  readonly version: string;
  readonly salt: string;
  readonly integrity: string;
}

/** Constants used across the SDK. */
export const CONSTANTS = {
  /** AES-256-GCM IV length in bytes. */
  IV_LENGTH: 12,
  /** AES-256-GCM auth tag length in bytes. */
  AUTH_TAG_LENGTH: 16,
  /** scrypt key length in bytes (256 bits). */
  KEY_LENGTH: 32,
  /** scrypt cost parameter (2^17 = 131072). */
  SCRYPT_N: 131072,
  /** scrypt block size. */
  SCRYPT_R: 8,
  /** scrypt parallelization. */
  SCRYPT_P: 1,
  /** Random keyfile size in bytes. */
  KEYFILE_LENGTH: 32,
  /** Salt length in bytes. */
  SALT_LENGTH: 32,
  /** Store metadata format version. */
  STORE_VERSION: "1",
  /** Default directory name. */
  DIR_NAME: ".secrets-engine",
  /** Keyfile filename. */
  KEYFILE_NAME: ".keyfile",
  /** Database filename. */
  DB_NAME: "store.db",
  /** Metadata filename. */
  META_NAME: "meta.json",
} as const;
