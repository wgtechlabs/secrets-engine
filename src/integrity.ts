/**
 * Integrity manager — HMAC-based tamper detection for the database.
 *
 * On every `open()`, the SDK recomputes the HMAC of the database contents
 * and compares it against the stored value in `meta.json`.
 */

import { readFile } from "node:fs/promises";
import { hmac, sha256 } from "./crypto.ts";
import { IntegrityError } from "./errors.ts";
import { readMetaFile, writeMetaFile } from "./platform.ts";
import type { MachineBindingMeta, StoreMeta } from "./types.ts";
import { CONSTANTS } from "./types.ts";

/**
 * Compute the integrity HMAC for the current database state.
 *
 * ```
 * integrity_hmac = HMAC-SHA256(master_key, SHA256(store.db))
 * ```
 */
export async function computeIntegrityHmac(
  masterKey: Buffer,
  dbFilePath: string,
  checkpointFn?: () => void,
): Promise<string> {
  // Checkpoint WAL to ensure all data is flushed to the main database file
  if (checkpointFn) {
    try {
      checkpointFn();
    } catch (err) {
      const originalMessage = err instanceof Error ? err.message : String(err);
      throw new IntegrityError(
        `Integrity checkpoint failed: ${originalMessage}`,
        "CHECKPOINT_FAILED",
      );
    }
  }

  const dbBytes = Buffer.from(await readFile(dbFilePath));
  const dbHash = sha256(dbBytes);
  return hmac(masterKey, dbHash);
}

export async function readStoreMeta(dirPath: string): Promise<StoreMeta | null> {
  const metaRaw = await readMetaFile(dirPath);
  if (!metaRaw) {
    return null;
  }

  return parseStoreMeta(metaRaw);
}

export async function loadStoreMetaOrThrow(dirPath: string): Promise<StoreMeta> {
  const meta = await readStoreMeta(dirPath);

  if (!meta) {
    throw new IntegrityError("Metadata file (meta.json) is missing", "METADATA_MISSING");
  }

  return meta;
}

/**
 * Verify the database integrity against the stored HMAC.
 * Throws {@link IntegrityError} if the check fails.
 */
export async function verifyIntegrity(
  masterKey: Buffer,
  dbFilePath: string,
  meta: StoreMeta,
  checkpointFn?: () => void,
): Promise<void> {
  assertSupportedStoreVersion(meta);
  const computedHmac = await computeIntegrityHmac(masterKey, dbFilePath, checkpointFn);

  if (computedHmac !== meta.integrity) {
    throw new IntegrityError(undefined, "INTEGRITY_MISMATCH");
  }
}

/**
 * Write or update the integrity HMAC in `meta.json`.
 */
export async function updateIntegrity(
  masterKey: Buffer,
  dbFilePath: string,
  dirPath: string,
  salt: string,
  options: {
    readonly checkpoint?: () => void;
    readonly machineBinding?: MachineBindingMeta;
  } = {},
): Promise<void> {
  const integrity = await computeIntegrityHmac(masterKey, dbFilePath, options.checkpoint);

  const meta: StoreMeta = {
    version: CONSTANTS.STORE_VERSION,
    salt,
    integrity,
    machineBinding: options.machineBinding,
  };

  await writeMetaFile(dirPath, JSON.stringify(meta, null, 2));
}

function parseStoreMeta(metaRaw: string): StoreMeta {
  let meta: unknown;

  try {
    meta = JSON.parse(metaRaw);
  } catch {
    throw new IntegrityError("Metadata file (meta.json) is corrupted", "METADATA_CORRUPTED");
  }

  if (!isStoreMeta(meta)) {
    throw new IntegrityError("Metadata file (meta.json) is corrupted", "METADATA_CORRUPTED");
  }

  assertSupportedStoreVersion(meta);
  return meta;
}

function assertSupportedStoreVersion(meta: StoreMeta): void {
  if (meta.version !== CONSTANTS.STORE_VERSION) {
    throw new IntegrityError(
      `Unsupported store version: expected "${CONSTANTS.STORE_VERSION}", got "${meta.version}"`,
      "UNSUPPORTED_VERSION",
    );
  }
}

function isStoreMeta(value: unknown): value is StoreMeta {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const meta = value as Partial<StoreMeta>;

  return (
    typeof meta.version === "string" &&
    typeof meta.salt === "string" &&
    typeof meta.integrity === "string" &&
    (meta.machineBinding === undefined || isMachineBindingMeta(meta.machineBinding))
  );
}

function isMachineBindingMeta(value: unknown): value is MachineBindingMeta {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const machineBinding = value as Partial<MachineBindingMeta>;
  return (
    typeof machineBinding.strategy === "string" && typeof machineBinding.fingerprint === "string"
  );
}
