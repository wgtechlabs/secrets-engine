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
import type { StoreMeta } from "./types.ts";
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
      throw new IntegrityError(`Integrity checkpoint failed: ${originalMessage}`);
    }
  }

  const dbBytes = Buffer.from(await readFile(dbFilePath));
  const dbHash = sha256(dbBytes);
  return hmac(masterKey, dbHash);
}

/**
 * Verify the database integrity against the stored HMAC.
 * Throws {@link IntegrityError} if the check fails.
 */
export async function verifyIntegrity(
  masterKey: Buffer,
  dbFilePath: string,
  dirPath: string,
  checkpointFn?: () => void,
): Promise<StoreMeta> {
  const metaRaw = await readMetaFile(dirPath);

  if (!metaRaw) {
    throw new IntegrityError("Metadata file (meta.json) is missing");
  }

  let meta: StoreMeta;
  try {
    meta = JSON.parse(metaRaw) as StoreMeta;
  } catch {
    throw new IntegrityError("Metadata file (meta.json) is corrupted");
  }

  if (meta.version !== CONSTANTS.STORE_VERSION) {
    throw new IntegrityError(
      `Unsupported store version: expected "${CONSTANTS.STORE_VERSION}", got "${meta.version}"`,
    );
  }

  const computedHmac = await computeIntegrityHmac(masterKey, dbFilePath, checkpointFn);

  if (computedHmac !== meta.integrity) {
    throw new IntegrityError();
  }

  return meta;
}

/**
 * Write or update the integrity HMAC in `meta.json`.
 */
export async function updateIntegrity(
  masterKey: Buffer,
  dbFilePath: string,
  dirPath: string,
  salt: string,
  checkpointFn?: () => void,
): Promise<void> {
  const integrity = await computeIntegrityHmac(masterKey, dbFilePath, checkpointFn);

  const meta: StoreMeta = {
    version: CONSTANTS.STORE_VERSION,
    salt,
    integrity,
  };

  await writeMetaFile(dirPath, JSON.stringify(meta, null, 2));
}
