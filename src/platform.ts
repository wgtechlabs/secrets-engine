/**
 * Platform utilities — filesystem permissions, machine identity, and path resolution.
 *
 * All OS-specific logic is isolated here so the rest of the codebase remains pure.
 */

import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir, hostname, networkInterfaces, userInfo } from "node:os";
import { join } from "node:path";
import { InitializationError, SecurityError } from "./errors.ts";
import { CONSTANTS } from "./types.ts";
import type { StorageLocation } from "./types.ts";

// ---------------------------------------------------------------------------
// Path Resolution
// ---------------------------------------------------------------------------

/**
 * Resolve the storage directory based on the priority rules from the architecture spec.
 *
 * 1. Explicit path (highest priority)
 * 2. `{ location: "xdg" }` — explicit XDG opt-in
 * 3. Auto-detect: if `XDG_CONFIG_HOME` is set in the environment, use it
 * 4. Home directory default (`~/.secrets-engine/`)
 *
 * This means users who have configured `XDG_CONFIG_HOME` get automatic
 * XDG compliance without passing any options.
 */
export function resolveStoragePath(options?: {
  path?: string;
  location?: StorageLocation;
}): string {
  if (options?.path) {
    return options.path;
  }

  if (options?.location === "xdg") {
    return resolveXdgPath();
  }

  // Auto-detect: respect XDG_CONFIG_HOME when set (Unix convention)
  if (process.platform !== "win32" && process.env.XDG_CONFIG_HOME) {
    return join(process.env.XDG_CONFIG_HOME, "secrets-engine");
  }

  return join(homedir(), CONSTANTS.DIR_NAME);
}

function resolveXdgPath(): string {
  if (process.platform === "win32") {
    const appData = process.env.APPDATA;
    if (!appData) {
      throw new InitializationError("APPDATA environment variable is not set");
    }
    return join(appData, "secrets-engine");
  }

  const xdgConfig = process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config");
  return join(xdgConfig, "secrets-engine");
}

// ---------------------------------------------------------------------------
// Directory & File Bootstrap
// ---------------------------------------------------------------------------

/** Expected permission modes by file. */
const EXPECTED_MODES = {
  directory: 0o700,
  database: 0o600,
  keyfile: 0o400,
  meta: 0o600,
} as const;

/**
 * Ensure the storage directory exists with correct permissions.
 * Creates the directory tree if it does not exist.
 */
export async function ensureDirectory(dirPath: string): Promise<void> {
  try {
    await mkdir(dirPath, { recursive: true, mode: EXPECTED_MODES.directory });
  } catch (error) {
    throw new InitializationError(`Cannot create storage directory at "${dirPath}"`, error);
  }

  if (process.platform !== "win32") {
    await verifyPermission(dirPath, EXPECTED_MODES.directory, "directory");
  }
}

// ---------------------------------------------------------------------------
// Permission Verification
// ---------------------------------------------------------------------------

/**
 * Verify that a filesystem path has the expected permission mode.
 * Throws {@link SecurityError} if the actual mode is more permissive.
 *
 * On Windows, permission checks are skipped because POSIX modes are not applicable.
 */
export async function verifyPermission(
  filePath: string,
  expectedMode: number,
  label: string,
): Promise<void> {
  if (process.platform === "win32") {
    return;
  }

  const fileStat = await stat(filePath);
  const actualMode = fileStat.mode & 0o777;

  if (actualMode !== expectedMode) {
    throw new SecurityError(
      `Insecure ${label} permissions`,
      formatOctal(expectedMode),
      formatOctal(actualMode),
      filePath,
    );
  }
}

function formatOctal(mode: number): string {
  return `0o${mode.toString(8).padStart(3, "0")}`;
}

// ---------------------------------------------------------------------------
// Machine Identity
// ---------------------------------------------------------------------------

/**
 * Collect machine-specific identity components.
 * Combined with the random keyfile, these form the scrypt password.
 *
 * Components: hostname + primary MAC address + OS username
 */
export function getMachineIdentity(): string {
  const host = hostname();
  const mac = getPrimaryMac();
  const user = userInfo().username;

  return `${host}:${mac}:${user}`;
}

/**
 * Retrieve the first non-internal, non-loopback MAC address.
 * Falls back to a deterministic placeholder if no NIC is found.
 */
function getPrimaryMac(): string {
  const interfaces = networkInterfaces();

  for (const entries of Object.values(interfaces)) {
    if (!entries) continue;
    for (const entry of entries) {
      if (!entry.internal && entry.mac && entry.mac !== "00:00:00:00:00:00") {
        return entry.mac;
      }
    }
  }

  return "no-mac-available";
}

// ---------------------------------------------------------------------------
// Keyfile Management
// ---------------------------------------------------------------------------

/**
 * Read or create the random keyfile.
 *
 * - On first run, generates 32 cryptographically random bytes and writes
 *   them to disk with `chmod 400`.
 * - On subsequent runs, reads the existing keyfile after verifying permissions.
 */
export async function ensureKeyfile(dirPath: string): Promise<Buffer> {
  const keyfilePath = join(dirPath, CONSTANTS.KEYFILE_NAME);

  try {
    if (process.platform !== "win32") {
      await verifyPermission(keyfilePath, EXPECTED_MODES.keyfile, "keyfile");
    }
    return await readFile(keyfilePath);
  } catch (error: unknown) {
    if (isFileNotFoundError(error)) {
      return await createKeyfile(keyfilePath);
    }
    throw error;
  }
}

async function createKeyfile(keyfilePath: string): Promise<Buffer> {
  const { randomBytes } = await import("node:crypto");
  const keyfileData = randomBytes(CONSTANTS.KEYFILE_LENGTH);

  await writeFile(keyfilePath, keyfileData, { mode: EXPECTED_MODES.keyfile });

  if (process.platform !== "win32") {
    await chmod(keyfilePath, EXPECTED_MODES.keyfile);
  }

  return keyfileData;
}

// ---------------------------------------------------------------------------
// Meta File (meta.json)
// ---------------------------------------------------------------------------

/**
 * Read `meta.json` from the storage directory.
 * Returns `null` if the file does not exist (first run).
 */
export async function readMetaFile(dirPath: string): Promise<string | null> {
  const metaPath = join(dirPath, CONSTANTS.META_NAME);

  try {
    return await readFile(metaPath, "utf-8");
  } catch (error: unknown) {
    if (isFileNotFoundError(error)) {
      return null;
    }
    throw error;
  }
}

/**
 * Write `meta.json` to the storage directory with correct permissions.
 */
export async function writeMetaFile(dirPath: string, content: string): Promise<void> {
  const metaPath = join(dirPath, CONSTANTS.META_NAME);
  await writeFile(metaPath, content, { mode: EXPECTED_MODES.meta });

  if (process.platform !== "win32") {
    await chmod(metaPath, EXPECTED_MODES.meta);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isFileNotFoundError(error: unknown): boolean {
  return (
    error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

/** Permission modes exported for testing and external validation. */
export const PERMISSION_MODES = EXPECTED_MODES;
