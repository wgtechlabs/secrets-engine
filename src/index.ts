/**
 * @wgtechlabs/secrets-engine
 *
 * Bun-first TypeScript SDK for securely storing and managing secrets
 * with zero-friction, machine-bound AES-256-GCM encryption.
 *
 * @packageDocumentation
 */

export { SecretsEngine } from "./engine.ts";

export {
  DecryptionError,
  InitializationError,
  IntegrityError,
  KeyNotFoundError,
  SecretsEngineError,
  SecurityError,
} from "./errors.ts";

export type { OpenOptions, StorageLocation } from "./types.ts";
