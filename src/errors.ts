/**
 * Base error class for all SecretsEngine errors.
 * Provides a consistent error interface with error codes.
 */
export abstract class SecretsEngineError extends Error {
  abstract readonly code: string;

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = this.constructor.name;
  }
}

/**
 * Thrown when filesystem permissions are more permissive than allowed.
 * The SDK refuses to operate when security invariants are violated.
 */
export class SecurityError extends SecretsEngineError {
  readonly code = "SECURITY_ERROR";

  constructor(
    message: string,
    readonly expectedPermission: string,
    readonly actualPermission: string,
    readonly path: string,
  ) {
    super(`${message} — expected ${expectedPermission}, got ${actualPermission} on "${path}"`);
  }
}

/**
 * Thrown when the HMAC integrity check of the database fails.
 * Indicates possible tampering or corruption.
 */
export class IntegrityError extends SecretsEngineError {
  readonly code = "INTEGRITY_ERROR";

  constructor(message = "Database integrity check failed — possible tampering detected") {
    super(message);
  }
}

/**
 * Thrown when a requested key does not exist in the store.
 */
export class KeyNotFoundError extends SecretsEngineError {
  readonly code = "KEY_NOT_FOUND";

  constructor(key: string) {
    super(`Key not found: "${key}"`);
  }
}

/**
 * Thrown when decryption of a stored entry fails.
 * Reports the key hash (not the plaintext name) to avoid leaking secrets.
 */
export class DecryptionError extends SecretsEngineError {
  readonly code = "DECRYPTION_ERROR";

  constructor(
    message: string,
    readonly keyHash?: string,
  ) {
    const detail = keyHash ? ` (entry: ${keyHash.slice(0, 16)}…)` : "";
    super(`Decryption failed${detail}: ${message}`);
  }
}

/**
 * Thrown when the storage directory or files cannot be initialized.
 */
export class InitializationError extends SecretsEngineError {
  readonly code = "INITIALIZATION_ERROR";

  constructor(message: string, cause?: unknown) {
    super(`Initialization failed: ${message}`, { cause });
  }
}
