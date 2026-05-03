# @wgtechlabs/secrets-engine

[![Secrets Engine – GitHub Repo Banner](https://ghrb.waren.build/banner?header=Secrets+Engine+%F0%9F%94%90&subheader=Defense-in-depth+encrypted+secret+storage+SDK+for+TypeScript&bg=013B84-016EEA&color=FFFFFF)](https://github.com/wgtechlabs/secrets-engine)
<!-- Created with GitHub Repo Banner by Waren Gonzaga: https://ghrb.waren.build -->

Keep your secrets truly secret. With encrypted names and values, zero friction, and strict security by default, secrets‑engine gives developers defense‑in‑depth without the hassle. It’s a TypeScript SDK for secure secret storage, powered by machine‑bound AES‑256‑GCM and hardened SQLite.

## Features

- **Zero friction** — No passphrase, no setup wizard. Works out of the box.
- **Maximum privacy** — Both key names and values are encrypted. No metadata leakage.
- **Machine-bound** — Encryption keys are derived from machine identity + random keyfile via scrypt.
- **Defense in depth** — Filesystem permission verification, HMAC integrity checks, per-entry unique IVs.
- **Actionable recovery** — Static reset/destroy APIs recover unreadable stores without a successful `open()`.
- **Bun-first, Node-compatible** — Prefers `bun:sqlite` on Bun and falls back to built-in `node:sqlite` on supported Node runtimes. Zero external runtime dependencies.

## Installation

```bash
bun add @wgtechlabs/secrets-engine
npm install @wgtechlabs/secrets-engine
```

On Node, use a runtime with built-in `node:sqlite` support (Node 22.5+; some Node 22 releases may require enabling SQLite support explicitly). Bun remains the primary runtime and uses `bun:sqlite`.

## Quick Start

```typescript
import { SecretsEngine } from "@wgtechlabs/secrets-engine";

// Open or create a store (defaults to ~/.secrets-engine/)
const secrets = await SecretsEngine.open();

// Store secrets with dot-notation namespacing
await secrets.set("openai.apiKey", "sk-...");
await secrets.set("anthropic.apiKey", "sk-ant-...");

// Retrieve
const key = await secrets.get("openai.apiKey"); // "sk-..."

// Check existence (no decryption needed — HMAC lookup)
await secrets.has("openai.apiKey"); // true

// List keys with glob patterns
await secrets.keys("openai.*"); // ["openai.apiKey"]

// Delete
await secrets.delete("openai.apiKey");

// Clean up
await secrets.close();
```

## Storage Location

The SDK resolves the storage directory using this priority order:

| Priority | Option | Path |
|----------|--------|------|
| 1 (highest) | `{ path: "/custom/path" }` | Explicit path |
| 2 | `{ location: "xdg" }` | `~/.config/secrets-engine/` |
| 3 (default) | _(none)_ | `~/.secrets-engine/` |

```typescript
// XDG-aware
const secrets = await SecretsEngine.open({ location: "xdg" });

// Custom path
const secrets = await SecretsEngine.open({ path: "/opt/myapp/secrets" });
```

## API Reference

### `SecretsEngine.open(options?)`

Open or create a secrets store. Returns a `Promise<SecretsEngine>`.

### `SecretsEngine.destroyAtPath(options?)`

Destroy a store at a path without requiring a successful `open()` first. For safety, this only deletes directories that look like a secrets-engine store.

Parameters:

- `options` is optional and uses the same shape as `SecretsEngine.open(options?)`
- `path` can point to an explicit storage directory and takes precedence when provided
- `location` can be used instead of `path` to resolve a preset storage location such as `"xdg"`
- if `options` is omitted, path resolution follows the same defaults as `open()` described in [Storage Location](#storage-location)
- there is no extra `force` flag; deletion is recursive only inside the validated store directory

### `SecretsEngine.resetAtPath(options?)`

Remove a store's contents and immediately recreate a fresh empty store at the same path. For safety, this only deletes directories that look like a secrets-engine store.

Parameters:

- `options` is optional and includes the same base fields as `SecretsEngine.open(options?)`
- `path` can point to an explicit storage directory and takes precedence when provided
- `location` can be used instead of `path` to resolve a preset storage location such as `"xdg"`
- `preserveDirectory` defaults to `true`, which removes the store contents but keeps the storage directory so the store can be recreated in place
- if `options` is omitted, path resolution follows the same defaults as `open()` described in [Storage Location](#storage-location)
- there is no extra `force` flag; reset removes store contents recursively only inside the validated store directory before reopening it

### `secrets.get(key)`

Retrieve a decrypted secret value. Returns `string | null`.

### `secrets.getOrThrow(key)`

Retrieve a decrypted secret, throwing `KeyNotFoundError` if missing.

### `secrets.set(key, value)`

Store an encrypted secret.

### `secrets.has(key)`

Check if a key exists via HMAC hash lookup (no decryption).

### `secrets.delete(key)`

Remove a secret. Returns `true` if deleted, `false` if not found.

### `secrets.keys(pattern?)`

List all key names, optionally filtered by glob pattern (e.g., `"openai.*"`).

### `secrets.destroy()`

**Irreversibly** delete the entire store, keyfile, and directory.

### `secrets.close()`

Close the database connection and release resources. **This method is async and must be awaited.**

Returns a `Promise<void>` that resolves when the database is closed and integrity is finalized.

**Breaking Change (v2.0.0):** This method is now async. Update your code to `await secrets.close()`.

### `secrets.size`

Number of secrets currently stored.

### `secrets.storagePath`

Absolute path to the storage directory.

## Security Model

| Layer | Protection |
|-------|-----------|
| Encryption | AES-256-GCM with unique IV per entry |
| Key derivation | scrypt (N=2¹⁷, r=8, p=1) from machine ID + random keyfile |
| Key name privacy | Both names and values encrypted; HMAC-SHA256 index |
| File permissions | Strict verification on open (700/600/400) |
| Integrity | HMAC-SHA256 of database contents in meta.json |
| Machine binding | Hostname + sorted MAC set + username + random keyfile |

Machine binding compatibility guarantees:

- new stores use a canonical sorted MAC-set binding, so adapter ordering changes do not change the derived identity
- older stores remain compatible through legacy single-MAC fallback candidates when the original MAC is still present
- stores that already include `machineBinding` metadata surface `MACHINE_IDENTITY_CHANGED` when the canonical identity truly changes
- legacy stores without `machineBinding` metadata still open normally, but incompatible identity changes fall back to the generic `INTEGRITY_MISMATCH` subcode

## Error Types

| Error | When |
|-------|------|
| `SecurityError` | File permissions too permissive |
| `IntegrityError` | Metadata, machine binding, or database HMAC verification fails |
| `KeyNotFoundError` | `getOrThrow()` for missing key |
| `DecryptionError` | Corrupted entry or wrong key |
| `InitializationError` | Cannot create store directory |

All errors extend `SecretsEngineError` with a `.code` property.

`IntegrityError` keeps `code === "INTEGRITY_ERROR"` and adds a machine-readable `.subcode` such as:

- `METADATA_MISSING`
- `METADATA_CORRUPTED`
- `DATABASE_MISSING`
- `UNSUPPORTED_VERSION`
- `INTEGRITY_MISMATCH`
- `MACHINE_IDENTITY_CHANGED`
- `CHECKPOINT_FAILED`

## Development

```bash
bun install
bun test
bun run typecheck
bun run lint
```

## License

MIT — WG Tech Labs
