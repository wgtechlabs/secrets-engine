/**
 * Glob-based pattern matching for key filtering.
 *
 * Supports the `*` wildcard only (as used in dot-notation key patterns).
 * No external dependencies.
 */

/**
 * Match a key against a glob pattern.
 *
 * Supports:
 * - `*` — matches any sequence of characters (except `.` when used with dot notation)
 * - `**` — not supported (flat namespace)
 * - Literal characters are matched exactly
 *
 * @example
 * ```ts
 * matchGlob("openai.*", "openai.apiKey")  // true
 * matchGlob("openai.*", "anthropic.key")  // false
 * matchGlob("*.apiKey", "openai.apiKey")  // true
 * ```
 */
export function matchGlob(pattern: string, key: string): boolean {
  const regexStr = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^.]*");

  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(key);
}

/**
 * Filter an array of keys by a glob pattern.
 */
export function filterKeys(keys: string[], pattern: string): string[] {
  return keys.filter((key) => matchGlob(pattern, key));
}
