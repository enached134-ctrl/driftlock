// Deterministic canonicalization + hashing.
//
// The whole product hinges on this: two servers that expose the *same* tool
// surface must hash identically regardless of key order or whitespace, and any
// real change must change the hash. We canonicalize to a stable string, then
// sha256 it.

import { createHash } from "node:crypto";

/**
 * Produce a canonical JSON string with deterministically sorted object keys.
 * Arrays keep their order (order is semantically meaningful in JSON Schema,
 * e.g. `required`, `enum`, `prefixItems`) but object keys are sorted so that
 * `{a,b}` and `{b,a}` hash the same.
 */
export function canonicalStringify(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortValue((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

/** Return the canonicalized *value* (object form) — used to store a stable schema in the lockfile. */
export function canonicalize<T>(value: T): T {
  return sortValue(value) as T;
}

/** sha256 hex of the canonical form of `value`. */
export function hashValue(value: unknown): string {
  return createHash("sha256").update(canonicalStringify(value)).digest("hex");
}

/** Short display form of a hash (first 12 hex chars), like git. */
export function shortHash(hash: string): string {
  return hash.slice(0, 12);
}
