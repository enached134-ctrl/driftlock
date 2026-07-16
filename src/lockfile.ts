// Read/write the committed mcp.lock and the driftlock.json config.

import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import type { Severity } from "./types.js";
import type { Lockfile, ServerFingerprint } from "./types.js";
import type { ServerSpec } from "./fingerprint.js";

export const LOCK_PATH = "mcp.lock";
export const CONFIG_PATH = "driftlock.json";
export const DRIFTLOCK_VERSION = "0.1.0";

export interface DriftlockConfig {
  /** Named servers to pin, keyed by the name used in mcp.lock. */
  servers: Record<string, ServerSpec>;
  /** Findings at or above this severity fail CI. Default "high". */
  failOn?: Severity;
}

export async function readConfig(path = CONFIG_PATH): Promise<DriftlockConfig | null> {
  if (!existsSync(path)) return null;
  return JSON.parse(await readFile(path, "utf8")) as DriftlockConfig;
}

export async function readLockfile(path = LOCK_PATH): Promise<Lockfile | null> {
  if (!existsSync(path)) return null;
  return JSON.parse(await readFile(path, "utf8")) as Lockfile;
}

export async function writeLockfile(
  servers: Record<string, ServerFingerprint>,
  path = LOCK_PATH,
): Promise<void> {
  const lock: Lockfile = {
    lockfileVersion: 1,
    driftlockVersion: DRIFTLOCK_VERSION,
    generatedAt: new Date().toISOString(),
    servers,
  };
  await writeFile(path, JSON.stringify(lock, null, 2) + "\n", "utf8");
}
