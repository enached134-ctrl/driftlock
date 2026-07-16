// Shared types for DriftLock — the MCP lockfile + drift gate.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** A single tool's pinned surface. */
export interface ToolFingerprint {
  name: string;
  description: string;
  /** Canonicalized JSON Schema of the tool's input. */
  inputSchema: unknown;
  /** sha256 over the canonical {name, description, inputSchema}. */
  hash: string;
}

/** A resource or prompt's pinned surface (lighter than tools). */
export interface EntryFingerprint {
  name: string;
  description: string;
  hash: string;
}

/** The full pinned surface of one MCP server. */
export interface ServerFingerprint {
  /** How driftlock reached the server, for reproducibility. */
  transport: "stdio" | "http";
  /** stdio command / http url — the source of truth for re-fingerprinting. */
  source: string;
  tools: ToolFingerprint[];
  resources: EntryFingerprint[];
  prompts: EntryFingerprint[];
  /** sha256 over the sorted per-entry hashes — the whole-surface fingerprint. */
  surfaceHash: string;
}

/** The committed mcp.lock file. */
export interface Lockfile {
  /** Schema version of the lockfile format itself. */
  lockfileVersion: 1;
  driftlockVersion: string;
  generatedAt: string;
  servers: Record<string, ServerFingerprint>;
}

/** One flagged issue found while diffing or scanning a surface. */
export interface Finding {
  severity: Severity;
  /** Short machine code, e.g. "tool-added", "schema-tightened", "poison.exfil". */
  code: string;
  /** Which server this finding belongs to. */
  server: string;
  /** Which tool (if any). */
  tool?: string;
  /** Human-readable one-line summary. */
  summary: string;
  /** Optional taxonomy tag, e.g. "OWASP-LLM06". */
  tag?: string;
  /** Optional before/after fragments for the report. */
  before?: string;
  after?: string;
}

/** Result of comparing a fresh fingerprint against the lockfile. */
export interface DiffResult {
  findings: Finding[];
  /** True if any finding is at or above the configured fail threshold. */
  failed: boolean;
}
