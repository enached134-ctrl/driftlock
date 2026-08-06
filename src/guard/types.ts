/** Severity of a single finding. Ordered so they can be compared numerically. */
export type Severity = "low" | "medium" | "high" | "critical";

export const SEVERITY_RANK: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** What the gate decided to do about a tool call. */
export type Action = "allow" | "review" | "deny";

/** Where in the tool call a finding was located. */
export type Surface =
  | "tool.name"
  | "tool.description"
  | "tool.schema"
  | "tool.args"
  | "output";

export interface Finding {
  /** Stable rule id, e.g. "exfil_bcc". */
  rule: string;
  severity: Severity;
  surface: Surface;
  /** Dotted path within the surface, e.g. "args.bcc" or "schema.properties.to.description". */
  path: string;
  /** The exact substring that matched — findings must be explainable. */
  match: string;
  /** Character offset of the match within the scanned string. */
  index: number;
  message: string;
  /** OWASP LLM Top-10 tag, where one applies. */
  owasp?: string;
}

export interface Decision {
  action: Action;
  findings: Finding[];
  /** Highest severity seen, or null when clean. */
  severity: Severity | null;
  /** Wall time spent inside the gate, in microseconds. */
  latencyUs: number;
}

/** A tool call as presented to the gate. */
export interface ToolCall {
  name: string;
  /** The tool's advertised description — the classic tool-poisoning surface. */
  description?: string;
  /** JSON Schema for the tool's parameters. */
  schema?: unknown;
  /** Arguments the model wants to pass. */
  args?: unknown;
}

/** A deterministic pattern rule. */
export interface Rule {
  id: string;
  severity: Severity;
  /**
   * Source of a RegExp, without flags. Compiled into one combined scanner,
   * so it must not contain capture groups other than non-capturing (?:...).
   */
  pattern: string;
  message: string;
  owasp?: string;
  /** Restrict this rule to specific surfaces. Empty = all surfaces. */
  surfaces?: Surface[];
  /**
   * Optional second-stage check run only on text that already matched.
   * This is how precision is bought without slowing the hot path: the regex
   * stays cheap and permissive, and the expensive discrimination happens on
   * the handful of candidates that survive it.
   */
  verify?: (match: string, context: string) => boolean;
}

/** Policy over which tools may run at all, and with what arguments. */
export interface Policy {
  /** If set, only these tool names may run. Supports "*" suffix wildcards. */
  allow?: string[];
  /** Tool names that are always denied. Takes precedence over allow. */
  deny?: string[];
  /** Tool names that always require human approval. */
  review?: string[];
  /** Per-argument constraints, keyed by "toolName.argPath" (argPath supports dots). */
  args?: Record<string, ArgConstraint>;
  /** Minimum severity that flips the decision to deny. Default "high". */
  failOn?: Severity;
  /** Extra rules appended to the built-ins. */
  rules?: Rule[];
  /** Built-in rule ids to disable, for tuning false positives. */
  disable?: string[];
}

export interface ArgConstraint {
  /** The argument must be absent or empty. */
  mustBeEmpty?: boolean;
  /** The argument's string form must fully match this pattern. */
  mustMatch?: string;
  /** The argument's string form must not contain this pattern. */
  mustNotMatch?: string;
  /** Allowed literal values. */
  oneOf?: (string | number | boolean)[];
  /** Action when violated. Default "deny". */
  action?: Action;
}
