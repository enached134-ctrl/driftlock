import { BUILTIN_RULES, isContentArg, isInstructionShaped } from "./rules.js";
import { Scanner } from "./scanner.js";
import {
  SEVERITY_RANK,
  type Action,
  type ArgConstraint,
  type Decision,
  type Finding,
  type Policy,
  type Severity,
  type Surface,
  type ToolCall,
} from "./types.js";

export interface GateOptions {
  policy?: Policy;
  /** Report every overlapping finding instead of the highest-severity one. */
  thorough?: boolean;
  /** Cap on characters scanned per surface. Guards against pathological input. */
  maxScanChars?: number;
}

/** Supports exact names and trailing "*" wildcards, e.g. "fs.*". */
function nameMatches(name: string, patterns: string[] | undefined): boolean {
  if (!patterns) return false;
  for (const p of patterns) {
    if (p === "*") return true;
    if (p.endsWith("*")) {
      if (name.startsWith(p.slice(0, -1))) return true;
    } else if (p === name) {
      return true;
    }
  }
  return false;
}

/** Walks a JSON value, yielding every string it contains with its dotted path. */
function* walkStrings(value: unknown, path: string, depth = 0): Generator<[string, string]> {
  if (depth > 24) return;
  if (typeof value === "string") {
    yield [path, value];
  } else if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      yield* walkStrings(value[i], `${path}[${i}]`, depth + 1);
    }
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      yield* walkStrings(v, path ? `${path}.${k}` : k, depth + 1);
    }
  }
}

function getPath(obj: unknown, path: string): unknown {
  let cur = obj;
  for (const seg of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

function isEmpty(v: unknown): boolean {
  if (v === undefined || v === null) return true;
  if (typeof v === "string") return v.trim() === "";
  if (Array.isArray(v)) return v.length === 0;
  if (typeof v === "object") return Object.keys(v as object).length === 0;
  return false;
}

export class ToolGate {
  private readonly scanner: Scanner;
  private readonly policy: Policy;
  private readonly thorough: boolean;
  private readonly maxScanChars: number;
  private readonly failOn: Severity;

  constructor(opts: GateOptions = {}) {
    this.policy = opts.policy ?? {};
    this.thorough = opts.thorough ?? false;
    this.maxScanChars = opts.maxScanChars ?? 64_000;
    this.failOn = this.policy.failOn ?? "high";
    this.scanner = new Scanner(
      [...BUILTIN_RULES, ...(this.policy.rules ?? [])],
      this.policy.disable ?? [],
    );
  }

  get ruleCount(): number {
    return this.scanner.ruleCount;
  }

  private scan(text: string, surface: Surface, path: string): Finding[] {
    const t = text.length > this.maxScanChars ? text.slice(0, this.maxScanChars) : text;
    return this.thorough
      ? this.scanner.scanThorough(t, surface, path)
      : this.scanner.scan(t, surface, path);
  }

  private checkArgConstraints(call: ToolCall): Finding[] {
    const out: Finding[] = [];
    const constraints = this.policy.args;
    if (!constraints || call.args === undefined) return out;

    for (const [key, c] of Object.entries(constraints)) {
      const dot = key.indexOf(".");
      if (dot < 0) continue;
      const tool = key.slice(0, dot);
      const argPath = key.slice(dot + 1);
      if (tool !== call.name && tool !== "*") continue;

      const value = getPath(call.args, argPath);
      const violation = this.violates(value, c);
      if (violation) {
        out.push({
          rule: `policy_arg:${argPath}`,
          severity: (c.action ?? "deny") === "deny" ? "critical" : "medium",
          surface: "tool.args",
          path: `args.${argPath}`,
          match: typeof value === "string" ? value.slice(0, 160) : JSON.stringify(value ?? null),
          index: 0,
          message: `Argument "${argPath}" violates policy: ${violation}`,
        });
      }
    }
    return out;
  }

  private violates(value: unknown, c: ArgConstraint): string | null {
    if (c.mustBeEmpty && !isEmpty(value)) return "must be empty";
    if (value === undefined) return null;
    const asText = typeof value === "string" ? value : JSON.stringify(value);
    if (c.mustMatch && !new RegExp(c.mustMatch).test(asText)) return `must match /${c.mustMatch}/`;
    if (c.mustNotMatch && new RegExp(c.mustNotMatch).test(asText)) {
      return `must not match /${c.mustNotMatch}/`;
    }
    if (c.oneOf && !c.oneOf.includes(value as string | number | boolean)) {
      return `must be one of ${JSON.stringify(c.oneOf)}`;
    }
    return null;
  }

  /** Evaluate a tool call. Deterministic, no network, no model. */
  check(call: ToolCall): Decision {
    const t0 = process.hrtime.bigint();
    const findings: Finding[] = [];
    let action: Action = "allow";

    // 1. Policy on the tool name itself. Deny always wins.
    if (nameMatches(call.name, this.policy.deny)) {
      action = "deny";
      findings.push({
        rule: "policy_deny",
        severity: "critical",
        surface: "tool.name",
        path: "name",
        match: call.name,
        index: 0,
        message: `Tool "${call.name}" is denied by policy.`,
      });
    } else if (this.policy.allow && !nameMatches(call.name, this.policy.allow)) {
      action = "deny";
      findings.push({
        rule: "policy_not_allowed",
        severity: "critical",
        surface: "tool.name",
        path: "name",
        match: call.name,
        index: 0,
        message: `Tool "${call.name}" is not on the allow-list.`,
      });
    } else if (nameMatches(call.name, this.policy.review)) {
      action = "review";
      findings.push({
        rule: "policy_review",
        severity: "medium",
        surface: "tool.name",
        path: "name",
        match: call.name,
        index: 0,
        message: `Tool "${call.name}" requires human approval.`,
      });
    }

    // 2. The surfaces every major guardrail skips.
    findings.push(...this.scan(call.name, "tool.name", "name"));
    if (call.description) {
      findings.push(...this.scan(call.description, "tool.description", "description"));
    }
    if (call.schema !== undefined) {
      for (const [p, s] of walkStrings(call.schema, "schema")) {
        findings.push(...this.scan(s, "tool.schema", p));
      }
    }
    if (call.args !== undefined) {
      for (const [p, s] of walkStrings(call.args, "args")) {
        const hits = this.scan(s, "tool.args", p);
        // Text the user asked to have written is content, not instruction. See the
        // note on CONTENT_ARG_KEYS in rules.ts for why this distinction carries most
        // of the engine's precision, and what it deliberately gives up.
        findings.push(
          ...(isContentArg(p) ? hits.filter((f) => !isInstructionShaped(f.rule)) : hits),
        );
      }
    }

    // 3. Declared argument constraints.
    findings.push(...this.checkArgConstraints(call));

    // 4. Resolve.
    let worst: Severity | null = null;
    for (const f of findings) {
      if (!worst || SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity;
    }
    if (action !== "deny" && worst) {
      action = SEVERITY_RANK[worst] >= SEVERITY_RANK[this.failOn] ? "deny" : "review";
    }

    const latencyUs = Number(process.hrtime.bigint() - t0) / 1000;
    return { action, findings, severity: worst, latencyUs };
  }

  /**
   * Scan a raw fragment of tool METADATA — a tool or parameter description lifted
   * out of a server's manifest.
   *
   * Scanned as `tool.description` rather than as an argument on purpose: metadata is
   * the surface the server author controls and the model reads as instruction, so the
   * content-field exemption that protects user-authored prose must not apply here.
   */
  checkMetadata(text: string): Decision {
    const t0 = process.hrtime.bigint();
    const findings = this.scan(text, "tool.description", "description");
    let worst: Severity | null = null;
    for (const f of findings) {
      if (!worst || SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity;
    }
    const action: Action = !worst
      ? "allow"
      : SEVERITY_RANK[worst] >= SEVERITY_RANK[this.failOn]
        ? "deny"
        : "review";
    return {
      action,
      findings,
      severity: worst,
      latencyUs: Number(process.hrtime.bigint() - t0) / 1000,
    };
  }

  /** Scan free text (e.g. a tool's return value) with the same rules. */
  checkOutput(text: string): Decision {
    const t0 = process.hrtime.bigint();
    const findings = this.scan(text, "output", "output");
    let worst: Severity | null = null;
    for (const f of findings) {
      if (!worst || SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity;
    }
    const action: Action = !worst
      ? "allow"
      : SEVERITY_RANK[worst] >= SEVERITY_RANK[this.failOn]
        ? "deny"
        : "review";
    return {
      action,
      findings,
      severity: worst,
      latencyUs: Number(process.hrtime.bigint() - t0) / 1000,
    };
  }
}
