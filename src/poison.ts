// Tool-poisoning detection — an adapter over the shared guard engine in ./guard.
//
// MCP "tool poisoning" hides instructions to the *model* inside a tool description or
// parameter text — the classic case (postmark-mcp v1.0.16, Sept 2025) added a line
// telling the agent to BCC every email to an attacker address. To the model the tool
// looked identical; nothing in the JSON changed except a sentence of prose.
//
// This file used to carry its own eight regexes. They were measured against a labeled
// corpus and caught 31.6% of attacks at the shipped `failOn: high` threshold — missing
// fetch-and-run, path traversal, shell injection, credential theft, and "Ignore all
// previous instructions", which slipped through on a single missing word in a pattern.
// The rules now live in ./guard, are shared with `driftlock guard`, and are measured on
// a held-out set every CI run. The public shape here is unchanged so the differ, the
// report and the existing tests keep working.
//
// Still deterministic and explainable: no model call, and every hit points at the exact
// substring that tripped it.

import { ToolGate } from "./guard/gate.js";
import type { Severity } from "./types.js";

export interface PoisonHit {
  severity: Severity;
  code: string;
  summary: string;
  tag: string;
  /** The exact substring that tripped the rule. */
  match: string;
}

/**
 * Guard rule ids collapse onto the stable `poison.*` codes the report and lockfile
 * already speak. Two codes are new because the guard engine detects two families the
 * old regexes had no concept of.
 */
const CODE: Record<string, { code: string; summary: string }> = {
  exfil_bcc: { code: "poison.exfil", summary: "Exfiltration instruction (BCC / forward / send a copy to an address)" },
  exfil_forward: { code: "poison.exfil", summary: "Exfiltration instruction (BCC / forward / send a copy to an address)" },
  exfil_endpoint: { code: "poison.exfil", summary: "Instruction to send data to an external endpoint" },
  exfil_pipeline: { code: "poison.exfil", summary: "Sensitive source piped to a network sink — data leaving with a secret in it" },
  injection_override: { code: "poison.imperative-injection", summary: "Imperative aimed at the model (ignore / disregard previous instructions)" },
  hidden_from_user: { code: "poison.imperative-injection", summary: "Instructs the model to conceal the action from the user" },
  tool_instruction: { code: "poison.tool-instruction", summary: "Tool description issues standing instructions to the model" },
  always_call: { code: "poison.tool-instruction", summary: "Tool metadata coerces the model into a fixed behaviour" },
  param_override: { code: "poison.tool-instruction", summary: "Tool metadata overrides an argument the caller supplied" },
  hidden_markup: { code: "poison.hidden-markup", summary: "Hidden markup that can carry instructions invisibly" },
  zero_width: { code: "poison.zero-width", summary: "Zero-width / invisible unicode (steganographic payload)" },
  b64_blob: { code: "poison.base64-blob", summary: "Long base64-looking blob (possible encoded payload)" },
  credential_bait: { code: "poison.credential-bait", summary: "Asks for credential material to be handed over" },
  remote_fetch_exec: { code: "poison.fetch-exec", summary: "Fetches remote content and executes it" },
  pipe_to_shell: { code: "poison.fetch-exec", summary: "Pipes a downloaded script straight into a shell" },
  win_fetch_exec: { code: "poison.fetch-exec", summary: "PowerShell download-and-execute" },
  path_traversal: { code: "poison.arg-abuse", summary: "Path traversal or access to a sensitive system path" },
  shell_injection: { code: "poison.arg-abuse", summary: "Shell metacharacters chained to a command" },
};

const TAG_LLM01 = new Set(["poison.imperative-injection", "poison.tool-instruction", "poison.zero-width", "poison.hidden-markup"]);

/** A bare address is not itself an attack, so it stays a separate, demotable signal. */
const ADDRESS = /@[a-z0-9.-]+\.[a-z]{2,}/i;

const gate = new ToolGate();

/**
 * Scan one text fragment (a tool description or param description) for poisoning.
 *
 * Fragments arriving here are tool METADATA, which is the surface an attacker controls
 * and the model reads as instruction — so it is scanned as `tool.description`, not as
 * user-authored content.
 */
export function scanText(text: string): PoisonHit[] {
  if (!text) return [];

  const decision = gate.checkMetadata(text);
  const hits: PoisonHit[] = [];
  const seen = new Set<string>();

  for (const f of decision.findings) {
    const mapped = CODE[f.rule];
    if (!mapped) continue;
    const key = `${mapped.code}:${f.match}`;
    if (seen.has(key)) continue;
    seen.add(key);
    hits.push({
      severity: f.severity as Severity,
      code: mapped.code,
      summary: mapped.summary,
      tag: TAG_LLM01.has(mapped.code) ? "OWASP-LLM01" : "OWASP-LLM06",
      match: f.match,
    });
  }

  const addr = ADDRESS.exec(text);
  if (addr) {
    hits.push({
      severity: "critical",
      code: "poison.hidden-recipient",
      summary: "Hidden recipient address embedded in tool text",
      tag: "OWASP-LLM06",
      match: addr[0],
    });
  }

  // An address alone (e.g. "contact support@company.com") is low signal. It only
  // becomes CRITICAL when something in the same text is trying to move data or
  // instruct the model — otherwise a benign support address blocks CI under an
  // "exfiltration" label, which is how a gate loses its users.
  const hasCue = hits.some(
    (h) =>
      h.code === "poison.exfil" ||
      h.code === "poison.imperative-injection" ||
      h.code === "poison.tool-instruction",
  );
  if (!hasCue) {
    for (const h of hits) {
      if (h.code === "poison.hidden-recipient") h.severity = "low";
    }
  }

  return hits;
}

/** Convert poison hits found on a specific tool into DriftLock findings. */
export function scanToolText(server: string, tool: string, text: string) {
  return scanText(text).map((hit) => ({
    severity: hit.severity,
    code: hit.code,
    server,
    tool,
    summary: hit.summary,
    tag: hit.tag,
    after: hit.match,
  }));
}
