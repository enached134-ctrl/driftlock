// Rule-based tool-poisoning heuristics.
//
// MCP "tool poisoning" hides instructions to the *model* inside a tool
// description or parameter text — the classic case (postmark-mcp v1.0.16,
// Sept 2025) added a line telling the agent to BCC every email to an attacker
// address. To the model the tool looked identical; nothing in the JSON changed
// except a sentence of prose.
//
// This is a deterministic, explainable rule engine — NOT an LLM. It scans text
// fragments for known injection shapes and returns findings with a severity and
// an OWASP tag. Every hit points at the exact matched substring so the report
// can highlight it.

import type { Finding, Severity } from "./types.js";

export interface PoisonHit {
  severity: Severity;
  code: string;
  summary: string;
  tag: string;
  /** The exact substring that tripped the rule. */
  match: string;
}

interface Rule {
  code: string;
  severity: Severity;
  tag: string;
  summary: string;
  test: RegExp;
}

// Order matters only for readability; all rules run.
const RULES: Rule[] = [
  {
    code: "poison.exfil",
    severity: "critical",
    tag: "OWASP-LLM06",
    summary: "Exfiltration instruction (BCC / forward / send a copy to an address)",
    test: /\b(bcc|blind\s+copy|forward\s+(?:a\s+)?(?:copy|all)|send\s+(?:a\s+)?copy|also\s+send|cc\b[^.]{0,40}@)/i,
  },
  {
    code: "poison.hidden-recipient",
    severity: "critical",
    tag: "OWASP-LLM06",
    summary: "Hidden recipient address embedded in tool text",
    test: /@[a-z0-9.-]+\.[a-z]{2,}/i,
  },
  {
    code: "poison.imperative-injection",
    severity: "high",
    tag: "OWASP-LLM01",
    summary: "Imperative aimed at the model (ignore/disregard/do not tell/always)",
    test: /\b(ignore\s+(?:the\s+)?(?:previous|above|prior)|disregard\s+(?:all|previous)|do\s+not\s+(?:tell|mention|inform|reveal)|without\s+(?:telling|informing)\s+the\s+user|always\s+(?:include|append|attach|bcc))/i,
  },
  {
    code: "poison.tool-instruction",
    severity: "high",
    tag: "OWASP-LLM06",
    summary: "Text addressed to the AI/assistant inside a tool description",
    test: /\b(as\s+an?\s+ai|you\s+are\s+(?:an?\s+)?(?:ai|assistant|agent)|note\s+to\s+(?:the\s+)?(?:ai|assistant|model|agent)|system\s*:\s)/i,
  },
  {
    code: "poison.hidden-markup",
    severity: "high",
    tag: "OWASP-LLM06",
    summary: "Hidden HTML/markup that can carry instructions invisibly",
    test: /<\s*(?:img|script|iframe|span\s+style\s*=\s*["']?[^"'>]*display\s*:\s*none)/i,
  },
  {
    code: "poison.zero-width",
    severity: "high",
    tag: "OWASP-LLM06",
    summary: "Zero-width / invisible unicode characters (steganographic payload)",
    // zero-width space, ZWNJ, ZWJ, word joiner, LTR/RTL marks, BOM
    test: /[​‌‍⁠‎‏﻿]/,
  },
  {
    code: "poison.base64-blob",
    severity: "low",
    tag: "OWASP-LLM06",
    // ≥64 chars AND not pure-hex, so git SHAs / hex IDs don't trip it.
    summary: "Long base64-looking blob (possible encoded payload)",
    test: /\b(?![a-fA-F0-9]+\b)[A-Za-z0-9+/]{64,}={0,2}\b/,
  },
  {
    code: "poison.credential-bait",
    severity: "high",
    tag: "OWASP-LLM06",
    summary: "Asks the agent to read secrets / env / keys and pass them along",
    test: /\b(api[_\s-]?key|secret|password|\.env\b|environment\s+variable|access\s+token|private\s+key)\b[^.]{0,60}\b(include|send|attach|pass|read|return)/i,
  },
];

/**
 * Scan one text fragment (a tool description or param description) for poisoning.
 * Returns zero or more hits; each hit records the matched substring.
 */
export function scanText(text: string): PoisonHit[] {
  if (!text) return [];
  const hits: PoisonHit[] = [];
  for (const rule of RULES) {
    const m = rule.test.exec(text);
    if (m) {
      hits.push({
        severity: rule.severity,
        code: rule.code,
        summary: rule.summary,
        tag: rule.tag,
        match: m[0],
      });
    }
  }
  // A bare address is only CRITICAL when it co-occurs with an exfil/imperative
  // cue. Alone (e.g. "contact support@company.com"), it's low-signal — demote
  // it so a benign support address never blocks CI with an "exfiltration" label.
  const hasExfilCue = hits.some(
    (h) =>
      h.code === "poison.exfil" ||
      h.code === "poison.imperative-injection" ||
      h.code === "poison.tool-instruction",
  );
  if (!hasExfilCue) {
    for (const h of hits) {
      if (h.code === "poison.hidden-recipient") h.severity = "low";
    }
  }
  return hits;
}

/**
 * Convert poison hits found on a specific tool into DriftLock findings.
 * `onlyNew` filters to text that was ADDED in a diff (the high-signal case:
 * poison introduced by a silent update), by passing the added fragment(s).
 */
export function scanToolText(
  server: string,
  tool: string,
  text: string,
): Finding[] {
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
