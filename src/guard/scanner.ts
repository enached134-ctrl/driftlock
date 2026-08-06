import { BUILTIN_RULES } from "./rules.js";
import { SEVERITY_RANK, type Finding, type Rule, type Surface } from "./types.js";

/** Longest span a built-in pattern can plausibly match. Drives stream overlap. */
export const MAX_MATCH_SPAN = 256;

function isValidGroupName(id: string): boolean {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(id);
}

/**
 * Compiles many rules into ONE regular expression and scans text in a single
 * pass.
 *
 * Why this shape: the naive design runs N regexes over every string, so cost
 * grows with the rule set and the clean path — which is >99% of traffic — pays
 * for every rule that did not fire. Here the clean path costs one pass
 * regardless of how many rules exist, and per-rule work only happens on the
 * rare text that actually matched.
 *
 * Ordering matters. JS alternation is leftmost-first, so at any given position
 * the first listed alternative wins. Rules are therefore sorted by severity
 * descending, which guarantees a critical rule is never masked by a lower one
 * matching the same span.
 */
export class Scanner {
  private readonly rules: Rule[];
  private readonly byGroup = new Map<string, Rule>();
  private readonly combined: RegExp;
  /** Per-rule regexes, compiled lazily, used only in thorough mode. */
  private individual: { rule: Rule; re: RegExp }[] | null = null;

  constructor(rules: Rule[] = BUILTIN_RULES, disable: string[] = []) {
    const off = new Set(disable);
    this.rules = rules
      .filter((r) => !off.has(r.id))
      .slice()
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

    const parts: string[] = [];
    for (const r of this.rules) {
      if (!isValidGroupName(r.id)) {
        throw new Error(`toolgate: rule id "${r.id}" is not a valid capture-group name`);
      }
      if (this.byGroup.has(r.id)) {
        throw new Error(`toolgate: duplicate rule id "${r.id}"`);
      }
      this.byGroup.set(r.id, r);
      parts.push(`(?<${r.id}>${r.pattern})`);
    }
    // 'd' gives us match indices; 'i' because these are natural-language rules.
    this.combined = new RegExp(parts.join("|"), "gid");
  }

  get ruleCount(): number {
    return this.rules.length;
  }

  private appliesTo(rule: Rule, surface: Surface): boolean {
    return !rule.surfaces || rule.surfaces.length === 0 || rule.surfaces.includes(surface);
  }

  private toFinding(rule: Rule, match: string, index: number, surface: Surface, path: string): Finding {
    return {
      rule: rule.id,
      severity: rule.severity,
      surface,
      path,
      match: match.length > 160 ? `${match.slice(0, 157)}...` : match,
      index,
      message: rule.message,
      ...(rule.owasp ? { owasp: rule.owasp } : {}),
    };
  }

  /**
   * Single-pass scan. Returns at most one finding per matched span; where two
   * rules could match the same span, the higher-severity one is reported.
   */
  scan(text: string, surface: Surface, path: string): Finding[] {
    if (!text) return [];
    const out: Finding[] = [];
    this.combined.lastIndex = 0;
    for (const m of text.matchAll(this.combined)) {
      const groups = m.groups;
      if (!groups) continue;
      for (const [id, value] of Object.entries(groups)) {
        if (value === undefined) continue;
        const rule = this.byGroup.get(id);
        if (!rule) break;
        if (!this.appliesTo(rule, surface)) break;
        if (rule.verify && !rule.verify(value, text)) break;
        out.push(this.toFinding(rule, value, m.index ?? 0, surface, path));
        break;
      }
    }
    return out;
  }

  /**
   * Runs every rule independently, so overlapping matches from different rules
   * are all reported. Costs one pass per rule — use it when you would rather
   * pay latency than miss a second, lower-severity finding on the same span.
   */
  scanThorough(text: string, surface: Surface, path: string): Finding[] {
    if (!text) return [];
    if (!this.individual) {
      this.individual = this.rules.map((rule) => ({
        rule,
        re: new RegExp(rule.pattern, "gid"),
      }));
    }
    const out: Finding[] = [];
    for (const { rule, re } of this.individual) {
      if (!this.appliesTo(rule, surface)) continue;
      re.lastIndex = 0;
      for (const m of text.matchAll(re)) {
        const value = m[0];
        if (rule.verify && !rule.verify(value, text)) continue;
        out.push(this.toFinding(rule, value, m.index ?? 0, surface, path));
      }
    }
    return out.sort((a, b) => a.index - b.index);
  }
}
