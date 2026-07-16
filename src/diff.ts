// Compare a fresh fingerprint against the pinned lockfile and explain every change.
//
// This is where "silent" changes become loud. We separate benign additive
// change (a new optional field) from the dangerous, easy-to-miss kind:
// a description that gained a sentence, a parameter that flipped from optional
// to required, an enum that quietly narrowed, a type that changed under you.

import { canonicalStringify } from "./canonicalize.js";
import { scanText } from "./poison.js";
import type {
  EntryFingerprint,
  Finding,
  ServerFingerprint,
  ToolFingerprint,
} from "./types.js";

/** Diff one server's fresh surface against its pinned surface. */
export function diffServer(
  server: string,
  pinned: ServerFingerprint,
  fresh: ServerFingerprint,
): Finding[] {
  const findings: Finding[] = [];
  const pinnedTools = byName(pinned.tools);
  const freshTools = byName(fresh.tools);

  const removed = [...pinnedTools.keys()].filter((n) => !freshTools.has(n));
  const added = [...freshTools.keys()].filter((n) => !pinnedTools.has(n));

  // Rename detection: a removed+added pair whose schema+description match exactly.
  const renames = detectRenames(removed, added, pinnedTools, freshTools);
  const renamedFrom = new Set(renames.map((r) => r.from));
  const renamedTo = new Set(renames.map((r) => r.to));

  for (const r of renames) {
    findings.push({
      severity: "high",
      code: "tool-renamed",
      server,
      tool: r.to,
      summary: `Tool renamed "${r.from}" -> "${r.to}" (same surface). Agents keyed on the old name silently break.`,
      before: r.from,
      after: r.to,
    });
  }

  for (const name of removed) {
    if (renamedFrom.has(name)) continue;
    findings.push({
      severity: "high",
      code: "tool-removed",
      server,
      tool: name,
      summary: `Tool "${name}" disappeared from the server. Calls to it will now fail at runtime.`,
      before: name,
    });
  }

  for (const name of added) {
    if (renamedTo.has(name)) continue;
    const t = freshTools.get(name)!;
    findings.push({
      severity: "medium",
      code: "tool-added",
      server,
      tool: name,
      summary: `New tool "${name}" appeared. Review before your agent is allowed to call it.`,
      after: name,
    });
    // A brand-new tool is a prime poisoning vector — scan its text.
    pushPoison(findings, server, name, t.description);
    scanSchemaText(findings, server, name, t.inputSchema);
  }

  // Tools present in both: only care if the hash changed.
  for (const [name, pt] of pinnedTools) {
    const ft = freshTools.get(name);
    if (!ft || pt.hash === ft.hash) continue;

    if (pt.description !== ft.description) {
      const addedText = addedWords(pt.description, ft.description);
      findings.push({
        severity: "high",
        code: "description-changed",
        server,
        tool: name,
        summary: `Tool "${name}" description changed. The model reads this as instructions.`,
        before: pt.description,
        after: ft.description,
      });
      // Poison-scan ONLY the newly added text — the high-signal case.
      pushPoison(findings, server, name, addedText);
    }

    const before = findings.length;
    diffSchema(findings, server, name, pt.inputSchema, ft.inputSchema);
    // Backstop: the hash changed, so SOMETHING changed. If neither the
    // description diff nor diffSchema named it, still fail — the hash is the
    // guarantee, the rules are only the explanation. (Catches nested $defs/
    // allOf/anyOf mutations the structural rules don't walk.)
    if (findings.length === before && pt.description === ft.description) {
      findings.push({
        severity: "high",
        code: "schema-changed",
        server,
        tool: name,
        summary: `Input schema for "${name}" changed in a way DriftLock could not attribute to a specific field. Review before shipping.`,
      });
    }
  }

  // Resources and prompts are attack surface too — a poisoned prompt template
  // or resource description reaches the model just like a tool description.
  diffEntries(findings, server, "resource", pinned.resources, fresh.resources);
  diffEntries(findings, server, "prompt", pinned.prompts, fresh.prompts);

  return findings;
}

/** Diff a list of resources or prompts by name; flag added/removed/changed + poison-scan text. */
function diffEntries(
  findings: Finding[],
  server: string,
  kind: "resource" | "prompt",
  pinned: EntryFingerprint[],
  fresh: EntryFingerprint[],
): void {
  const p = new Map(pinned.map((e) => [e.name, e]));
  const f = new Map(fresh.map((e) => [e.name, e]));
  for (const [name, pe] of p) {
    const fe = f.get(name);
    if (!fe) {
      findings.push({
        severity: "medium",
        code: `${kind}-removed`,
        server,
        tool: name,
        summary: `${cap(kind)} "${name}" was removed.`,
        before: name,
      });
      continue;
    }
    if (fe.hash !== pe.hash) {
      findings.push({
        severity: "high",
        code: `${kind}-changed`,
        server,
        tool: name,
        summary: `${cap(kind)} "${name}" changed. The model reads this text as context/instructions.`,
        before: pe.description,
        after: fe.description,
      });
      for (const hit of scanText(addedWords(pe.description, fe.description) || fe.description)) {
        findings.push({
          severity: hit.severity,
          code: hit.code,
          server,
          tool: name,
          summary: hit.summary,
          tag: hit.tag,
          after: hit.match,
        });
      }
    }
  }
  for (const [name, fe] of f) {
    if (p.has(name)) continue;
    findings.push({
      severity: "medium",
      code: `${kind}-added`,
      server,
      tool: name,
      summary: `New ${kind} "${name}" appeared. Review before trusting it.`,
      after: name,
    });
    for (const hit of scanText(fe.description)) {
      findings.push({ severity: hit.severity, code: hit.code, server, tool: name, summary: hit.summary, tag: hit.tag, after: hit.match });
    }
  }
}

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function byName(tools: ToolFingerprint[]): Map<string, ToolFingerprint> {
  return new Map(tools.map((t) => [t.name, t]));
}

function detectRenames(
  removed: string[],
  added: string[],
  pinned: Map<string, ToolFingerprint>,
  fresh: Map<string, ToolFingerprint>,
): Array<{ from: string; to: string }> {
  const renames: Array<{ from: string; to: string }> = [];
  const usedAdded = new Set<string>();
  for (const from of removed) {
    const p = pinned.get(from)!;
    const pSchema = canonicalStringify(p.inputSchema);
    for (const to of added) {
      if (usedAdded.has(to)) continue;
      const f = fresh.get(to)!;
      if (f.description === p.description && canonicalStringify(f.inputSchema) === pSchema) {
        renames.push({ from, to });
        usedAdded.add(to);
        break;
      }
    }
  }
  return renames;
}

function pushPoison(findings: Finding[], server: string, tool: string, text: string): void {
  for (const hit of scanText(text)) {
    findings.push({
      severity: hit.severity,
      code: hit.code,
      server,
      tool,
      summary: hit.summary,
      tag: hit.tag,
      after: hit.match,
    });
  }
}

/** Detect the silent, dangerous schema mutations. */
function diffSchema(
  findings: Finding[],
  server: string,
  tool: string,
  pinned: unknown,
  fresh: unknown,
): void {
  const p = asObject(pinned);
  const f = asObject(fresh);
  if (!p || !f) {
    if (canonicalStringify(pinned) !== canonicalStringify(fresh)) {
      findings.push({
        severity: "medium",
        code: "schema-changed",
        server,
        tool,
        summary: `Input schema for "${tool}" changed.`,
      });
    }
    return;
  }

  const pReq = new Set(asStringArray(p.required));
  const fReq = new Set(asStringArray(f.required));
  for (const field of fReq) {
    if (!pReq.has(field)) {
      findings.push({
        severity: "high",
        code: "schema-tightened",
        server,
        tool,
        summary: `Parameter "${field}" became REQUIRED (was optional). Existing calls that omit it will now be rejected.`,
        after: field,
      });
    }
  }
  for (const field of pReq) {
    if (!fReq.has(field)) {
      findings.push({
        severity: "low",
        code: "schema-relaxed",
        server,
        tool,
        summary: `Parameter "${field}" became optional (was required).`,
        before: field,
      });
    }
  }

  const pProps = asObject(p.properties) ?? {};
  const fProps = asObject(f.properties) ?? {};
  const pKeys = new Set(Object.keys(pProps));
  const fKeys = new Set(Object.keys(fProps));

  for (const key of pKeys) {
    if (!fKeys.has(key)) {
      findings.push({
        severity: "medium",
        code: "param-removed",
        server,
        tool,
        summary: `Parameter "${key}" removed from "${tool}".`,
        before: key,
      });
      continue;
    }
    const pp = asObject(pProps[key]);
    const fp = asObject(fProps[key]);
    if (!pp || !fp) continue;

    // Poison hides just as well in a PARAMETER description as in the tool's.
    if (typeof pp.description === "string" && typeof fp.description === "string" && pp.description !== fp.description) {
      findings.push({
        severity: "high",
        code: "param-description-changed",
        server,
        tool,
        summary: `Description of parameter "${key}" changed. The model reads param descriptions as instructions too.`,
        before: String(pp.description),
        after: String(fp.description),
      });
      pushPoison(findings, server, tool, addedWords(String(pp.description), String(fp.description)) || String(fp.description));
    }

    if (pp.type !== fp.type && (pp.type || fp.type)) {
      findings.push({
        severity: "high",
        code: "param-type-changed",
        server,
        tool,
        summary: `Parameter "${key}" type changed ${String(pp.type)} -> ${String(fp.type)}.`,
        before: String(pp.type),
        after: String(fp.type),
      });
    }

    const pEnum = asArray(pp.enum);
    const fEnum = asArray(fp.enum);
    if (pEnum && fEnum) {
      const fSet = new Set(fEnum.map((v) => canonicalStringify(v)));
      const dropped = pEnum.filter((v) => !fSet.has(canonicalStringify(v)));
      if (dropped.length > 0) {
        findings.push({
          severity: "medium",
          code: "enum-narrowed",
          server,
          tool,
          summary: `Enum for "${key}" narrowed; dropped ${dropped.map((v) => JSON.stringify(v)).join(", ")}.`,
        });
      }
    }
  }

  for (const key of fKeys) {
    if (!pKeys.has(key)) {
      findings.push({
        severity: "low",
        code: "param-added",
        server,
        tool,
        summary: `New parameter "${key}" added to "${tool}".`,
        after: key,
      });
      const fp = asObject(fProps[key]);
      if (fp && typeof fp.description === "string") {
        pushPoison(findings, server, tool, fp.description);
      }
    }
  }
}

/** Scan every param description in a schema for poisoning (used on brand-new tools). */
function scanSchemaText(findings: Finding[], server: string, tool: string, schema: unknown): void {
  const s = asObject(schema);
  const props = s && asObject(s.properties);
  if (!props) return;
  for (const key of Object.keys(props)) {
    const p = asObject(props[key]);
    if (p && typeof p.description === "string") {
      pushPoison(findings, server, tool, p.description);
    }
  }
}

/** Return the substring of `next` that is not a prefix-shared run with `prev` (cheap added-text extractor). */
export function addedWords(prev: string, next: string): string {
  const prevWords = new Set(prev.split(/\s+/).filter(Boolean));
  const added = next.split(/\s+/).filter((w) => w && !prevWords.has(w));
  return added.join(" ");
}

function asObject(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}
function asArray(v: unknown): unknown[] | null {
  return Array.isArray(v) ? v : null;
}
function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}
