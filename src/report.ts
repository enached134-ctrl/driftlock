// Terraform-plan-style rendering of findings.

import type { Finding, Severity } from "./types.js";

const useColor =
  process.env.NO_COLOR === undefined && process.env.DRIFTLOCK_NO_COLOR === undefined;

const C = {
  red: (s: string) => color(s, 31),
  green: (s: string) => color(s, 32),
  yellow: (s: string) => color(s, 33),
  blue: (s: string) => color(s, 34),
  gray: (s: string) => color(s, 90),
  bold: (s: string) => (useColor ? `\x1b[1m${s}\x1b[22m` : s),
  bgRed: (s: string) => (useColor ? `\x1b[41m\x1b[97m${s}\x1b[0m` : s),
};

function color(s: string, code: number): string {
  return useColor ? `\x1b[${code}m${s}\x1b[39m` : s;
}

const SEV_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEV_LABEL: Record<Severity, string> = {
  critical: C.bgRed(" CRITICAL "),
  high: C.red("HIGH"),
  medium: C.yellow("MEDIUM"),
  low: C.blue("LOW"),
  info: C.gray("INFO"),
};

const SIGN: Record<string, string> = {
  "tool-added": C.green("+"),
  "tool-removed": C.red("-"),
  "tool-renamed": C.yellow("~"),
  "description-changed": C.yellow("~"),
  "schema-tightened": C.red("!"),
  "schema-relaxed": C.blue("~"),
  "schema-changed": C.yellow("~"),
  "param-added": C.green("+"),
  "param-removed": C.red("-"),
  "param-type-changed": C.red("!"),
  "enum-narrowed": C.yellow("~"),
};

/** Render a full verify report, git/terraform-plan flavored. */
export function renderReport(findings: Finding[], opts: { failThreshold: Severity }): string {
  if (findings.length === 0) {
    return C.green("✔ driftlock: no drift. Every pinned MCP server matches mcp.lock.");
  }

  const sorted = [...findings].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  const lines: string[] = [];
  lines.push(C.bold("DriftLock detected changes to your pinned MCP surface:"));
  lines.push("");

  let lastServer = "";
  for (const f of sorted) {
    if (f.server !== lastServer) {
      lines.push(C.bold(`  ⟐ ${f.server}`));
      lastServer = f.server;
    }
    const sign = f.code.startsWith("poison.") ? C.bgRed(" ⚠ ") : (SIGN[f.code] ?? C.gray("•"));
    const target = f.tool ? C.bold(f.tool) : "";
    const tag = f.tag ? " " + C.gray(`[${f.tag}]`) : "";
    lines.push(`    ${sign} ${SEV_LABEL[f.severity]} ${target}${tag}`);
    lines.push(`        ${f.summary}`);
    if (f.code === "description-changed" && f.before !== undefined && f.after !== undefined) {
      lines.push(`        ${C.red("- " + truncate(f.before))}`);
      lines.push(`        ${C.green("+ " + truncate(f.after))}`);
    } else if (f.code.startsWith("poison.") && f.after) {
      lines.push(`        ${C.bgRed(" injected ")} ${C.red(truncate(f.after, 160))}`);
    }
    lines.push("");
  }

  const counts = tally(findings);
  lines.push(
    C.bold("Summary: ") +
      Object.entries(counts)
        .filter(([, n]) => n > 0)
        .map(([sev, n]) => `${n} ${sev}`)
        .join(", "),
  );

  const failed = findings.some((f) => SEV_ORDER[f.severity] <= SEV_ORDER[opts.failThreshold]);
  lines.push("");
  lines.push(
    failed
      ? C.bgRed(" DRIFT GATE: BLOCKED ") +
          C.red(
            ` — drift at or above ${opts.failThreshold} threshold. Nothing that drifts ships. Run 'driftlock update' only after review.`,
          )
      : C.yellow("DRIFT GATE: PASS (with warnings)"),
  );
  return lines.join("\n");
}

function tally(findings: Finding[]): Record<Severity, number> {
  const t: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) t[f.severity]++;
  return t;
}

function truncate(s: string, n = 100): string {
  const clean = s.replace(/\s+/g, " ").trim();
  return clean.length > n ? clean.slice(0, n - 1) + "…" : clean;
}

/** Machine-readable JSON — for piping driftlock into other tooling. */
export function renderJson(findings: Finding[], opts: { failThreshold: Severity }): string {
  const failed = findings.some((f) => SEV_ORDER[f.severity] <= SEV_ORDER[opts.failThreshold]);
  return JSON.stringify(
    {
      driftDetected: findings.length > 0,
      gateFailed: failed,
      failThreshold: opts.failThreshold,
      counts: tally(findings),
      findings,
    },
    null,
    2,
  );
}

/** Compact GitHub-PR-comment markdown version. */
export function renderMarkdown(findings: Finding[], opts: { failThreshold: Severity }): string {
  const failed = findings.some((f) => SEV_ORDER[f.severity] <= SEV_ORDER[opts.failThreshold]);
  if (findings.length === 0) {
    return "### 🔒 DriftLock\n✅ No drift — every pinned MCP server matches `mcp.lock`.";
  }
  const rows = [...findings]
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])
    .map((f) => {
      const sev =
        f.severity === "critical" ? "🟥 CRITICAL" : f.severity === "high" ? "🟧 HIGH" : f.severity === "medium" ? "🟨 MEDIUM" : "⬜ " + f.severity;
      const what = f.after && f.code.startsWith("poison.") ? ` — \`${truncate(f.after, 80)}\`` : "";
      return `| ${sev} | \`${f.server}\`${f.tool ? " › `" + f.tool + "`" : ""} | ${f.summary}${what} | ${f.tag ?? ""} |`;
    });
  const header =
    "### 🔒 DriftLock — MCP drift detected\n\n" +
    (failed
      ? "> **❌ Drift gate blocked this PR.** A pinned MCP server changed its tool surface. Review, then run `driftlock update` to re-pin intentionally.\n\n"
      : "> ⚠️ Drift detected below the fail threshold.\n\n") +
    "| Severity | Where | What changed | Tag |\n|---|---|---|---|\n";
  return header + rows.join("\n");
}
