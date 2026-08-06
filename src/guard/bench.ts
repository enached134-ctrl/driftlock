import { CORPUS, type Case } from "./corpus.js";
import { ToolGate } from "./gate.js";
import { clopperPearson, fmtInterval, samplesNeeded, type Interval } from "./stats.js";
import type { Decision } from "./types.js";

export interface BenchResult {
  cases: number;
  benign: number;
  attacks: number;
  /** Attack flagged (deny or review). */
  tp: number;
  /** Benign flagged — the number that decides whether anyone keeps this on. */
  fp: number;
  tn: number;
  /** Attack that slipped through as "allow". */
  fn: number;
  fpr: number;
  fnr: number;
  precision: number;
  recall: number;
  f1: number;
  /** Exact 95% intervals. The point estimates above mean little without these. */
  ci: { recall: Interval; fpr: Interval };
  /** Attacks hard-blocked (deny), not merely flagged for review. */
  blocked: number;
  latency: { p50: number; p95: number; p99: number; max: number; mean: number };
  misses: { id: string; note: string }[];
  falseAlarms: { id: string; note: string; rules: string[] }[];
}

function pct(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const i = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[i] ?? 0;
}

/**
 * Measures the gate against the labeled corpus.
 *
 * "Detected" means the gate did not return `allow` — a call sent to human
 * review still counts as caught. False positives are counted the same way,
 * because a benign call routed to review is still friction the operator pays.
 */
export function runBench(gate = new ToolGate(), corpus: Case[] = CORPUS): BenchResult {
  // Warm the JIT so the latency figures describe steady state, not first-call
  // compilation. Reporting cold numbers would flatter nobody and mislead everyone.
  for (let i = 0; i < 200; i++) gate.check(corpus[i % corpus.length]!.call);

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  let blocked = 0;
  const lat: number[] = [];
  const misses: { id: string; note: string }[] = [];
  const falseAlarms: { id: string; note: string; rules: string[] }[] = [];

  for (const c of corpus) {
    const d: Decision = gate.check(c.call);
    lat.push(d.latencyUs);
    const flagged = d.action !== "allow";

    if (c.label === "attack") {
      if (flagged) {
        tp++;
        if (d.action === "deny") blocked++;
      } else {
        fn++;
        misses.push({ id: c.id, note: c.note });
      }
    } else if (flagged) {
      fp++;
      falseAlarms.push({
        id: c.id,
        note: c.note,
        rules: [...new Set(d.findings.map((f) => f.rule))],
      });
    } else {
      tn++;
    }
  }

  const attacks = tp + fn;
  const benign = fp + tn;
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = attacks === 0 ? 0 : tp / attacks;
  const sorted = [...lat].sort((a, b) => a - b);

  return {
    cases: corpus.length,
    benign,
    attacks,
    tp,
    fp,
    tn,
    fn,
    fpr: benign === 0 ? 0 : fp / benign,
    fnr: attacks === 0 ? 0 : fn / attacks,
    precision,
    recall,
    f1: precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall),
    ci: { recall: clopperPearson(tp, attacks), fpr: clopperPearson(fp, benign) },
    blocked,
    latency: {
      p50: pct(sorted, 50),
      p95: pct(sorted, 95),
      p99: pct(sorted, 99),
      max: sorted[sorted.length - 1] ?? 0,
      mean: lat.reduce((a, b) => a + b, 0) / (lat.length || 1),
    },
    misses,
    falseAlarms,
  };
}

const p1 = (n: number) => `${(n * 100).toFixed(1)}%`;
const us = (n: number) => (n < 1000 ? `${n.toFixed(1)}µs` : `${(n / 1000).toFixed(2)}ms`);

/**
 * States what the sample size does and does not license, in the output itself.
 *
 * A perfect score on a small corpus is the easiest number in security to publish and
 * the easiest to demolish. Printing the caveat next to the figure means nobody has to
 * discover it in the README, and it stops a flattering run from being quoted bare.
 */
function honestyNotes(r: BenchResult): string[] {
  const L: string[] = ["  what this sample size supports"];
  const fprCap = r.ci.fpr.upper;
  const recallFloor = r.ci.recall.lower;

  L.push(
    `    ${r.benign} benign cases rule out a false-positive rate above ${(fprCap * 100).toFixed(1)}%, no lower.`,
  );
  L.push(
    `    ${r.attacks} attack cases rule out a recall below ${(recallFloor * 100).toFixed(1)}%, no higher.`,
  );
  if (fprCap > 0.05) {
    L.push(
      `    To claim "under 5% false positives" you need ${samplesNeeded(0.05)} clean benign cases; you have ${r.benign}.`,
    );
  }
  if (recallFloor < 0.95) {
    L.push(
      `    To claim "over 95% recall" you need ${samplesNeeded(0.05)} attack cases caught; you have ${r.attacks}.`,
    );
  }
  L.push("");
  return L;
}

export function formatBench(r: BenchResult): string {
  const L: string[] = [];
  L.push("");
  L.push("  driftlock guard — measured on the held-out set");
  L.push(`  ${r.cases} cases — ${r.attacks} attack, ${r.benign} benign`);
  L.push("");
  L.push("  detection                     rate     95% interval");
  L.push(`    recall (attacks caught)     ${fmtInterval(r.ci.recall)}   ${r.tp}/${r.attacks}`);
  L.push(`    hard-blocked (deny)         ${r.blocked}/${r.attacks}`);
  L.push("");
  L.push("  cost to legitimate traffic");
  L.push(`    false-positive rate         ${fmtInterval(r.ci.fpr)}   ${r.fp}/${r.benign}`);
  L.push(`    precision                   ${p1(r.precision)}`);
  L.push(`    f1                          ${r.f1.toFixed(3)}`);
  L.push("");
  L.push("  latency per tool call");
  L.push(`    p50 ${us(r.latency.p50)}   p95 ${us(r.latency.p95)}   p99 ${us(r.latency.p99)}   max ${us(r.latency.max)}`);
  L.push("");
  L.push(...honestyNotes(r));
  if (r.misses.length) {
    L.push("  missed attacks");
    for (const m of r.misses) L.push(`    ${m.id} — ${m.note}`);
    L.push("");
  }
  if (r.falseAlarms.length) {
    L.push("  false alarms");
    for (const f of r.falseAlarms) L.push(`    ${f.id} [${f.rules.join(", ")}] — ${f.note}`);
    L.push("");
  }
  return L.join("\n");
}
