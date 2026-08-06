#!/usr/bin/env node
// DriftLock CLI — pin / verify / update the MCP tool surface your agent trusts.

import { readFile, writeFile } from "node:fs/promises";
import { ToolGate } from "./guard/gate.js";
import { runBench, formatBench } from "./guard/bench.js";
import { EVAL3 } from "./guard/corpus-eval3.js";
import { fingerprintServer, type ServerSpec } from "./fingerprint.js";
import { diffServer } from "./diff.js";
import { renderReport, renderMarkdown, renderJson } from "./report.js";
import {
  readConfig,
  readLockfile,
  writeLockfile,
  DRIFTLOCK_VERSION,
} from "./lockfile.js";
import type { Finding, Severity } from "./types.js";

const HELP = `driftlock ${DRIFTLOCK_VERSION} — the lockfile & CI drift-gate for MCP

USAGE
  driftlock pin        Fingerprint every configured server and write mcp.lock
  driftlock verify     Re-fingerprint and fail if the surface drifted from mcp.lock
  driftlock update     Alias for pin — re-pin intentionally after reviewing drift
  driftlock guard <f>  Evaluate one live tool call. Exits 1 if denied.
  driftlock bench      Run the labeled corpus and print recall, FPR and latency

  pin/verify guard the trust boundary BEFORE a run; guard watches it DURING one.
  Both share the same rule engine, and bench is how its error rate gets published.

  guard input (JSON): { "name": "...", "description": "...",
                        "schema": {...}, "args": {...} }

CONFIG (driftlock.json)
  {
    "failOn": "high",
    "servers": {
      "invoice": { "transport": "stdio", "command": "node", "args": ["server.js"] },
      "search":  { "transport": "http",  "url": "https://mcp.example.com/mcp" }
    }
  }

FLAGS
  --config <path>   Config file (default driftlock.json)
  --lock <path>     Lockfile path (default mcp.lock)
  --markdown        Emit the report as GitHub-PR markdown (used by the Action)
  --fail-on <sev>   Override failOn: critical|high|medium|low
  -h, --help        This help
`;

/**
 * Publish the engine's own error rate.
 *
 * Measured on `guard/corpus-eval3.ts`, which was written after the rules were frozen
 * and has never been used to change one. The dev corpora are excluded on purpose: a
 * score on data you tuned against measures fit, not detection.
 */
function bench(asJson: boolean): number {
  const result = runBench(new ToolGate(), EVAL3);
  process.stdout.write(asJson ? `${JSON.stringify(result, null, 2)}\n` : formatBench(result));
  return 0;
}

/** Evaluate one live tool call. Exit 1 on deny so a wrapper can refuse to proceed. */
async function guard(file: string | undefined, argv: string[]): Promise<number> {
  if (!file) {
    fail("guard needs a JSON file describing the call. See 'driftlock --help'.");
    return 2;
  }
  let call: unknown;
  try {
    call = JSON.parse(await readFile(file, "utf8"));
  } catch (err) {
    fail(`cannot read ${file}: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
  if (!call || typeof call !== "object" || typeof (call as { name?: unknown }).name !== "string") {
    fail(`${file} must be an object with at least a "name".`);
    return 2;
  }

  const gate = new ToolGate({ thorough: argv.includes("--thorough") });
  const decision = gate.check(call as Parameters<ToolGate["check"]>[0]);

  if (argv.includes("--json")) {
    process.stdout.write(`${JSON.stringify(decision, null, 2)}\n`);
  } else if (decision.findings.length === 0) {
    process.stdout.write(`\n  allow — no findings (${decision.latencyUs.toFixed(1)}µs)\n\n`);
  } else {
    process.stdout.write(`\n  ${decision.action.toUpperCase()} — ${decision.severity} (${decision.latencyUs.toFixed(1)}µs)\n\n`);
    for (const f of decision.findings) {
      process.stdout.write(`    ${f.rule}  ${f.severity}  at ${f.path}\n      ${f.message}\n      match: ${JSON.stringify(f.match.slice(0, 120))}\n\n`);
    }
  }
  return decision.action === "deny" ? 1 : 0;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || cmd === "-h" || cmd === "--help") {
    process.stdout.write(HELP);
    return 0;
  }
  // guard and bench are self-contained: they need no server config, so they run
  // before the config is loaded and are usable in a repo that has never been pinned.
  if (cmd === "bench") return bench(argv.includes("--json"));
  if (cmd === "guard") return guard(argv[1], argv.slice(2));

  const flags = parseFlags(argv.slice(1));
  const config = await readConfig(flags.config);
  if (!config || !config.servers || Object.keys(config.servers).length === 0) {
    fail(`No servers configured. Create ${flags.config ?? "driftlock.json"} (see 'driftlock --help').`);
    return 2;
  }
  const failOn = (flags.failOn ?? config.failOn ?? "high") as Severity;

  if (cmd === "pin" || cmd === "update") {
    return pin(config.servers, flags.lock);
  }
  if (cmd === "verify") {
    return verify(config.servers, failOn, flags);
  }
  fail(`Unknown command "${cmd}". Run 'driftlock --help'.`);
  return 2;
}

async function pin(
  servers: Record<string, ServerSpec>,
  lock?: string,
): Promise<number> {
  const out: Record<string, Awaited<ReturnType<typeof fingerprintServer>>> = {};
  for (const [name, spec] of Object.entries(servers)) {
    process.stderr.write(`pinning ${name} …\n`);
    out[name] = await fingerprintServer(spec);
  }
  await writeLockfile(out, lock);
  const total = Object.values(out).reduce((n, s) => n + s.tools.length, 0);
  process.stdout.write(
    `🔒 Pinned ${Object.keys(out).length} server(s), ${total} tool(s) into ${lock ?? "mcp.lock"}.\n`,
  );
  return 0;
}

async function verify(
  servers: Record<string, ServerSpec>,
  failOn: Severity,
  flags: Flags,
): Promise<number> {
  const locked = await readLockfile(flags.lock);
  if (!locked) {
    fail("No mcp.lock found. Run 'driftlock pin' first and commit the lockfile.");
    return 2;
  }

  const findings: Finding[] = [];
  for (const [name, spec] of Object.entries(servers)) {
    const pinned = locked.servers[name];
    const fresh = await fingerprintServer(spec).catch((e) => {
      findings.push({
        severity: "high",
        code: "server-unreachable",
        server: name,
        summary: `Could not reach server "${name}": ${(e as Error).message}`,
      });
      return null;
    });
    if (!fresh) continue;
    if (!pinned) {
      findings.push({
        severity: "medium",
        code: "server-unpinned",
        server: name,
        summary: `Server "${name}" is configured but not in mcp.lock. Run 'driftlock pin'.`,
      });
      continue;
    }
    findings.push(...diffServer(name, pinned, fresh));
  }

  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const failed = findings.some((f) => order[f.severity] <= order[failOn]);

  if (flags.json) {
    process.stdout.write(renderJson(findings, { failThreshold: failOn }) + "\n");
  } else if (flags.markdown) {
    process.stdout.write(renderMarkdown(findings, { failThreshold: failOn }) + "\n");
  } else {
    process.stdout.write(renderReport(findings, { failThreshold: failOn }) + "\n");
  }
  if (flags.markdown && flags.githubOutput) {
    await appendGithubOutput(flags.githubOutput, failed, findings.length);
  }
  return failed ? 1 : 0;
}

interface Flags {
  config?: string;
  lock?: string;
  markdown?: boolean;
  json?: boolean;
  failOn?: string;
  githubOutput?: string;
}

function parseFlags(args: string[]): Flags {
  const f: Flags = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--config") f.config = args[++i];
    else if (a === "--lock") f.lock = args[++i];
    else if (a === "--markdown") f.markdown = true;
    else if (a === "--json") f.json = true;
    else if (a === "--fail-on") f.failOn = args[++i];
    else if (a === "--github-output") f.githubOutput = args[++i];
  }
  if (!f.githubOutput && process.env.GITHUB_OUTPUT) f.githubOutput = process.env.GITHUB_OUTPUT;
  return f;
}

async function appendGithubOutput(path: string, failed: boolean, count: number): Promise<void> {
  await writeFile(path, `drift_detected=${count > 0}\ngate_failed=${failed}\nfinding_count=${count}\n`, {
    flag: "a",
  });
}

function fail(msg: string): void {
  process.stderr.write(`driftlock: ${msg}\n`);
}

main()
  // Set exitCode and let the event loop drain so stdout (piped to a file by the
  // Action) is never truncated; MCP client.close() releases the child handles.
  .then((code) => {
    process.exitCode = code;
  })
  .catch((e) => {
    process.stderr.write(`driftlock: fatal: ${(e as Error).stack ?? e}\n`);
    process.exitCode = 2;
  });
