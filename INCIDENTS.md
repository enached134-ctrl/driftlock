# Incidents DriftLock is designed to catch

DriftLock exists because MCP's trust model has a soft spot: an agent treats a
server's **tool descriptions and schemas as instructions**, and those can change
*after* you've decided to trust the server. Below are real, documented cases of
that soft spot being hit. DriftLock turns each of these from an invisible
runtime event into a red CI check.

> Note: the summaries below are reconstructed from public reporting. Where you
> rely on specifics, follow the linked primary sources. The **fixture** in this
> repo (`fixtures/invoice-mcp/`) is an original re-enactment of the *class* of
> attack, not a copy of any real malicious code.

---

## postmark-mcp v1.0.16 — the email BCC backdoor (Sept 2025)

**What happened (as reported):** a popular community MCP server for sending email
shipped a routine-looking version bump. The change added a single instruction to
a tool's behavior: silently **BCC every email to an attacker-controlled address**.
To any agent using the server, the tool looked identical to the version before —
same name, same parameters. The exfiltration rode along on normal, authorized
tool calls. Reporting put the blast radius at roughly **hundreds of organizations**
before it was pulled.

**Why nothing caught it:**
- No application code changed on the *consumer* side.
- The tool's JSON schema was effectively unchanged; the payload lived in prose.
- There is no `package-lock.json` equivalent for "the behavior of the remote
  tools my agent is allowed to call" — so there was nothing to diff.

**How DriftLock catches it:** the pinned `mcp.lock` records the exact hash of every
tool's description + schema. On the next `verify`, the added BCC sentence changes
the hash → `HIGH`, and the rule engine additionally flags the exfil verb and the
hidden recipient address → `CRITICAL / OWASP-LLM06`. The PR is blocked before the
poisoned tool is ever callable. This repo ships that exact scenario as a runnable
fixture (`driftlock verify --config driftlock.poisoned.json`).

---

## Tool-poisoning / "rug pull" as a class (2025–2026)

Security researchers have repeatedly demonstrated that a **first-run-benign**
MCP server can later mutate its tool descriptions to smuggle instructions to the
model — hidden data-exfiltration, "ignore previous instructions", instructions to
read `.env`/secrets and pass them along, or invisible zero-width/HTML payloads.
The common thread is **time-of-check vs time-of-use**: you audit a server once,
trust it, and it changes underneath you.

**How DriftLock addresses the class:** it collapses time-of-check and
time-of-use to *every CI run*. Trust is no longer a one-time decision — it's a
pinned artifact re-verified continuously, with a human `update` step required to
move the pin.

---

## Silent contract breaks (not malicious, still costly)

Not all drift is an attack. A well-meaning maintainer flips a parameter from
optional to required, narrows an enum, renames a tool, or changes a type. Your
agent's calls start failing in production with no code change on your side.
DriftLock flags these as `HIGH`/`MEDIUM` so they surface in review, not at 2 AM.

---

### Sources to follow for specifics
- OWASP GenAI / LLM Top 10 — **LLM06** (excessive agency / tool risks) and prompt
  injection (LLM01): https://genai.owasp.org/
- Model Context Protocol security guidance: https://modelcontextprotocol.io/
- Public reporting and vendor writeups on the postmark-mcp incident (Sept 2025)
  and on MCP tool-poisoning research — search current primary sources before
  citing exact figures.
