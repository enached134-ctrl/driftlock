// Connect to an MCP server and pin its exact tool surface.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { canonicalize, hashValue } from "./canonicalize.js";
import type {
  EntryFingerprint,
  ServerFingerprint,
  ToolFingerprint,
} from "./types.js";

/** How to reach a server. Either a stdio command line or an http endpoint. */
export type ServerSpec =
  | { transport: "stdio"; command: string; args?: string[]; env?: Record<string, string> }
  | { transport: "http"; url: string; headers?: Record<string, string> };

const CLIENT_INFO = { name: "driftlock", version: "0.1.0" };

/** Build a stable `source` string stored in the lockfile for re-fingerprinting. */
export function specSource(spec: ServerSpec): string {
  if (spec.transport === "stdio") {
    return [spec.command, ...(spec.args ?? [])].join(" ");
  }
  return spec.url;
}

/** Connect, enumerate tools/resources/prompts, and produce a deterministic fingerprint. */
export async function fingerprintServer(spec: ServerSpec): Promise<ServerFingerprint> {
  const client = new Client(CLIENT_INFO, { capabilities: {} });
  const transport =
    spec.transport === "stdio"
      ? new StdioClientTransport({
          command: spec.command,
          args: spec.args ?? [],
          // Don't leak the parent's full env (CI secrets/tokens) to a server we
          // may be treating as untrusted. Use the SDK's safe default subset,
          // plus only what the config explicitly opts into.
          env: { ...getDefaultEnvironment(), ...(spec.env ?? {}) },
        })
      : new StreamableHTTPClientTransport(new URL(spec.url), {
          requestInit: spec.headers ? { headers: spec.headers } : undefined,
        });

  await client.connect(transport);
  try {
    const tools = await pinTools(client);
    const resources = await pinResources(client);
    const prompts = await pinPrompts(client);
    return {
      transport: spec.transport,
      source: specSource(spec),
      tools,
      resources,
      prompts,
      surfaceHash: surfaceHashOf(tools, resources, prompts),
    };
  } finally {
    await client.close().catch(() => {});
  }
}

async function pinTools(client: Client): Promise<ToolFingerprint[]> {
  const res = await client.listTools().catch(() => ({ tools: [] as unknown[] }));
  const tools = (res.tools ?? []) as Array<{
    name: string;
    description?: string;
    inputSchema?: unknown;
  }>;
  return tools
    .map((t) => {
      const inputSchema = canonicalize(t.inputSchema ?? {});
      const description = t.description ?? "";
      const hash = hashValue({ name: t.name, description, inputSchema });
      return { name: t.name, description, inputSchema, hash };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

async function pinResources(client: Client): Promise<EntryFingerprint[]> {
  const res = await client
    .listResources()
    .catch(() => ({ resources: [] as unknown[] }));
  const resources = (res.resources ?? []) as Array<{
    uri?: string;
    name?: string;
    description?: string;
  }>;
  return resources
    .map((r) => {
      const name = r.name ?? r.uri ?? "";
      const description = r.description ?? "";
      return { name, description, hash: hashValue({ name, uri: r.uri ?? "", description }) };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

async function pinPrompts(client: Client): Promise<EntryFingerprint[]> {
  const res = await client.listPrompts().catch(() => ({ prompts: [] as unknown[] }));
  const prompts = (res.prompts ?? []) as Array<{
    name: string;
    description?: string;
  }>;
  return prompts
    .map((p) => {
      const description = p.description ?? "";
      return { name: p.name, description, hash: hashValue({ name: p.name, description }) };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** Whole-surface hash: sha256 over every entry hash, sorted for order-independence. */
export function surfaceHashOf(
  tools: ToolFingerprint[],
  resources: EntryFingerprint[],
  prompts: EntryFingerprint[],
): string {
  const all = [
    ...tools.map((t) => `tool:${t.hash}`),
    ...resources.map((r) => `resource:${r.hash}`),
    ...prompts.map((p) => `prompt:${p.hash}`),
  ].sort();
  return hashValue(all);
}
