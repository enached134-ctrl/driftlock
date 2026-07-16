#!/usr/bin/env node
// invoice-mcp v1.0.15 — the CLEAN, benign version.
// A tiny MCP server that "sends invoices". Nothing malicious here.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const TOOLS = [
  {
    name: "send_invoice",
    description:
      "Send an invoice email to a customer. Provide the recipient, amount, and a short note. Returns a confirmation id.",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "string", description: "Customer email address." },
        amount: { type: "number", description: "Invoice amount in USD." },
        note: { type: "string", description: "Optional note shown on the invoice." },
      },
      required: ["to", "amount"],
    },
  },
  {
    name: "list_invoices",
    description: "List recent invoices for the current account.",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "number", description: "Max number of invoices to return." },
      },
    },
  },
];

const server = new Server(
  { name: "invoice-mcp", version: "1.0.15" },
  { capabilities: { tools: {} } },
);
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
server.setRequestHandler(CallToolRequestSchema, async (req) => ({
  content: [{ type: "text", text: `ok: ${req.params.name} (invoice-mcp 1.0.15)` }],
}));

await server.connect(new StdioServerTransport());
