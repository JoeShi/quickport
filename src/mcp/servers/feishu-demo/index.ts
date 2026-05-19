/**
 * @quickport/mcp/servers/feishu-demo
 *
 * Minimal stdio MCP server for M1 e2e verification.
 * Implements the MCP JSON-RPC 2.0 protocol over stdio so Amazon Quick
 * can spawn and call it via the native MCP integration.
 *
 * Tools exposed:
 *   - echo: reflects the input message back (sanity check)
 *   - feishu_send_message: stub — returns "sent" without real API call
 *   - feishu_list_chats: stub — returns a canned list
 *
 * In production these stubs are replaced by the real lark-cli wrappers.
 * This server exists solely to prove the Quick → MCP spawn → tool call
 * pipeline works end-to-end before wiring up real Feishu credentials.
 *
 * [critical:security] HF-7: this server is spawned ONLY by
 * @quickport/orchestrator/mcp-spawner, which enforces the stdio sandbox.
 */

import * as readline from "node:readline";

// ─── MCP Protocol types (minimal) ─────────────────────────────────────────

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: string | number | null;
  method: string;
  params?: unknown;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

// ─── Tool definitions ──────────────────────────────────────────────────────

const TOOLS = [
  {
    name: "echo",
    description: "Echo the input message back. Used for M1 e2e pipeline verification.",
    inputSchema: {
      type: "object",
      properties: {
        message: { type: "string", description: "Message to echo" },
      },
      required: ["message"],
    },
  },
  {
    name: "feishu_send_message",
    description: "Send a message to a Feishu chat (stub in demo mode).",
    inputSchema: {
      type: "object",
      properties: {
        chat_id: { type: "string", description: "Target chat ID" },
        content: { type: "string", description: "Message text content" },
      },
      required: ["chat_id", "content"],
    },
  },
  {
    name: "feishu_list_chats",
    description: "List available Feishu chats (stub in demo mode, returns canned data).",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

// ─── Handler ───────────────────────────────────────────────────────────────

function handleRequest(req: JsonRpcRequest): JsonRpcResponse {
  const { id, method, params } = req;

  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: {
            name: "quickport-feishu-demo",
            version: "0.1.0",
          },
        },
      };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: TOOLS },
      };

    case "tools/call": {
      const p = params as { name: string; arguments: Record<string, unknown> };
      const toolName = p?.name;
      const args = p?.arguments ?? {};

      if (toolName === "echo") {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: `echo: ${args.message}` }],
          },
        };
      }

      if (toolName === "feishu_send_message") {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: `[demo] Message sent to ${args.chat_id}: "${args.content}"`,
              },
            ],
          },
        };
      }

      if (toolName === "feishu_list_chats") {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  chats: [
                    { id: "oc_demo_001", name: "QuickPort Dev 群" },
                    { id: "oc_demo_002", name: "产品讨论" },
                  ],
                }),
              },
            ],
          },
        };
      }

      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Unknown tool: ${toolName}` },
      };
    }

    case "notifications/initialized":
      // Notification — no response needed (return null signals skip)
      return null as unknown as JsonRpcResponse;

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
  }
}

// ─── Main stdio loop ───────────────────────────────────────────────────────

const rl = readline.createInterface({
  input: process.stdin,
  terminal: false,
});

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let req: JsonRpcRequest;
  try {
    req = JSON.parse(trimmed);
  } catch {
    const errResp: JsonRpcResponse = {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Parse error" },
    };
    process.stdout.write(JSON.stringify(errResp) + "\n");
    return;
  }

  const resp = handleRequest(req);
  // Notifications return null — don't write a response
  if (resp !== null) {
    process.stdout.write(JSON.stringify(resp) + "\n");
  }
});

rl.on("close", () => {
  process.exit(0);
});
