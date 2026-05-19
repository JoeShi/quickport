/**
 * @quickport/mcp/servers/feishu
 *
 * Production Feishu MCP server — 7 real lark-cli-backed tools.
 * Implements MCP JSON-RPC 2.0 over stdio for Quick Desktop native MCP support.
 *
 * Tools:
 *   1. feishu_list_chats       — list group chats the user/bot is a member of
 *   2. feishu_search_chats     — search for chats by name or keyword
 *   3. feishu_send_message     — send text or markdown to a chat or DM
 *   4. feishu_get_messages     — list recent messages in a chat
 *   5. feishu_search_messages  — search messages by keyword across chats
 *   6. feishu_reply_message    — reply to a specific message (optionally in thread)
 *   7. feishu_get_message_batch — fetch details for specific message IDs
 *
 * Auth: delegates to lark-cli, which manages its own credential lifecycle
 * (keychain master key at service="lark-cli"). No token handling in this server.
 *
 * [critical:security] HF-7: this server is spawned ONLY by
 * @quickport/orchestrator/mcp-spawner, which enforces the stdio sandbox.
 * [critical:security] HF-9: declared capabilities in manifest.json must match
 * the tool set here; scanner R9 validates declared ⊆ tools ⊆ OAuth grant.
 */

import * as readline from "node:readline";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

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

// ─── lark-cli helper ───────────────────────────────────────────────────────

interface LarkCliResult {
  ok: boolean;
  output?: unknown;
  error?: string;
}

async function runLarkCli(args: string[], appendFormat = true): Promise<LarkCliResult> {
  const finalArgs = appendFormat ? [...args, "--format", "json"] : args;
  try {
    const { stdout, stderr } = await execFileAsync("lark-cli", finalArgs, {
      timeout: 30_000,
      env: { ...process.env },
    });
    if (stderr && stderr.trim()) {
      // lark-cli may write non-fatal warnings to stderr
      const stderrTrim = stderr.trim();
      if (stderrTrim.startsWith("Error") || stderrTrim.startsWith("error")) {
        return { ok: false, error: stderrTrim };
      }
    }
    const rawOut = stdout.trim();
    if (!rawOut) return { ok: true, output: null };
    const parsed = JSON.parse(rawOut);
    // Feishu API error: { code: N, msg: "..." }
    if (parsed?.code !== undefined && parsed.code !== 0) {
      return { ok: false, error: `Feishu API error ${parsed.code}: ${parsed.msg ?? "unknown"}` };
    }
    // lark-cli skill error: { ok: false, error: { message: "..." } }
    if (parsed?.ok === false) {
      const errMsg = parsed.error?.message ?? parsed.error ?? "unknown error";
      return { ok: false, error: String(errMsg) };
    }
    return { ok: true, output: parsed };
  } catch (err: any) {
    if (err.killed || err.signal === "SIGTERM") {
      return { ok: false, error: "lark-cli timed out after 30s" };
    }
    const msg = err.stderr?.trim() || err.message || String(err);
    return { ok: false, error: msg };
  }
}

function textResult(text: string): unknown {
  return { content: [{ type: "text", text }] };
}

function jsonResult(data: unknown): unknown {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}

function errorResult(message: string): unknown {
  return { content: [{ type: "text", text: `Error: ${message}` }], isError: true };
}

// ─── Tool definitions ──────────────────────────────────────────────────────

const TOOLS = [
  {
    name: "feishu_list_chats",
    description:
      "List Feishu group chats the authenticated user is a member of. Returns chat IDs, names, and metadata.",
    inputSchema: {
      type: "object",
      properties: {
        page_size: {
          type: "number",
          description: "Number of chats to return (1-100, default 50)",
        },
        page_token: {
          type: "string",
          description: "Pagination token from a previous call",
        },
      },
    },
  },
  {
    name: "feishu_search_chats",
    description:
      "Search for Feishu group chats by name or keyword. Useful for finding a chat ID by group name.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Search keyword (max 64 chars)",
        },
        page_size: {
          type: "number",
          description: "Number of results to return (1-100, default 20)",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "feishu_send_message",
    description:
      "Send a text or markdown message to a Feishu group chat or DM. Requires chat_id (oc_xxx) or user_id (ou_xxx).",
    inputSchema: {
      type: "object",
      properties: {
        chat_id: {
          type: "string",
          description: "Target group chat ID (oc_xxx). Mutually exclusive with user_id.",
        },
        user_id: {
          type: "string",
          description: "Target user open_id (ou_xxx) for DM. Mutually exclusive with chat_id.",
        },
        text: {
          type: "string",
          description: "Plain text message content. Mutually exclusive with markdown.",
        },
        markdown: {
          type: "string",
          description: "Markdown-formatted message content. Mutually exclusive with text.",
        },
      },
    },
  },
  {
    name: "feishu_get_messages",
    description:
      "List recent messages in a Feishu chat or DM conversation. Returns message content, sender, and timestamps.",
    inputSchema: {
      type: "object",
      properties: {
        chat_id: {
          type: "string",
          description: "Chat ID (oc_xxx). Mutually exclusive with user_id.",
        },
        user_id: {
          type: "string",
          description: "User open_id (ou_xxx) for P2P conversation. Mutually exclusive with chat_id.",
        },
        page_size: {
          type: "number",
          description: "Number of messages to return (1-50, default 20)",
        },
        sort: {
          type: "string",
          enum: ["asc", "desc"],
          description: "Sort order by time (default: desc = newest first)",
        },
        start: {
          type: "string",
          description: "Start time filter (ISO 8601, e.g. 2026-05-01T00:00:00+08:00)",
        },
        end: {
          type: "string",
          description: "End time filter (ISO 8601)",
        },
      },
    },
  },
  {
    name: "feishu_search_messages",
    description:
      "Search messages by keyword across Feishu chats. Optionally filter by chat, sender, or time range.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Search keyword",
        },
        chat_id: {
          type: "string",
          description: "Limit search to this chat ID (oc_xxx)",
        },
        page_size: {
          type: "number",
          description: "Number of results (1-50, default 20)",
        },
        start: {
          type: "string",
          description: "Start time filter (ISO 8601)",
        },
        end: {
          type: "string",
          description: "End time filter (ISO 8601)",
        },
        is_at_me: {
          type: "boolean",
          description: "Only return messages that @mention the current user",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "feishu_reply_message",
    description:
      "Reply to a specific Feishu message. Optionally reply in-thread to keep discussion organized.",
    inputSchema: {
      type: "object",
      properties: {
        message_id: {
          type: "string",
          description: "Message ID to reply to (om_xxx)",
        },
        text: {
          type: "string",
          description: "Plain text reply content. Mutually exclusive with markdown.",
        },
        markdown: {
          type: "string",
          description: "Markdown reply content. Mutually exclusive with text.",
        },
        reply_in_thread: {
          type: "boolean",
          description: "If true, reply in the message thread rather than the main chat",
        },
      },
      required: ["message_id"],
    },
  },
  {
    name: "feishu_get_message_batch",
    description:
      "Fetch full details for up to 50 Feishu messages by their IDs. Useful for enriching search results.",
    inputSchema: {
      type: "object",
      properties: {
        message_ids: {
          type: "array",
          items: { type: "string" },
          description: "List of message IDs to fetch (om_xxx format, max 50)",
        },
      },
      required: ["message_ids"],
    },
  },
];

// ─── Tool handlers ─────────────────────────────────────────────────────────

async function handleTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  switch (name) {
    case "feishu_list_chats": {
      const cliArgs = ["im", "chats", "list"];
      const params: Record<string, unknown> = {};
      if (args.page_size) params["page_size"] = args.page_size;
      if (args.page_token) params["page_token"] = args.page_token;
      if (Object.keys(params).length > 0) cliArgs.push("--params", JSON.stringify(params));
      const r = await runLarkCli(cliArgs);
      if (!r.ok) return errorResult(r.error!);
      const data = (r.output as any)?.data;
      return jsonResult({ chats: data?.items ?? [], has_more: data?.has_more ?? false, page_token: data?.page_token });
    }

    case "feishu_search_chats": {
      if (!args.query) return errorResult("query is required");
      const cliArgs = ["im", "+chat-search", "--query", String(args.query)];
      if (args.page_size) cliArgs.push("--page-size", String(args.page_size));
      const r = await runLarkCli(cliArgs);
      if (!r.ok) return errorResult(r.error!);
      const data = (r.output as any)?.data;
      return jsonResult({ chats: data?.chats ?? data?.items ?? [], has_more: data?.has_more ?? false });
    }

    case "feishu_send_message": {
      if (!args.chat_id && !args.user_id) return errorResult("chat_id or user_id is required");
      if (!args.text && !args.markdown) return errorResult("text or markdown is required");
      const cliArgs = ["im", "+messages-send"];
      if (args.chat_id) cliArgs.push("--chat-id", String(args.chat_id));
      if (args.user_id) cliArgs.push("--user-id", String(args.user_id));
      if (args.text) cliArgs.push("--text", String(args.text));
      if (args.markdown) cliArgs.push("--markdown", String(args.markdown));
      const r = await runLarkCli(cliArgs, false);
      if (!r.ok) return errorResult(r.error!);
      const msgId = (r.output as any)?.data?.message_id;
      return textResult(msgId ? `Message sent (ID: ${msgId})` : "Message sent");
    }

    case "feishu_get_messages": {
      if (!args.chat_id && !args.user_id) return errorResult("chat_id or user_id is required");
      const cliArgs = ["im", "+chat-messages-list"];
      if (args.chat_id) cliArgs.push("--chat-id", String(args.chat_id));
      if (args.user_id) cliArgs.push("--user-id", String(args.user_id));
      if (args.page_size) cliArgs.push("--page-size", String(args.page_size));
      if (args.sort) cliArgs.push("--sort", String(args.sort));
      if (args.start) cliArgs.push("--start", String(args.start));
      if (args.end) cliArgs.push("--end", String(args.end));
      const r = await runLarkCli(cliArgs, false);
      if (!r.ok) return errorResult(r.error!);
      const data = (r.output as any)?.data;
      // +chat-messages-list returns data.messages (not data.items)
      return jsonResult({ messages: data?.messages ?? data?.items ?? [], has_more: data?.has_more ?? false, page_token: data?.page_token });
    }

    case "feishu_search_messages": {
      if (!args.query) return errorResult("query is required");
      const cliArgs = ["im", "+messages-search", "--query", String(args.query)];
      if (args.chat_id) cliArgs.push("--chat-id", String(args.chat_id));
      if (args.page_size) cliArgs.push("--page-size", String(args.page_size));
      if (args.start) cliArgs.push("--start", String(args.start));
      if (args.end) cliArgs.push("--end", String(args.end));
      if (args.is_at_me) cliArgs.push("--is-at-me");
      const r = await runLarkCli(cliArgs);
      if (!r.ok) return errorResult(r.error!);
      const data = (r.output as any)?.data;
      return jsonResult({ messages: data?.messages ?? data?.items ?? [], has_more: data?.has_more ?? false, page_token: data?.page_token });
    }

    case "feishu_reply_message": {
      if (!args.message_id) return errorResult("message_id is required");
      if (!args.text && !args.markdown) return errorResult("text or markdown is required");
      const cliArgs = ["im", "+messages-reply", "--message-id", String(args.message_id)];
      if (args.text) cliArgs.push("--text", String(args.text));
      if (args.markdown) cliArgs.push("--markdown", String(args.markdown));
      if (args.reply_in_thread) cliArgs.push("--reply-in-thread");
      const r = await runLarkCli(cliArgs, false);
      if (!r.ok) return errorResult(r.error!);
      const msgId = (r.output as any)?.data?.message_id;
      return textResult(msgId ? `Reply sent (ID: ${msgId})` : "Reply sent");
    }

    case "feishu_get_message_batch": {
      const ids = args.message_ids as string[];
      if (!Array.isArray(ids) || ids.length === 0) return errorResult("message_ids must be a non-empty array");
      if (ids.length > 50) return errorResult("message_ids: max 50 IDs per request");
      const cliArgs = ["im", "+messages-mget", "--message-ids", ids.join(",")];
      const r = await runLarkCli(cliArgs);
      if (!r.ok) return errorResult(r.error!);
      const out = r.output as any;
      // +messages-mget returns { ok: true, data: { items: [...] } } or top-level items
      const messages = out?.data?.items ?? out?.data?.messages ?? out?.items ?? [];
      return jsonResult({ messages });
    }

    default:
      return errorResult(`Unknown tool: ${name}`);
  }
}

// ─── MCP request handler ───────────────────────────────────────────────────

function handleRequest(req: JsonRpcRequest): JsonRpcResponse | null {
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
            name: "quickport-feishu",
            version: "0.2.0",
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

      // Return a pending response — actual execution is async
      return null; // handled below via async dispatch
    }

    case "notifications/initialized":
      return null;

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

function writeResponse(resp: JsonRpcResponse): void {
  process.stdout.write(JSON.stringify(resp) + "\n");
}

let pendingRequests = 0;
let stdinClosed = false;

function maybeExit(): void {
  if (stdinClosed && pendingRequests === 0) process.exit(0);
}

rl.on("line", async (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let req: JsonRpcRequest;
  try {
    req = JSON.parse(trimmed);
  } catch {
    writeResponse({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Parse error" },
    });
    return;
  }

  const { id, method, params } = req;

  // Handle tools/call asynchronously (lark-cli subprocess)
  if (method === "tools/call") {
    const p = params as { name: string; arguments: Record<string, unknown> };
    const toolName = p?.name;
    const args = p?.arguments ?? {};

    if (!TOOLS.find((t) => t.name === toolName)) {
      writeResponse({
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Unknown tool: ${toolName}` },
      });
      return;
    }

    pendingRequests++;
    try {
      const result = await handleTool(toolName, args);
      writeResponse({ jsonrpc: "2.0", id, result });
    } catch (err: any) {
      writeResponse({
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: `Tool execution error: ${err?.message ?? String(err)}` },
      });
    } finally {
      pendingRequests--;
      maybeExit();
    }
    return;
  }

  // Handle notifications/initialized (no response)
  if (method === "notifications/initialized") return;

  // All other methods are synchronous
  const resp = handleRequest(req);
  if (resp !== null) {
    writeResponse(resp);
  }
});

rl.on("close", () => {
  stdinClosed = true;
  maybeExit();
});
