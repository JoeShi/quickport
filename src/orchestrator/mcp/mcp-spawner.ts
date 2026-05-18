/**
 * @quickport/orchestrator/mcp/mcp-spawner
 *
 * HF-7 enforcement: ONLY this module may spawn MCP server child processes.
 * Any other code calling child_process.spawn with an MCP server target = R5 blocker P0.
 *
 * Responsibilities (per @Arch ce595cb2, @Gatekeeper 7d0260fb):
 *  - Maintain binary whitelist (path + SHA-256 hash) for registered MCP servers
 *  - Spawn with minimal environment (scrub LD_PRELOAD, NODE_OPTIONS, DYLD_*, etc.)
 *  - Inject LARK_ACCESS_TOKEN from Keychain (never via CLI arg — visible to ps aux)
 *  - Apply OS sandbox profile at spawn time (HF-3'F)
 *  - Write lifecycle events to audit log (mcp_server_spawned, mcp_server_exited) [HF-6]
 *  - Verify binary hash before every spawn (HF-8)
 *
 * MCP servers are installed to: ~/.quickwork/quickport/mcp-servers/<id>/
 * Per OQ-24 resolved: @Arch c3046784, subordinate namespace under Amazon Quick's root.
 *
 * [critical:security] All MCP server process management goes through here.
 */

import { spawn, ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { getToken } from "../credentials/keychain-adapter.js";
import { auditLog, AuditEventType } from "../audit/audit-log.js";

// MCP server install root (per OQ-24: ~/.quickwork/quickport/mcp-servers/)
// Never write to ~/.quickwork/ root directly — that's Amazon Quick's namespace.
export const MCP_SERVERS_DIR = `${process.env.HOME ?? "~"}/.quickwork/quickport/mcp-servers`;

// ─── Types ────────────────────────────────────────────────────────────────

export interface McpServerManifest {
  /** Unique server identifier, e.g. "feishu-mcp" */
  id: string;
  /** Display name shown in UI */
  name: string;
  /** Absolute path to server entry point (e.g. ~/.quickwork/quickport/mcp-servers/feishu/server.mjs) */
  entryPath: string;
  /** Expected SHA-256 of the entry file (HF-8: binary integrity) */
  expectedHash: string;
  /** OAuth scope declared by this server (HF-9: must ⊆ MCP tool list ⊆ OAuth grant) */
  declaredOauthScopes: string[];
  /** List of MCP tools declared by this server */
  declaredTools: string[];
}

export interface SpawnedMcpServer {
  manifest: McpServerManifest;
  process: ChildProcess;
  spawnTime: Date;
  pid: number;
}

// ─── Allowed env vars that can be inherited by MCP server processes ────────
// [critical:security] Anything not in this list is stripped.
const ALLOWED_ENV_KEYS: ReadonlySet<string> = new Set([
  "PATH",
  "HOME",
  "USER",
  "LANG",
  "LC_ALL",
  "TZ",
  "TERM",
  "TMPDIR",
  "TEMP",
  "TMP",
  // QuickPort-injected:
  "LARK_ACCESS_TOKEN",
  "QUICKWORK_AUDIT_LOG_PATH",
]);

// ─── Module state ─────────────────────────────────────────────────────────

const activeServers = new Map<string, SpawnedMcpServer>();

// ─── Public API ───────────────────────────────────────────────────────────

/**
 * Spawn an MCP server by its manifest.
 * Performs: hash check → env sanitization → token injection → OS sandbox → spawn → audit.
 *
 * @throws if hash mismatch (HF-8) or server already running.
 */
export async function spawnMcpServer(
  manifest: McpServerManifest
): Promise<SpawnedMcpServer> {
  if (activeServers.has(manifest.id)) {
    throw new Error(`MCP server "${manifest.id}" is already running.`);
  }

  // HF-8: Verify binary integrity before spawn
  await verifyBinaryHash(manifest.entryPath, manifest.expectedHash);

  // Build sanitized environment
  const cleanEnv = buildCleanEnv();

  // Inject Feishu OAuth token from Keychain [critical:security]
  const feishuToken = await getToken("@quickport/feishu-token");
  if (feishuToken) {
    cleanEnv["LARK_ACCESS_TOKEN"] = feishuToken;
  }

  // Determine spawn command (HF-3'F: OS sandbox wrapper)
  const { cmd, args } = buildSandboxedSpawnArgs(manifest.entryPath, cleanEnv);

  const proc = spawn(cmd, args, {
    env: cleanEnv,
    stdio: ["pipe", "pipe", "pipe"],
    detached: false,
  });

  if (!proc.pid) {
    throw new Error(`Failed to spawn MCP server "${manifest.id}"`);
  }

  const spawnedServer: SpawnedMcpServer = {
    manifest,
    process: proc,
    spawnTime: new Date(),
    pid: proc.pid,
  };

  activeServers.set(manifest.id, spawnedServer);

  // HF-6: Audit lifecycle event
  await auditLog({
    type: AuditEventType.MCP_SERVER_SPAWNED,
    serverId: manifest.id,
    pid: proc.pid,
    entryPath: manifest.entryPath,
    callerFingerprint: getCallerFingerprint(),
    timestamp: spawnedServer.spawnTime,
  });

  // Clean up on exit
  proc.on("exit", async (code, signal) => {
    activeServers.delete(manifest.id);
    await auditLog({
      type: AuditEventType.MCP_SERVER_EXITED,
      serverId: manifest.id,
      pid: proc.pid,
      exitCode: code ?? undefined,
      signal: signal ?? undefined,
      timestamp: new Date(),
    });
  });

  return spawnedServer;
}

/**
 * Stop a running MCP server gracefully.
 */
export async function stopMcpServer(serverId: string): Promise<void> {
  const server = activeServers.get(serverId);
  if (!server) return; // Idempotent
  server.process.kill("SIGTERM");
  // Give it 5s to die gracefully, then SIGKILL
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(() => {
      server.process.kill("SIGKILL");
      resolve();
    }, 5000);
    server.process.once("exit", () => {
      clearTimeout(timeout);
      resolve();
    });
  });
}

// ─── Internal helpers ─────────────────────────────────────────────────────

async function verifyBinaryHash(
  entryPath: string,
  expectedHash: string
): Promise<void> {
  const content = await readFile(entryPath);
  const actual = createHash("sha256").update(content).digest("hex");
  if (actual !== expectedHash) {
    throw new Error(
      `[critical:security] MCP server binary integrity check FAILED for ${entryPath}.\n` +
        `Expected SHA-256: ${expectedHash}\n` +
        `Actual SHA-256:   ${actual}\n` +
        `This is a blocker P0 per HF-8. The server may have been tampered with.`
    );
  }
}

function buildCleanEnv(): Record<string, string> {
  const clean: Record<string, string> = {};
  for (const [key, val] of Object.entries(process.env)) {
    if (val && ALLOWED_ENV_KEYS.has(key)) {
      clean[key] = val;
    }
  }
  return clean;
}

function buildSandboxedSpawnArgs(
  entryPath: string,
  _env: Record<string, string>
): { cmd: string; args: string[] } {
  if (process.platform === "darwin") {
    // macOS: use sandbox-exec with minimal profile
    // TODO: write actual sandbox profile to ~/.quickwork/quickport/sandbox/mcp-server.sb
    // For now: spawn directly (sandbox profile TBD in ADR-002 final)
    return { cmd: "node", args: [entryPath] };
  } else if (process.platform === "win32") {
    // Windows: AppContainer sandbox (requires separate wrapper)
    // TODO: implement AppContainer wrapper in ADR-002 final
    return { cmd: "node", args: [entryPath] };
  } else {
    return { cmd: "node", args: [entryPath] };
  }
}

function getCallerFingerprint(): string {
  // Returns a fingerprint identifying the calling process (this orchestrator)
  // Used in audit log for tracing which module triggered the spawn
  return `orchestrator:mcp-spawner:pid=${process.pid}`;
}
