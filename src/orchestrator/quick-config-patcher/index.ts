/**
 * @quickport/orchestrator/quick-config-patcher
 *
 * [critical:security] ONLY this module may write to ~/.quickwork/mcp_config.json.
 * R5 Semgrep rule `quickwork-R5-direct-quick-config-write` enforces this.
 *
 * 5-Invariants Protocol (per @Arch 6cd68744 + @Gatekeeper 3b238ace + @Gatekeeper fda3816d):
 *   1. Atomic write:       write tmp → fsync → rename(2) — Quick can never read a partial file
 *   2. Backup-before-write: copy current → ~/.quickwork/quickport/backups/mcp_config.<ts>.json
 *   3. Schema validate:    parse JSON + validate mcpServers/servers dual-schema after write
 *   4. HF-6 audit entry:   emit quick_config_patched event with pre/post hash + backup path
 *   5. Rollback path:      diff-merge restore on uninstall (AC-11: Quick's own entries preserved)
 *
 * Install path layout (OQ-24 resolved, @Arch c3046784):
 *   ~/.quickwork/                    ← Amazon Quick's namespace (NOT ours)
 *     mcp_config.json                ← Quick's config, we patch via this module ONLY
 *     quickport/                     ← our subordinate namespace
 *       mcp-servers/<id>/            ← our MCP server binaries
 *       skills/<name>/               ← skill installs
 *       state/audit.ndjson           ← audit log (R5 narrow waist)
 *       backups/mcp_config.<ts>.json ← pre-patch snapshots (N=10 kept)
 */

import { readFile, writeFile, rename, mkdir, unlink, readdir, chmod, open } from "node:fs/promises";
import { join, dirname } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import os from "node:os";
import { auditLog, AuditEventType } from "../audit/audit-log.js";
import { register as registryRegister, unregister as registryUnregister, list as registryList } from "../capability-registry/index.js";

// ─── Path constants ────────────────────────────────────────────────────────

const QUICK_ROOT = join(os.homedir(), ".quickwork");
export const MCP_CONFIG_PATH = join(QUICK_ROOT, "mcp_config.json");
export const QUICKPORT_DIR = join(QUICK_ROOT, "quickport");
export const BACKUPS_DIR = join(QUICKPORT_DIR, "backups");

/** Maximum number of backup snapshots to retain */
const MAX_BACKUPS = 10;

// ─── MCP config schema types ───────────────────────────────────────────────

export interface McpServerEntry {
  /** Server display name */
  name: string;
  /** Launch command */
  command: string;
  /** Command arguments */
  args: string[];
  /** Optional environment variables to inject */
  env?: Record<string, string>;
}

/**
 * mcp_config.json dual-schema:
 *   - "mcpServers" key = Claude Desktop compatibility format
 *   - "servers" key = Amazon Quick native format
 * Both may coexist. We write to both for maximum compatibility.
 */
export interface McpConfig {
  mcpServers?: Record<string, McpServerEntry>;
  servers?: Record<string, McpServerEntry>;
  [key: string]: unknown; // preserve unknown Quick-internal fields
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Register a new MCP server in mcp_config.json AND our capability registry.
 * Follows all 5 invariants. Idempotent: if already present, overwrites.
 * Symmetric write: (1) patch Quick mcp_config.json, (2) record to capability-registry.json.
 *
 * @param serverId     Unique server key (e.g. "quickport-feishu")
 * @param entry        Server launch config
 * @param version      Skill manifest version (stored in registry for integrity tracking)
 * @param scanEventRef Optional foreign key → SkillScanResultEvent.eventId (per @Arch 601df1b6)
 *                     Should be set by install pipeline for all user-triggered installs.
 */
export async function registerMcpServer(
  serverId: string,
  entry: McpServerEntry,
  version: string = "unknown",
  scanEventRef?: string
): Promise<void> {
  await patchConfig("add", [serverId], scanEventRef, (config) => {
    config.mcpServers ??= {};
    config.servers ??= {};
    config.mcpServers[serverId] = entry;
    config.servers[serverId] = entry;
  });
  // Symmetric write: record to our private registry (per @Arch d7873f09)
  // This is the single source of truth for AC-11 diff-merge uninstall.
  await registryRegister(serverId, entry, version);
}

/**
 * Remove a QuickPort-registered MCP server from mcp_config.json AND our capability registry.
 * Leaves Quick's own entries untouched. Idempotent.
 *
 * @param serverId  The server key to remove
 */
export async function unregisterMcpServer(serverId: string): Promise<void> {
  await patchConfig("remove", [serverId], undefined, (config) => {
    if (config.mcpServers?.[serverId]) delete config.mcpServers[serverId];
    if (config.servers?.[serverId]) delete config.servers[serverId];
  });
  // Symmetric remove from our private registry
  await registryUnregister(serverId);
}

/**
 * AC-11: Uninstall QuickPort — remove all quickport-managed entries from mcp_config.json.
 * Performs a diff-merge restore: reads our capability-registry as source of truth,
 * surgically removes ONLY our entries; Quick's own entries are preserved intact.
 *
 * No longer requires caller to pass managedServerIds — we read from our registry
 * (per @Arch d7873f09: capability-registry.json is the single source of truth).
 */
export async function uninstallAllManagedServers(): Promise<void> {
  // Read our private registry — these are the ONLY entries we are authorized to remove
  const managed = await registryList();
  const managedIds = managed.map((e) => e.serverId);

  if (managedIds.length === 0) return; // Nothing to clean up

  await patchConfig("repair", managedIds, undefined, (config) => {
    for (const id of managedIds) {
      if (config.mcpServers?.[id]) delete config.mcpServers[id];
      if (config.servers?.[id]) delete config.servers[id];
    }
  });

  // Clean up registry entries too
  for (const id of managedIds) {
    await registryUnregister(id);
  }
}

/**
 * Read the current mcp_config.json (or return empty config if missing).
 */
export async function readMcpConfig(): Promise<McpConfig> {
  try {
    const raw = await readFile(MCP_CONFIG_PATH, "utf8");
    return JSON.parse(raw) as McpConfig;
  } catch (err: any) {
    if (err.code === "ENOENT") return {};
    throw err;
  }
}

// ─── Core patch engine (5-invariants) ─────────────────────────────────────

/**
 * Core patch engine — all 5 invariants enforced here.
 * @param operation    Audit operation type
 * @param affectedIds  Server IDs being modified
 * @param scanEventRef Optional foreign key to SkillScanResultEvent (per @Arch 601df1b6)
 * @param mutator      Pure function that mutates the in-memory config
 */
async function patchConfig(
  operation: "add" | "remove" | "repair",
  affectedIds: string[],
  scanEventRef: string | undefined,
  mutator: (config: McpConfig) => void
): Promise<void> {
  await ensureDirectories();

  // Read current state
  const currentRaw = await readCurrentRaw();
  const preHash = sha256(currentRaw);

  // ── Invariant 2: Backup-before-write ─────────────────────────────────
  const backupPath = await createBackup(currentRaw);

  // ── Apply mutation ────────────────────────────────────────────────────
  const config: McpConfig = currentRaw ? JSON.parse(currentRaw) : {};
  mutator(config);

  // ── Invariant 1: Atomic write (tmp → fsync → rename) ─────────────────
  const newContent = JSON.stringify(config, null, 2) + "\n";
  const postHash = sha256(newContent);
  await atomicWrite(MCP_CONFIG_PATH, newContent);

  // ── Invariant 3: Schema validate ──────────────────────────────────────
  try {
    await validateSchema(MCP_CONFIG_PATH);
  } catch (err) {
    // Schema validation failed — rollback immediately
    await atomicWrite(MCP_CONFIG_PATH, currentRaw || "{}");
    throw new Error(
      `[critical:security] mcp_config.json schema validation failed after patch. ` +
        `Rolled back to pre-patch state. Backup at: ${backupPath}\n${err}`
    );
  }

  // ── Invariant 4: HF-6 audit entry ────────────────────────────────────
  await auditLog({
    type: AuditEventType.QUICK_CONFIG_PATCHED,
    eventId: randomUUID(),         // unique event ID — foreign key target for downstream refs
    operation,
    affectedServerIds: affectedIds,
    preHash,
    postHash,
    backupPath,
    scanEventRef,                  // explicit link to SkillScanResultEvent (per @Arch 601df1b6)
    callerFingerprint: `orchestrator:quick-config-patcher:pid=${process.pid}`,
    timestamp: new Date(),
  });

  // ── Rotate old backups (keep MAX_BACKUPS most recent) ─────────────────
  await rotateBackups();
}

// ─── Helpers ──────────────────────────────────────────────────────────────

async function ensureDirectories(): Promise<void> {
  await mkdir(BACKUPS_DIR, { recursive: true });
}

async function readCurrentRaw(): Promise<string> {
  try {
    return await readFile(MCP_CONFIG_PATH, "utf8");
  } catch (err: any) {
    if (err.code === "ENOENT") return "";
    throw err;
  }
}

async function createBackup(content: string): Promise<string> {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = join(BACKUPS_DIR, `mcp_config.${ts}.json`);
  // Write empty JSON if config didn't exist yet (first install)
  await writeFile(backupPath, content || "{}", "utf8");
  // [critical:security] Backup may contain credential-adjacent config — restrict to owner only.
  // chmod 600: rw------- (per @Gatekeeper 419a34f6 review note #2)
  await chmod(backupPath, 0o600);
  return backupPath;
}

/**
 * Atomic write: write to a temp file → explicit fsync → rename(2) → fsync parent dir.
 * [critical:security] Per @Gatekeeper 419a34f6 review note #1:
 *   - Node.js writeFile does NOT guarantee fsync. Must open fd, write, fsync, close, then rename.
 *   - On POSIX: also fsync parent directory so directory entry is durable after rename.
 *   - On Windows: rename is best-effort atomic (NTFS MoveFileEx MOVEFILE_REPLACE_EXISTING).
 * This ensures mcp_config.json is never corrupt even on power loss or process kill during write.
 */
async function atomicWrite(targetPath: string, content: string): Promise<void> {
  const tmpPath = targetPath + `.tmp.${process.pid}`;
  let fd: Awaited<ReturnType<typeof open>> | null = null;
  try {
    fd = await open(tmpPath, "w", 0o644);
    await fd.writeFile(content, { encoding: "utf8" });
    // Explicit fsync: flush kernel buffer → disk (crash safety)
    await fd.sync();
    await fd.close();
    fd = null;

    // rename(2) is atomic on POSIX; NTFS best-effort on Windows
    await rename(tmpPath, targetPath);

    // Fsync parent directory on POSIX so the directory entry is durable
    // (avoids losing the rename on power cut between rename + parent dir write-back)
    if (process.platform !== "win32") {
      const parentFd = await open(dirname(targetPath), "r");
      try { await parentFd.sync(); } finally { await parentFd.close(); }
    }
  } catch (err) {
    if (fd) { try { await fd.close(); } catch { /* ignore */ } }
    try { await unlink(tmpPath); } catch { /* ignore */ }
    throw err;
  }
}

/**
 * Validate that mcp_config.json is valid JSON with at least one of the expected schemas.
 */
async function validateSchema(path: string): Promise<void> {
  const raw = await readFile(path, "utf8");
  let parsed: McpConfig;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("mcp_config.json is not valid JSON after write");
  }

  // Must be an object (not array, not null)
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("mcp_config.json root must be a JSON object");
  }

  // If mcpServers or servers exist, each entry must have command + args
  // Exception: entries marked `disabled: true` (mcpServers schema) or `enabled: false` (servers schema)
  // may omit args / command — these are placeholder/disabled entries Quick may set at install time
  // (e.g. the default `builder-mcp` entry has command but no args; future Quick versions may ship
  // disabled entries with neither). Active entries still require both fields.
  for (const schemaKey of ["mcpServers", "servers"] as const) {
    const entries = parsed[schemaKey];
    if (entries && typeof entries === "object") {
      for (const [id, entry] of Object.entries(entries)) {
        const e = entry as McpServerEntry & { disabled?: boolean; enabled?: boolean };
        const isDisabled = e.disabled === true || e.enabled === false;
        if (!isDisabled) {
          if (typeof e.command !== "string" || !e.command) {
            throw new Error(`mcp_config.json[${schemaKey}][${id}].command must be a non-empty string`);
          }
          if (!Array.isArray(e.args)) {
            throw new Error(`mcp_config.json[${schemaKey}][${id}].args must be an array`);
          }
        }
      }
    }
  }
}

async function rotateBackups(): Promise<void> {
  try {
    const files = (await readdir(BACKUPS_DIR))
      .filter((f) => f.startsWith("mcp_config.") && f.endsWith(".json"))
      .sort(); // ISO timestamps sort lexicographically = chronological

    // Remove oldest files beyond MAX_BACKUPS
    const toDelete = files.slice(0, Math.max(0, files.length - MAX_BACKUPS));
    await Promise.all(toDelete.map((f) => unlink(join(BACKUPS_DIR, f))));
  } catch {
    // Best-effort rotation; never fail a patch because of backup cleanup
  }
}

function sha256(content: string): string {
  if (!content) return sha256("{}");
  return createHash("sha256").update(content, "utf8").digest("hex");
}
