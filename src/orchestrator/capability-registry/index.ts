/**
 * @quickport/orchestrator/capability-registry
 *
 * QuickPort's private MCP server registration ledger.
 *
 * Design rationale (per @Arch d7873f09):
 *   We write to both mcp_config.json (Quick's config) AND our own registry.
 *   This keeps Quick's mcp_config.json schema clean (no `_quickport_managed` pollution)
 *   while giving us a robust source of truth for:
 *     - AC-11 diff-merge uninstall (what did WE register?)
 *     - Integrity checks (entryHash mismatch → tampered or version-bumped)
 *     - Audit trail (installedAt, installedVersion, managedBy)
 *
 * Registry file: ~/.quickwork/quickport/state/capability-registry.json
 *   (QuickPort-owned, NOT shared with Amazon Quick)
 *
 * R5 narrow waist: Only `@quickport/orchestrator/quick-config-patcher` calls register/unregister.
 * Do NOT import this module from skill code — blocker P0.
 *
 * Canonical interface per @Arch d7873f09:
 *   register(serverId, entry) / unregister(serverId) / list() / get(serverId)
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import os from "node:os";
import type { McpServerEntry } from "../quick-config-patcher/index.js";

// ─── Path constants ────────────────────────────────────────────────────────

const QUICKPORT_STATE_DIR = join(os.homedir(), ".quickwork", "quickport", "state");
export const CAPABILITY_REGISTRY_PATH = join(QUICKPORT_STATE_DIR, "capability-registry.json");

// ─── Schema ───────────────────────────────────────────────────────────────

export interface RegistryEntry {
  /** Server ID (key in mcp_config.json) */
  serverId: string;
  /** Snapshot of the McpServerEntry at registration time */
  entry: McpServerEntry;
  /** SHA-256 of JSON.stringify(entry) — integrity signal for tamper/version-bump detection */
  entryHash: string;
  /** ISO 8601 timestamp of initial registration */
  installedAt: string;
  /** Version of the MCP server package registered (from skill manifest) */
  installedVersion: string;
  /** Always "quickport" — the managed-by marker stays in our registry, not Quick's config */
  managedBy: "quickport";
}

export interface CapabilityRegistry {
  /** Schema version (semver) — for future migration */
  schemaVersion: "1.0";
  /** ISO 8601 last-modified timestamp */
  updatedAt: string;
  /** Map of serverId → RegistryEntry */
  entries: Record<string, RegistryEntry>;
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Register a managed MCP server in the capability registry.
 * Called by quick-config-patcher after successfully patching mcp_config.json.
 *
 * @param serverId  Unique server key (must match mcp_config.json key)
 * @param entry     Server launch config (snapshot stored for AC-11 integrity)
 * @param version   Version string from skill manifest
 */
export async function register(
  serverId: string,
  entry: McpServerEntry,
  version: string = "unknown"
): Promise<void> {
  const registry = await readRegistry();

  registry.entries[serverId] = {
    serverId,
    entry,
    entryHash: hashEntry(entry),
    installedAt: registry.entries[serverId]?.installedAt ?? new Date().toISOString(),
    installedVersion: version,
    managedBy: "quickport",
  };
  registry.updatedAt = new Date().toISOString();

  await writeRegistry(registry);
}

/**
 * Remove a server from the capability registry.
 * Called by quick-config-patcher after successfully removing from mcp_config.json.
 * Idempotent: no-op if serverId not present.
 *
 * @param serverId  Server ID to remove
 */
export async function unregister(serverId: string): Promise<void> {
  const registry = await readRegistry();
  if (!registry.entries[serverId]) return; // idempotent
  delete registry.entries[serverId];
  registry.updatedAt = new Date().toISOString();
  await writeRegistry(registry);
}

/**
 * List all QuickPort-managed server IDs.
 * Used by quick-config-patcher.uninstallAllManagedServers() for AC-11 diff-merge.
 */
export async function list(): Promise<RegistryEntry[]> {
  const registry = await readRegistry();
  return Object.values(registry.entries);
}

/**
 * Get a specific registry entry, or null if not managed by us.
 */
export async function get(serverId: string): Promise<RegistryEntry | null> {
  const registry = await readRegistry();
  return registry.entries[serverId] ?? null;
}

/**
 * Check if a server is managed by QuickPort (fast path for uninstall guard).
 */
export async function isManaged(serverId: string): Promise<boolean> {
  const registry = await readRegistry();
  return serverId in registry.entries;
}

// ─── Internal helpers ─────────────────────────────────────────────────────

async function readRegistry(): Promise<CapabilityRegistry> {
  try {
    const raw = await readFile(CAPABILITY_REGISTRY_PATH, "utf8");
    const parsed = JSON.parse(raw) as CapabilityRegistry;
    // Tolerate missing schemaVersion (first run after migration)
    parsed.entries ??= {};
    return parsed;
  } catch (err: any) {
    if (err.code === "ENOENT") {
      return {
        schemaVersion: "1.0",
        updatedAt: new Date().toISOString(),
        entries: {},
      };
    }
    throw err;
  }
}

async function writeRegistry(registry: CapabilityRegistry): Promise<void> {
  await mkdir(QUICKPORT_STATE_DIR, { recursive: true });
  // Write direct (not atomic) — registry is our private file, loss is recoverable
  // from mcp_config.json re-scan if needed. Quick never reads this file.
  await writeFile(
    CAPABILITY_REGISTRY_PATH,
    JSON.stringify(registry, null, 2) + "\n",
    { encoding: "utf8", mode: 0o600 } // owner-only: registry may contain version metadata
  );
}

function hashEntry(entry: McpServerEntry): string {
  return createHash("sha256")
    .update(JSON.stringify(entry), "utf8")
    .digest("hex")
    .slice(0, 16) + "...";
}
