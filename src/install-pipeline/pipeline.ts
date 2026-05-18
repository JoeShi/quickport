/**
 * @quickport/install-pipeline — pipeline implementation (SCAFFOLD v0)
 *
 * Status: NOT FOR PRODUCTION USE. Awaits Arch ADR-002 §模块分解 to lock final
 * dependency-injection topology. This scaffold demonstrates the public API
 * shape against canonical scanner / quick-config-patcher interfaces so the
 * §模块分解 段 can cite real code instead of pseudo-code.
 *
 * What is real:
 *   - Public API surface (InstallPipeline interface in types.ts)
 *   - Decision dispatch on scanResult.decision
 *   - Audit trail wiring (scanEventId → consent → quickConfigPatched)
 *   - Error type taxonomy
 *
 * What is stubbed:
 *   - extract logic (assumes pre-extracted dir for v0)
 *   - verify (always returns ok=true placeholder)
 *   - search aggregation across multiple sources (single source only)
 *   - audit log emission (no-op for now; awaits @quickport/orchestrator/audit interface lock)
 */

import { resolve } from 'node:path';
import { mkdir, cp, rm } from 'node:fs/promises';
import { homedir } from 'node:os';

import type { ScannerEngine, SkillManifest } from '../scanner/index.js';
import { isBlocked, requiresAcceptance } from '../scanner/formatter.js';
import {
  registerMcpServer,
  unregisterMcpServer,
  uninstallAllManagedServers,
} from '../orchestrator/quick-config-patcher/index.js';
import { list as listManaged } from '../orchestrator/capability-registry/index.js';
import { parseManifest } from '../scanner/manifest.js';

import type { SkillSource } from '../marketplace-adapter/index.js';
import {
  type CommitResult,
  type InstallContext,
  type InstallPipeline,
  type PreviewResult,
  ConsentRequiredError,
  InstallBlockedError,
  PatchFailedError,
} from './types.js';

const QUICKPORT_HOME = resolve(homedir(), '.quickwork', 'quickport');
const SKILLS_DIR = resolve(QUICKPORT_HOME, 'skills');
const MCP_SERVERS_DIR = resolve(QUICKPORT_HOME, 'mcp-servers');

export interface InstallPipelineDeps {
  scanner: ScannerEngine;
  /** Registered marketplace sources; first match by source.id wins for fetchPackage */
  sources: SkillSource[];
}

export class DefaultInstallPipeline implements InstallPipeline {
  constructor(private readonly deps: InstallPipelineDeps) {}

  // ─── search ──────────────────────────────────────────────────────────────

  async search(
    query: string,
    opts: { sources?: string[]; limit?: number } = {},
  ): Promise<
    Array<{
      source: string;
      listing: import('../marketplace-adapter/types.js').SkillListing;
    }>
  > {
    const sources = opts.sources
      ? this.deps.sources.filter(s => opts.sources!.includes(s.id))
      : this.deps.sources;

    const results = await Promise.allSettled(
      sources.map(async source => {
        const listings = await source.search(query, { limit: opts.limit });
        return listings.map(listing => ({ source: source.id, listing }));
      }),
    );

    return results
      .filter(
        (r): r is PromiseFulfilledResult<
          Array<{ source: string; listing: import('../marketplace-adapter/types.js').SkillListing }>
        > => r.status === 'fulfilled',
      )
      .flatMap(r => r.value);
  }

  // ─── preview ─────────────────────────────────────────────────────────────

  async preview(ctx: InstallContext): Promise<PreviewResult> {
    const source = this.lookupSource(ctx.source.id);
    const pkg = await source.fetchPackage(ctx.skillId, ctx.version);

    // SCAFFOLD: assume pre-extracted package; real impl unpacks tarball first.
    if (!pkg.isExtracted) {
      throw new Error(
        'preview(): tarball extract not implemented in scaffold v0 (awaits ADR-002 §extract).',
      );
    }

    const manifest = parseManifest(pkg.localPath);
    const scanResult = await this.deps.scanner.scan(pkg.localPath);

    return {
      package: pkg,
      manifest,
      scanResult,
      decision: scanResult.decision,
    };
  }

  // ─── commit ──────────────────────────────────────────────────────────────

  async commit(ctx: InstallContext): Promise<CommitResult> {
    const preview = await this.preview(ctx);
    const { scanResult, manifest, package: pkg } = preview;

    // Stage 1: decision gate
    if (isBlocked(scanResult)) {
      throw new InstallBlockedError(scanResult);
    }
    if (requiresAcceptance(scanResult) && !ctx.userConsent) {
      throw new ConsentRequiredError(scanResult);
    }

    // Stage 2: emit consent audit (P1 path)
    let consentEventId: string | undefined;
    if (ctx.userConsent) {
      consentEventId = await this.emitConsentEvent(ctx, scanResult);
    }

    // Stage 3: extract → install destination
    const skillName = manifest.name;
    const isMcpServer = manifest.type === 'mcp-server';
    const destBase = isMcpServer ? MCP_SERVERS_DIR : SKILLS_DIR;
    const destPath = resolve(destBase, skillName);

    await mkdir(destBase, { recursive: true });
    // SCAFFOLD: simple cp from already-extracted dir; real impl handles tarball + signature verify.
    await cp(pkg.localPath, destPath, { recursive: true, force: true });

    // Stage 4: register MCP server (if applicable) — patches mcp_config.json AND capability-registry
    let mcpServerId: string | undefined;
    let quickConfigPatchedEventId: string;
    if (isMcpServer) {
      mcpServerId = skillName;
      const entry = this.buildMcpEntry(manifest, destPath);
      try {
        await registerMcpServer(mcpServerId, entry, manifest.version, scanResult.eventId);
      } catch (err) {
        // Roll back filesystem changes
        await rm(destPath, { recursive: true, force: true });
        throw new PatchFailedError(
          `Failed to register MCP server "${mcpServerId}" in mcp_config.json`,
          err,
        );
      }
      // quick-config-patcher emits its own QuickConfigPatchedEvent; we cite its eventId.
      // SCAFFOLD: capture not yet wired through audit module. Use scanEventId as placeholder ref.
      quickConfigPatchedEventId = `pending:${scanResult.eventId}`;
    } else {
      // Pure (non-MCP) skill — no Quick config touch.
      quickConfigPatchedEventId = `n/a:${scanResult.eventId}`;
    }

    // Stage 5: optional verify (stubbed — real impl spawns MCP server stdio handshake)
    const verifyResult = isMcpServer
      ? { ok: true, declaredCapabilities: ['(verify-not-implemented-in-scaffold)'] }
      : undefined;

    // Stage 6: telemetry for OQ-1 D metric (count of installs)
    await this.emitInstalledEvent(ctx, scanResult);

    return {
      installedAt: new Date().toISOString(),
      skillPath: destPath,
      mcpServerPath: isMcpServer ? destPath : undefined,
      mcpServerId,
      verifyResult,
      auditTrail: {
        scanEventId: scanResult.eventId,
        consentEventId,
        quickConfigPatchedEventId,
      },
    };
  }

  // ─── uninstall ───────────────────────────────────────────────────────────

  async uninstall(skillId: string): Promise<void> {
    // For MCP-server skills, unregister via patcher (also removes capability-registry entry).
    // For pure skills, just rm the dir.
    // SCAFFOLD: try both paths idempotently.
    try {
      await unregisterMcpServer(skillId);
    } catch {
      // Not registered — pure skill or already removed. Continue.
    }
    const candidates = [resolve(MCP_SERVERS_DIR, skillId), resolve(SKILLS_DIR, skillId)];
    for (const dir of candidates) {
      await rm(dir, { recursive: true, force: true });
    }
  }

  async uninstallAll(): Promise<void> {
    // Step 1: diff-merge restore mcp_config.json (Jack's quick-config-patcher does the heavy lifting)
    await uninstallAllManagedServers();
    // Step 2: remove our namespace
    await rm(QUICKPORT_HOME, { recursive: true, force: true });
  }

  // ─── helpers ─────────────────────────────────────────────────────────────

  private lookupSource(sourceId: string): SkillSource {
    const found = this.deps.sources.find(s => s.id === sourceId);
    if (!found) throw new Error(`Unknown source: ${sourceId}`);
    return found;
  }

  private buildMcpEntry(
    manifest: SkillManifest,
    installedPath: string,
  ): import('../orchestrator/quick-config-patcher/index.js').McpServerEntry {
    // SCAFFOLD: a real impl reads manifest.entrypoint or runtime config to build this.
    // Today we just produce a deterministic shape so quick-config-patcher schema-validate passes.
    return {
      name: manifest.name,
      command: 'node', // placeholder — manifest must declare actual launcher
      args: [resolve(installedPath, 'server.mjs')],
      env: {},
    };
  }

  private async emitConsentEvent(
    _ctx: InstallContext,
    _scanResult: import('../scanner/index.js').ScanResult,
  ): Promise<string> {
    // SCAFFOLD: real impl calls @quickport/orchestrator/audit.write({
    //   type: 'INSTALL_CONSENT_ACKNOWLEDGED',
    //   scanEventRef: scanResult.eventId,
    //   acceptedFindingRefs: ctx.userConsent!.acceptedFindingRefs,
    //   consentNote: ctx.userConsent!.consentNote,
    //   ...
    // }) and returns the audit event id.
    return `consent:scaffold:${Date.now()}`;
  }

  private async emitInstalledEvent(
    _ctx: InstallContext,
    _scanResult: import('../scanner/index.js').ScanResult,
  ): Promise<void> {
    // SCAFFOLD: real impl emits telemetry for OQ-1 D metric.
  }
}

/**
 * Convenience factory: creates a default-configured InstallPipeline.
 * Real apps wire scanner + sources via DI container.
 */
export function createDefaultInstallPipeline(deps: InstallPipelineDeps): InstallPipeline {
  return new DefaultInstallPipeline(deps);
}

// Listed sources directory (for AC-11 sanity checks etc.)
export async function listManagedServers(): Promise<string[]> {
  const entries = await listManaged();
  return entries.map(e => e.serverId);
}
