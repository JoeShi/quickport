/**
 * @quickport/install-pipeline — public types
 *
 * Status: SCAFFOLD v0 — interface candidate, awaits Arch ADR-002 §模块分解.
 *
 * Pipeline stages (mirrors §3 of notes/quickport-install-pipeline-draft.md):
 *
 *   user query → search (marketplace-adapter)
 *     ↓ SkillListing[]
 *   user picks → preview (fetch + scan + decide)
 *     ↓ PreviewResult
 *   if requires-user-consent → consent dialog
 *     ↓ InstallContext.userConsent
 *   commit (extract → register MCP server → audit → verify)
 *     ↓ CommitResult
 *
 * Audit chain (canonical, Gatekeeper a188dca4 + Arch d7873f09):
 *   ScanResult.eventId → InstallConsentAcknowledgedEvent.scanEventRef
 *                     → QuickConfigPatchedEvent.scanEventRef
 */

import type { ScanResult, SkillManifest as ScannerManifest } from '../scanner/index.js';
import type { SkillSource, SkillPackage } from '../marketplace-adapter/index.js';

/**
 * Per-install-attempt context (immutable, passed through pipeline stages).
 */
export interface InstallContext {
  /** Marketplace source */
  source: SkillSource;
  /** Source-scoped skill identifier */
  skillId: string;
  /** Specific version to install */
  version: string;
  /**
   * User consent payload — required when scan decision is 'requires-user-consent'.
   * Omitted means user has not (yet) consented; commit() will throw if required.
   */
  userConsent?: {
    /** finding.ref values the user explicitly accepted */
    acceptedFindingRefs: string[];
    /**
     * User-supplied consent note (per ADR-001 5-子字段例外条款).
     * Stored verbatim in audit log InstallConsentAcknowledgedEvent.
     */
    consentNote: string;
  };
}

/**
 * Result of preview() — combines fetch + scan, decides next step.
 */
export interface PreviewResult {
  /** Local package (already fetched, ready for commit) */
  package: SkillPackage;
  /** Parsed skill manifest from package */
  manifest: ScannerManifest;
  /** Scanner findings + decision (canonical from scanner) */
  scanResult: ScanResult;
  /**
   * Convenience getter: scanResult.decision.
   * - 'allowed': commit() can proceed without consent
   * - 'requires-user-consent': UI must collect consent → fill InstallContext.userConsent before commit()
   * - 'blocked': commit() will refuse; show findings, do NOT install
   */
  decision: ScanResult['decision'];
}

/**
 * Result of commit() — successful install snapshot.
 */
export interface CommitResult {
  /** ISO 8601 timestamp of install completion */
  installedAt: string;
  /** Filesystem path where the skill is installed */
  skillPath: string;
  /** If MCP server, path to the launcher binary */
  mcpServerPath?: string;
  /** If MCP server, server id (key in mcp_config.json) */
  mcpServerId?: string;
  /** Optional post-install verify result (one stdio handshake) */
  verifyResult?: {
    ok: boolean;
    /** Capabilities the MCP server actually declared during initialize */
    declaredCapabilities: string[];
  };
  /** Audit event id chain for forensic queries */
  auditTrail: {
    scanEventId: string;
    consentEventId?: string;
    quickConfigPatchedEventId: string;
  };
}

/**
 * InstallPipeline — public API.
 *
 * Implementations live in `pipeline.ts`. UI (Tauri webview) and CLI both
 * consume this interface. Tests use a mock-scanner-backed implementation.
 */
export interface InstallPipeline {
  /**
   * Search marketplace(s) for skills matching `query`.
   * Aggregates across all registered sources, returns sorted/deduped listings.
   */
  search(query: string, opts?: { sources?: string[]; limit?: number }): Promise<
    Array<{ source: string; listing: import('../marketplace-adapter/index.js').SkillListing }>
  >;

  /**
   * Fetch the package, run scanner, return decision.
   * Does NOT touch ~/.quickwork/quickport/ filesystem yet (only temp scratch).
   */
  preview(ctx: InstallContext): Promise<PreviewResult>;

  /**
   * Commit the install. Requires preview() to have been called first
   * (engine implementation will scan again if no recent preview cached, AC-3'-bis).
   *
   * Calls (in order):
   *   1. Extract package to ~/.quickwork/quickport/skills/<name>/ (or mcp-servers/ for MCP type)
   *   2. emit InstallConsentAcknowledgedEvent (P1 path only)
   *   3. quickConfigPatcher.registerMcpServer(...)  (transitively writes capability-registry)
   *   4. Optional verify: spawn MCP server once, check capability declaration matches manifest
   *   5. emit InstalledEvent (telemetry for OQ-1 D metric)
   *
   * Failure modes:
   *   - decision='blocked' → throws InstallBlockedError, no fs/audit side effects
   *   - decision='requires-user-consent' but ctx.userConsent missing → throws ConsentRequiredError
   *   - patch failure → quick-config-patcher rolls back; we throw PatchFailedError
   *   - verify failure → we call uninstall(skillId) for cleanup; throw VerifyFailedError
   */
  commit(ctx: InstallContext): Promise<CommitResult>;

  /**
   * Uninstall a single skill. Idempotent. Removes:
   *   - ~/.quickwork/quickport/skills/<name>/ (or mcp-servers/<id>/)
   *   - mcp_config.json entry (via quickConfigPatcher.unregisterMcpServer)
   *   - capability-registry entry (transitively)
   * Does NOT delete user data directories the skill may have created elsewhere.
   */
  uninstall(skillId: string): Promise<void>;

  /**
   * QuickPort full-uninstall trigger (AC-11).
   * Iterates all managed servers via capability-registry and:
   *   1. quickConfigPatcher.uninstallAllManagedServers()  (diff-merge restore)
   *   2. Removes ~/.quickwork/quickport/{skills,mcp-servers,backups,state}/
   *   3. Final audit flush
   */
  uninstallAll(): Promise<void>;
}

// ─── Error types ───────────────────────────────────────────────────────────

export class InstallBlockedError extends Error {
  readonly code = 'INSTALL_BLOCKED';
  constructor(public readonly scanResult: ScanResult) {
    super(
      `Install blocked: ${scanResult.summary.P0} P0 finding(s). ` +
        `Skill cannot be installed without addressing these issues.`,
    );
  }
}

export class ConsentRequiredError extends Error {
  readonly code = 'CONSENT_REQUIRED';
  constructor(public readonly scanResult: ScanResult) {
    super(
      `User consent required: ${scanResult.summary.P1} P1 finding(s). ` +
        `Pass InstallContext.userConsent before retrying commit().`,
    );
  }
}

export class PatchFailedError extends Error {
  readonly code = 'PATCH_FAILED';
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
  }
}

export class VerifyFailedError extends Error {
  readonly code = 'VERIFY_FAILED';
  constructor(
    public readonly skillId: string,
    public readonly reason: string,
  ) {
    super(`Verify failed for ${skillId}: ${reason}`);
  }
}
