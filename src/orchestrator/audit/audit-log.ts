/**
 * @quickport/orchestrator/audit/audit-log
 *
 * HF-4 / HF-6 implementation: PIPL-compliant audit logging.
 * ALL calls (inbound from Quick, outbound to Feishu/email, skill installs, MCP lifecycle,
 * Quick mcp_config.json patches) are logged through this module.
 * Direct writes to audit files = R5 blocker P0.
 *
 * HF-6 caller_source types (canonical per @Gatekeeper 4c58f6d7 + @Arch 6cd68744, 9 types):
 *   D/E modes: connector_registered, quick_call_inbound, local_call_attempted, outbound_to_3rdparty
 *   F mode additions: mcp_server_spawned, mcp_server_exited, mcp_tool_invoked
 *   Resources model: mcp_resource_subscribed, mcp_resource_updated_pushed
 *   Config patcher: quick_config_patched (new, per @Arch 6cd68744)
 */

import { appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import os from "node:os";
import { createHash } from "node:crypto";

// ─── Audit event types (HF-6 caller_source schema) ────────────────────────

export enum AuditEventType {
  // D/E mode events
  CONNECTOR_REGISTERED = "connector_registered",
  QUICK_CALL_INBOUND = "quick_call_inbound",
  LOCAL_CALL_ATTEMPTED = "local_call_attempted",
  OUTBOUND_TO_3RDPARTY = "outbound_to_3rdparty",
  // F mode (MCP) lifecycle events
  MCP_SERVER_SPAWNED = "mcp_server_spawned",
  MCP_SERVER_EXITED = "mcp_server_exited",
  MCP_TOOL_INVOKED = "mcp_tool_invoked",
  // F mode (Resources model) events
  MCP_RESOURCE_SUBSCRIBED = "mcp_resource_subscribed",
  MCP_RESOURCE_UPDATED_PUSHED = "mcp_resource_updated_pushed",
  // Skill install events
  SKILL_INSTALL_STARTED = "skill_install_started",
  SKILL_INSTALL_COMPLETED = "skill_install_completed",
  SKILL_INSTALL_BLOCKED = "skill_install_blocked",
  SKILL_SCAN_RESULT = "skill_scan_result",
  // Credential events
  CREDENTIAL_SET = "credential_set",
  CREDENTIAL_GET = "credential_get",
  CREDENTIAL_DELETED = "credential_deleted",
  // Token migration
  TOKEN_MIGRATION_COMPLETED = "token_migration_completed",
  // Quick config patcher (HF-6 9th type, per @Arch 6cd68744)
  QUICK_CONFIG_PATCHED = "quick_config_patched",
  // User consent acknowledgment for P1 (requires-user-consent) skills (per @Arch 601df1b6)
  INSTALL_CONSENT_ACKNOWLEDGED = "install_consent_acknowledged",
}

// ─── Event schemas ────────────────────────────────────────────────────────

export interface BaseAuditEvent {
  type: AuditEventType;
  timestamp: Date;
  callerFingerprint?: string;
}

export interface McpServerSpawnedEvent extends BaseAuditEvent {
  type: AuditEventType.MCP_SERVER_SPAWNED | AuditEventType.MCP_SERVER_EXITED;
  serverId: string;
  pid: number;
  entryPath?: string;
  exitCode?: number;
  signal?: string;
}

export interface McpToolInvokedEvent extends BaseAuditEvent {
  type: AuditEventType.MCP_TOOL_INVOKED;
  serverId: string;
  toolName: string;
  /** SHA-256 of the input args (never log raw args — may contain PII per PIPL) */
  argsHash: string;
  durationMs?: number;
  success: boolean;
}

export interface McpResourceEvent extends BaseAuditEvent {
  type: AuditEventType.MCP_RESOURCE_SUBSCRIBED | AuditEventType.MCP_RESOURCE_UPDATED_PUSHED;
  resourceUri: string;
  serverId: string;
}

export interface QuickCallEvent extends BaseAuditEvent {
  type: AuditEventType.QUICK_CALL_INBOUND | AuditEventType.LOCAL_CALL_ATTEMPTED | AuditEventType.OUTBOUND_TO_3RDPARTY;
  endpoint: string;
  method?: string;
  /** SHA-256 of caller token — never log raw token */
  callerTokenHash?: string;
  statusCode?: number;
  success: boolean;
}

export interface SkillEvent extends BaseAuditEvent {
  type: AuditEventType.SKILL_INSTALL_STARTED | AuditEventType.SKILL_INSTALL_COMPLETED | AuditEventType.SKILL_INSTALL_BLOCKED | AuditEventType.SKILL_SCAN_RESULT;
  /**
   * Unique event ID — for SKILL_SCAN_RESULT this is the foreign key target
   * referenced by QuickConfigPatchedEvent.scanEventRef and
   * InstallConsentAcknowledgedEvent.scanEventRef (per @Arch 601df1b6).
   */
  eventId?: string;
  skillName: string;
  skillVersion: string;
  scanDecision?: "pass" | "blocked" | "warning" | "allowed" | "requires-user-consent";
  blockerCount?: number;
  suggestionCount?: number;
}

/**
 * HF-6 9th caller_source type: emitted by @quickport/orchestrator/quick-config-patcher/*
 * whenever ~/.quickwork/mcp_config.json is patched (add/remove MCP server entries).
 * [critical:security] ANY patch to mcp_config.json MUST emit this event.
 *
 * Cross-event linkage (per @Arch 601df1b6):
 *   scanEventRef → SkillScanResultEvent.eventId (explicit foreign key, not timestamp join)
 *   This enables PIPL forensics across concurrent parallel skill installs without ambiguity.
 */
export interface QuickConfigPatchedEvent extends BaseAuditEvent {
  type: AuditEventType.QUICK_CONFIG_PATCHED;
  /** Unique event ID — used as foreign key by downstream events */
  eventId: string;
  /** Operation: "add" (register MCP server), "remove" (uninstall), "repair" (rollback) */
  operation: "add" | "remove" | "repair";
  /** Affected MCP server ID(s) */
  affectedServerIds: string[];
  /** SHA-256 of mcp_config.json content before patch */
  preHash: string;
  /** SHA-256 of mcp_config.json content after patch */
  postHash: string;
  /** Path to backup file created before this patch */
  backupPath: string;
  /**
   * Optional explicit ref to the SkillScanResultEvent.eventId that triggered this patch.
   * Should be set for all "add" operations from install pipeline.
   * Absent only for system-initiated repair/rollback operations.
   */
  scanEventRef?: string;
}

/**
 * Emitted when user explicitly acknowledges a P1 (requires-user-consent) scan finding.
 * ADR-001 5-subfield exception clause: must include consentNote explaining why risk is accepted.
 * Per @Arch 601df1b6: scanEventRef is REQUIRED here (must field, not optional).
 */
export interface InstallConsentAcknowledgedEvent extends BaseAuditEvent {
  type: AuditEventType.INSTALL_CONSENT_ACKNOWLEDGED;
  /** Unique event ID */
  eventId: string;
  /** Foreign key → SkillScanResultEvent.eventId (required, per @Arch 601df1b6) */
  scanEventRef: string;
  /** User-provided rationale for accepting the risk (ADR-001 5-subfield §consentNote) */
  consentNote: string;
  /** Approver identity (user handle or "local-user") */
  approvedBy: string;
  skillName: string;
  skillVersion: string;
}

export type AuditEvent =
  | McpServerSpawnedEvent
  | McpToolInvokedEvent
  | McpResourceEvent
  | QuickCallEvent
  | SkillEvent
  | QuickConfigPatchedEvent
  | InstallConsentAcknowledgedEvent
  | BaseAuditEvent;

// ─── Audit log writer ─────────────────────────────────────────────────────

// [critical:security] R5 narrow waist: ONLY this module writes here.
// Path = ~/.quickwork/quickport/state/ (our subordinate namespace under Amazon Quick's root)
// Per @Arch c3046784 + @Gatekeeper 3b238ace + OQ-24 resolved.
const AUDIT_LOG_DIR = join(os.homedir(), ".quickwork", "quickport", "state");
const AUDIT_LOG_PATH = join(AUDIT_LOG_DIR, "audit.ndjson");

let initialized = false;

async function ensureLogDir(): Promise<void> {
  if (initialized) return;
  await mkdir(AUDIT_LOG_DIR, { recursive: true });
  initialized = true;
}

/**
 * Write an audit event to the append-only audit log.
 * [critical:security] This is the ONLY path for writing audit events.
 * Direct writes to audit files from skill code = R5 blocker P0.
 */
export async function auditLog(event: AuditEvent): Promise<void> {
  await ensureLogDir();

  // Sanitize: replace any raw PII-bearing fields with hashes
  const sanitized = sanitizeEvent(event);

  const line = JSON.stringify({
    ...sanitized,
    timestamp: (sanitized.timestamp ?? new Date()).toISOString(),
  }) + "\n";

  await appendFile(AUDIT_LOG_PATH, line, "utf8");
}

/**
 * Hash a sensitive value (token, PII) for audit log inclusion.
 * Never log raw tokens or user data per PIPL requirements.
 */
export function hashForAudit(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16) + "...";
}

// ─── Sanitization ─────────────────────────────────────────────────────────

function sanitizeEvent(event: AuditEvent): AuditEvent {
  // Ensure no raw tokens leak into audit log
  const e = { ...event } as any;

  // Scrub any accidentally-included raw token fields
  const tokenFields = ["token", "accessToken", "password", "secret", "credential"];
  for (const field of tokenFields) {
    if (typeof e[field] === "string") {
      e[field] = hashForAudit(e[field]);
    }
  }

  return e;
}
