/**
 * Skill Scanner Engine - Core Types
 * Output format: <tier> <severity> [critical:*] ref:skill-name#<rule-id>
 * aligned with v0.1 review protocol
 */

export type Severity = 'P0' | 'P1' | 'P2';
export type Tier = 'blocker' | 'suggestion' | 'nit';
export type CriticalTag = '[critical:security]' | '[critical:perf]';
export type ThreatCategory =
  | 'malicious-code'
  | 'data-exfiltration'
  | 'privilege-escalation'
  | 'supply-chain-poisoning';

export interface ScanFinding {
  /** Rule ID, e.g., "R3-manifest-integrity" */
  ruleId: string;
  /** Tier: blocker / suggestion / nit */
  tier: Tier;
  /** Severity: P0 / P1 / P2 */
  severity: Severity;
  /** critical tag for security/perf */
  criticalTag?: CriticalTag;
  /** Human-readable message */
  message: string;
  /** File path relative to skill root */
  file?: string;
  /** Line number if applicable */
  line?: number;
  /** Column if applicable */
  column?: number;
  /** Threat category */
  category: ThreatCategory;
  /** Raw evidence (snippet, diff, etc.) */
  evidence?: string;
  /** Recommended fix or mitigation */
  recommendation?: string;
}

export interface SkillManifest {
  name: string;
  version: string;
  description?: string;
  /** Declared capabilities */
  capabilities?: CapabilityDeclaration[];
  /** Declared outbound domains */
  domains?: string[];
  /** Declared FS paths */
  fsPaths?: string[];
  /** Entry point */
  main?: string;
  /** Dependencies */
  dependencies?: Record<string, string>;
  /** Dev dependencies */
  devDependencies?: Record<string, string>;
  /** Author / publisher */
  author?: string;
  /** License */
  license?: string;
  /** Raw manifest object for diff scanning */
  [key: string]: unknown;
}

export interface CapabilityDeclaration {
  name: string;
  /** e.g., "im.send", "email.read", "fs.read" */
  resource: string;
  /** Detailed scope, e.g., "~/.config" */
  scope?: string;
  /** Why this capability is needed */
  reason?: string;
}

export interface ScanContext {
  /** Skill name */
  skillName: string;
  /** Absolute path to skill directory */
  skillPath: string;
  /** Parsed manifest */
  manifest: SkillManifest;
  /** Manifest raw text for diff analysis */
  manifestRaw: string;
  /** All source files (relative paths) */
  sourceFiles: string[];
  /** Temporary working directory */
  tmpDir?: string;
}

export interface ScanResult {
  /** Unique event ID for audit trail join (per Arch 5a3c2c91) */
  eventId: string;
  skillName: string;
  skillVersion: string;
  /** Total findings */
  findings: ScanFinding[];
  /** Summary by severity */
  summary: {
    P0: number;
    P1: number;
    P2: number;
  };
  /** Scan duration in ms */
  durationMs: number;
  /** Scanner engine version */
  scannerVersion: string;
  /** ISO timestamp */
  scannedAt: string;
  /** Coverage dimensions scanned */
  coverage: string[];
  /** Confidence based on coverage */
  confidence: 'high' | 'medium' | 'low';
  /** Known blind spots */
  knownBlindSpots: string[];
  /** Auto decision for install pipeline */
  decision: 'allowed' | 'requires-user-consent' | 'blocked';
}

export interface ScannerModule {
  name: string;
  /** Run the scan module */
  scan(ctx: ScanContext): Promise<ScanFinding[]> | ScanFinding[];
}
