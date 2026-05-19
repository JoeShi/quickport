/**
 * R5 — Install-Orchestrator Bypass Detection
 * Detects direct access to keychain APIs, audit log writes,
 * mcp_config.json writes, and capability-registry.json writes
 * outside the allowed orchestrator modules.
 *
 * Aligned with Semgrep YAML v0.1.2 rules:
 * - quickwork-R5-js-direct-keychain-access
 * - quickwork-R5-py-direct-keychain-access
 * - quickwork-R5-direct-audit-log-write
 * - quickwork-R5-direct-quick-config-write
 * - quickwork-R5-direct-capability-registry-write
 */

import * as fs from 'fs';
import * as path from 'path';
import { ScanContext, ScanFinding, ScannerModule } from '../types';

interface BypassPattern {
  name: string;
  regex: RegExp;
  message: string;
  ruleId: string;
  category: string;
  recommendation: string;
}

const JS_BYPASS_PATTERNS: BypassPattern[] = [
  // Keychain / credential APIs
  {
    name: 'keytar-import',
    regex: /require\(['"]keytar['"]\)/g,
    message: 'Direct keytar import (bypass orchestrator credentials API)',
    ruleId: 'R5-direct-keychain-access',
    category: 'privilege-escalation',
    recommendation: 'Use @quickport/orchestrator/credentials/* API instead of keytar',
  },
  {
    name: 'node-credential-manager-import',
    regex: /require\(['"]node-credential-manager['"]\)/g,
    message: 'Direct node-credential-manager import (bypass orchestrator)',
    ruleId: 'R5-direct-keychain-access',
    category: 'privilege-escalation',
    recommendation: 'Use @quickport/orchestrator/credentials/* API',
  },
  {
    name: 'credential-manager-import',
    regex: /require\(['"]credential-manager['"]\)/g,
    message: 'Direct credential-manager import (bypass orchestrator)',
    ruleId: 'R5-direct-keychain-access',
    category: 'privilege-escalation',
    recommendation: 'Use @quickport/orchestrator/credentials/* API',
  },
  {
    name: 'macos-security-command',
    regex: /spawn\(['"]security['"]|exec\(['"]security\s+add-generic-password/g,
    message: 'Direct macOS security command (bypass orchestrator credentials API)',
    ruleId: 'R5-direct-keychain-access',
    category: 'privilege-escalation',
    recommendation: 'Use @quickport/orchestrator/credentials/* API',
  },
  // Audit log direct write
  {
    name: 'audit-log-direct-write',
    regex: /writeFile(?:Sync)?\(['"`](?:~\/\.quickwork\/|.*?quickport\/state\/)\.audit\.json['"`]/g,
    message: 'Direct audit log write (bypass orchestrator audit API)',
    ruleId: 'R5-direct-audit-log-write',
    category: 'privilege-escalation',
    recommendation: 'Use @quickport/orchestrator/audit/log() API',
  },
  // mcp_config.json direct write (string literals)
  {
    name: 'mcp-config-string-literal',
    regex: /writeFile(?:Sync)?\(['"`][^'"`]*mcp_config\.json['"`]/g,
    message: 'Direct mcp_config.json write (bypass quick-config-patcher 5-invariants protocol)',
    ruleId: 'R5-direct-quick-config-write',
    category: 'privilege-escalation',
    recommendation: 'Use @quickport/orchestrator/quick-config-patcher/* API with atomic write + backup + schema validate + audit + rollback',
  },
  // mcp_config.json template literals
  {
    name: 'mcp-config-template-literal',
    regex: /writeFile(?:Sync)?\(`\$\{[^}]*\}\/\.quickwork\/mcp_config\.json`/g,
    message: 'Dynamic mcp_config.json path write (bypass quick-config-patcher)',
    ruleId: 'R5-direct-quick-config-write',
    category: 'privilege-escalation',
    recommendation: 'Use @quickport/orchestrator/quick-config-patcher/* API',
  },
  // mcp_config.json path.join
  {
    name: 'mcp-config-path-join',
    regex: /writeFile(?:Sync)?\(path\.join\([^)]*['"`].quickwork['"`],?\s*['"`]mcp_config\.json['"`]\)/g,
    message: 'path.join mcp_config.json write (bypass quick-config-patcher)',
    ruleId: 'R5-direct-quick-config-write',
    category: 'privilege-escalation',
    recommendation: 'Use @quickport/orchestrator/quick-config-patcher/* API',
  },
  // capability-registry.json direct write
  {
    name: 'capability-registry-string-literal',
    regex: /writeFile(?:Sync)?\(['"`][^'"`]*capability-registry\.json['"`]/g,
    message: 'Direct capability-registry.json write (bypass capability-registry module)',
    ruleId: 'R5-direct-capability-registry-write',
    category: 'privilege-escalation',
    recommendation: 'Use @quickport/orchestrator/capability-registry/* API',
  },
  // capability-registry.json template literals
  {
    name: 'capability-registry-template-literal',
    regex: /writeFile(?:Sync)?\(`\$\{[^}]*\}\/quickport\/state\/capability-registry\.json`/g,
    message: 'Dynamic capability-registry.json path write (bypass capability-registry)',
    ruleId: 'R5-direct-capability-registry-write',
    category: 'privilege-escalation',
    recommendation: 'Use @quickport/orchestrator/capability-registry/* API',
  },
];

const PY_BYPASS_PATTERNS: BypassPattern[] = [
  {
    name: 'python-keyring-access',
    regex: /keyring\.(set_password|get_password|delete_password)\s*\(/g,
    message: 'Direct Python keyring access (bypass orchestrator credentials API)',
    ruleId: 'R5-py-direct-keychain-access',
    category: 'privilege-escalation',
    recommendation: 'Use @quickport/orchestrator/credentials/* API',
  },
];

function checkFile(
  filePath: string,
  relPath: string,
  patterns: BypassPattern[],
  findings: ScanFinding[]
): void {
  const content = fs.readFileSync(filePath, 'utf-8');

  for (const pattern of patterns) {
    const matches = content.match(pattern.regex);
    if (matches) {
      for (const match of matches) {
        findings.push({
          ruleId: pattern.ruleId,
          tier: 'blocker',
          severity: 'P0',
          criticalTag: '[critical:security]',
          message: pattern.message,
          file: relPath,
          category: pattern.category as any,
          evidence: match.substring(0, 80),
          recommendation: pattern.recommendation,
        });
      }
    }
  }
}

export class NarrowWaistBypassModule implements ScannerModule {
  name = 'narrow-waist-bypass';

  scan(ctx: ScanContext): ScanFinding[] {
    const findings: ScanFinding[] = [];

    const jsFiles = ctx.sourceFiles.filter((f) =>
      /\.(js|ts|jsx|tsx|mjs|cjs)$/.test(f)
    );

    const pyFiles = ctx.sourceFiles.filter((f) => f.endsWith('.py'));

    for (const relPath of jsFiles) {
      // Skip orchestrator modules (they are allowed to access these APIs)
      if (relPath.includes('orchestrator/')) continue;
      // Skip test files (false positive exclusion per Semgrep YAML)
      if (/\.(test|spec)\.(ts|js)$/.test(relPath)) continue;
      if (relPath.includes('/test/') || relPath.includes('/tests/')) continue;
      if (relPath.includes('/fixtures/')) continue;

      const fullPath = path.join(ctx.skillPath, relPath);
      checkFile(fullPath, relPath, JS_BYPASS_PATTERNS, findings);
    }

    for (const relPath of pyFiles) {
      if (relPath.includes('orchestrator/')) continue;
      if (/\.(test|spec)\.py$/.test(relPath)) continue;
      if (relPath.includes('/test/') || relPath.includes('/tests/')) continue;

      const fullPath = path.join(ctx.skillPath, relPath);
      checkFile(fullPath, relPath, PY_BYPASS_PATTERNS, findings);
    }

    return findings;
  }
}
