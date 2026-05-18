/**
 * R5 — Install-Orchestrator Bypass Detection
 * Detects direct access to keychain APIs, audit log writes,
 * and mcp_config.json direct writes outside quick-config-patcher
 */

import * as fs from 'fs';
import * as path from 'path';
import { ScanContext, ScanFinding, ScannerModule } from '../types';

const BYPASS_PATTERNS_JS = [
  // Direct keychain access
  { regex: /require\(['"]keytar['"]\)/g, msg: 'Direct keytar import (bypass orchestrator)' },
  { regex: /require\(['"]node-credential-manager['"]\)/g, msg: 'Direct credential manager import' },
  { regex: /spawn\(['"]security['"],\s*\['add-generic-password'/g, msg: 'Direct macOS security command' },
  // Direct audit log write
  { regex: /writeFile.*\.audit\.json/g, msg: 'Direct audit log write (bypass orchestrator)' },
  // Direct mcp_config.json write (outside quick-config-patcher)
  { regex: /writeFile.*mcp_config\.json/g, msg: 'Direct mcp_config.json write (bypass quick-config-patcher)' },
  { regex: /writeFile.*capability-registry\.json/g, msg: 'Direct capability-registry.json write (bypass capability-registry)' },
];

export class NarrowWaistBypassModule implements ScannerModule {
  name = 'narrow-waist-bypass';

  scan(ctx: ScanContext): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const codeFiles = ctx.sourceFiles.filter((f) =>
      /\.(js|ts|jsx|tsx|mjs|cjs)$/.test(f)
    );

    for (const relPath of codeFiles) {
      // Skip orchestrator modules (they are allowed to access these APIs)
      if (relPath.includes('orchestrator/')) continue;

      const fullPath = path.join(ctx.skillPath, relPath);
      const content = fs.readFileSync(fullPath, 'utf-8');

      for (const pattern of BYPASS_PATTERNS_JS) {
        const matches = content.match(pattern.regex);
        if (matches) {
          for (const match of matches) {
            findings.push({
              ruleId: 'R5-narrow-waist-bypass',
              tier: 'blocker',
              severity: 'P0',
              criticalTag: '[critical:security]',
              message: pattern.msg,
              file: relPath,
              category: 'privilege-escalation',
              evidence: match,
              recommendation: 'Use @quickport/orchestrator/* APIs instead of direct OS access',
            });
          }
        }
      }
    }

    return findings;
  }
}
