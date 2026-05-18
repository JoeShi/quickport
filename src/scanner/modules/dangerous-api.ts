/**
 * R7 — Dangerous API Module
 * Detects eval, Function constructor, vm.runInThisContext
 */

import * as fs from 'fs';
import * as path from 'path';
import { ScanContext, ScanFinding, ScannerModule } from '../types';

const DANGEROUS_PATTERNS_JS = [
  /eval\s*\(/g,
  /new\s+Function\s*\(/g,
  /Function\s*\(/g,
  /vm\.runInThisContext\s*\(/g,
  /vm\.runInNewContext\s*\(/g,
];

const DANGEROUS_PATTERNS_PY = [
  /eval\s*\(/g,
  /exec\s*\(/g,
  /compile\s*\(/g,
];

export class DangerousApiModule implements ScannerModule {
  name = 'dangerous-api';

  scan(ctx: ScanContext): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const codeFiles = ctx.sourceFiles.filter((f) =>
      /\.(js|ts|jsx|tsx|py|mjs|cjs)$/.test(f)
    );

    for (const relPath of codeFiles) {
      const fullPath = path.join(ctx.skillPath, relPath);
      const content = fs.readFileSync(fullPath, 'utf-8');
      const isPython = relPath.endsWith('.py');
      const patterns = isPython ? DANGEROUS_PATTERNS_PY : DANGEROUS_PATTERNS_JS;

      for (const pattern of patterns) {
        const matches = content.match(pattern);
        if (matches) {
          for (let i = 0; i < matches.length; i++) {
            findings.push({
              ruleId: 'R7-dangerous-api',
              tier: 'blocker',
              severity: 'P0',
              criticalTag: '[critical:security]',
              message: `Dangerous API detected: ${matches[i].trim()}`,
              file: relPath,
              category: 'malicious-code',
              evidence: matches[i].trim(),
              recommendation: 'Remove eval/Function/vm calls unless explicitly declared in manifest + ADR exception',
            });
          }
        }
      }
    }

    return findings;
  }
}
