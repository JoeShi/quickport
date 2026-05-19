/**
 * R7 — Dangerous / High-Risk API Detection
 * Detects eval/exec/code injection APIs and shell injection patterns.
 *
 * Aligned with Semgrep YAML v0.1.2 rules:
 * - quickwork-R7-eval-exec-inject (eval, Function, vm, child_process.exec with dynamic)
 * - quickwork-R7-bis-shell-injection (child_process.exec with template literal or dynamic input)
 */

import * as fs from 'fs';
import * as path from 'path';
import { ScanContext, ScanFinding, ScannerModule } from '../types';

interface DangerousApiPattern {
  name: string;
  regex: RegExp;
  message: string;
  ruleId: string;
  category: string;
  recommendation: string;
}

const DANGEROUS_PATTERNS: DangerousApiPattern[] = [
  // R7 — eval / exec / code injection
  {
    name: 'eval-call',
    regex: /eval\s*\(/g,
    message: 'eval() can execute arbitrary code — P0',
    ruleId: 'R7-eval-exec-inject',
    category: 'privilege-escalation',
    recommendation: 'Use JSON.parse for data or a proper sandbox like vm2 (still risky)',
  },
  {
    name: 'function-constructor',
    regex: /new\s+Function\s*\(/g,
    message: 'Function() constructor compiles arbitrary JS — P0',
    ruleId: 'R7-eval-exec-inject',
    category: 'privilege-escalation',
    recommendation: 'Avoid dynamic code compilation; pre-compile known functions',
  },
  {
    name: 'vm-runInThisContext',
    regex: /vm\.runInThisContext\s*\(/g,
    message: 'vm.runInThisContext() runs code in same context — P0',
    ruleId: 'R7-eval-exec-inject',
    category: 'privilege-escalation',
    recommendation: 'Use isolated-vm with restricted API surface',
  },
  {
    name: 'vm-runInNewContext',
    regex: /vm\.runInNewContext\s*\(/g,
    message: 'vm.runInNewContext() with untrusted input — P0',
    ruleId: 'R7-eval-exec-inject',
    category: 'privilege-escalation',
    recommendation: 'Validate all inputs and use strict context options',
  },
  // R7-bis — Shell injection via child_process.exec/execSync/execFile with dynamic input
  {
    name: 'exec-template-literal',
    regex: /exec(?:Sync|File)?\s*\(`[^`]*\$\{/g,
    message: 'Shell command with template literal interpolation — injection risk P0',
    ruleId: 'R7-bis-shell-injection',
    category: 'injection',
    recommendation: 'Use execFile with array arguments or sanitize with shell-quote',
  },
  {
    name: 'exec-concatenation',
    regex: /exec(?:Sync|File)?\s*\([^)]*\+\s*[^)]*\)/g,
    message: 'Shell command with string concatenation — injection risk P0',
    ruleId: 'R7-bis-shell-injection',
    category: 'injection',
    recommendation: 'Use execFile with array arguments or sanitize with shell-quote',
  },
  {
    name: 'exec-variable-argument',
    regex: /exec(?:Sync)?\s*\(\$?[a-zA-Z_]\w*\s*\)/g,
    message: 'Shell command with dynamic variable — injection risk P0',
    ruleId: 'R7-bis-shell-injection',
    category: 'injection',
    recommendation: 'Use execFile with array arguments or sanitize with shell-quote',
  },
  // Dynamic require — can load arbitrary modules at runtime
  {
    name: 'dynamic-require',
    regex: /require\s*\(\$?[a-zA-Z_]\w*\s*\)/g,
    message: 'Dynamic require() with variable — arbitrary module loading risk P1',
    ruleId: 'R7-dynamic-require',
    category: 'privilege-escalation',
    recommendation: 'Use static imports or a known-allowlist require wrapper',
  },
];

export class DangerousApiModule implements ScannerModule {
  name = 'dangerous-api';

  scan(ctx: ScanContext): ScanFinding[] {
    const findings: ScanFinding[] = [];

    const sourceFiles = ctx.sourceFiles.filter((f) =>
      /\.(js|ts|jsx|tsx|mjs|cjs)$/.test(f)
    );

    for (const relPath of sourceFiles) {
      if (/\.(test|spec)\.(ts|js)$/.test(relPath)) continue;
      if (relPath.includes('/test/') || relPath.includes('/tests/')) continue;
      if (relPath.includes('/fixtures/')) continue;

      const fullPath = path.join(ctx.skillPath, relPath);
      const content = fs.readFileSync(fullPath, 'utf-8');

      for (const pattern of DANGEROUS_PATTERNS) {
        const matches = content.match(pattern.regex);
        if (matches) {
          for (const match of matches) {
            findings.push({
              ruleId: pattern.ruleId,
              tier: pattern.ruleId === 'R7-dynamic-require' ? 'suggestion' : 'blocker',
              severity: pattern.ruleId === 'R7-dynamic-require' ? 'P1' : 'P0',
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

    return findings;
  }
}
