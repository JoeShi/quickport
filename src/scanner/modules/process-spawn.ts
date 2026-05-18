/**
 * R3 — Process Spawn Diff Module
 * Detects child_process / subprocess / os.system calls
 */

import * as fs from 'fs';
import * as path from 'path';
import { ScanContext, ScanFinding, ScannerModule } from '../types';

const SPAWN_PATTERNS_JS = [
  /child_process\.(spawn|exec|execFile|fork)\s*\(/g,
  /require\(['"]child_process['"]\)\.(spawn|exec|execFile|fork)\s*\(/g,
];

const SPAWN_PATTERNS_PY = [
  /subprocess\.(run|Popen|call|check_call|check_output)\s*\(/g,
  /os\.(system|popen|exec|execv|execve)\s*\(/g,
];

export class ProcessSpawnModule implements ScannerModule {
  name = 'process-spawn-diff';

  scan(ctx: ScanContext): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const codeFiles = ctx.sourceFiles.filter((f) =>
      /\.(js|ts|jsx|tsx|py|mjs|cjs)$/.test(f)
    );

    for (const relPath of codeFiles) {
      const fullPath = path.join(ctx.skillPath, relPath);
      const content = fs.readFileSync(fullPath, 'utf-8');
      const isPython = relPath.endsWith('.py');
      const patterns = isPython ? SPAWN_PATTERNS_PY : SPAWN_PATTERNS_JS;

      for (const pattern of patterns) {
        const matches = content.match(pattern);
        if (matches) {
          for (let i = 0; i < matches.length; i++) {
            findings.push({
              ruleId: 'R3-process-spawn-diff',
              tier: 'blocker',
              severity: 'P0',
              criticalTag: '[critical:security]',
              message: `Process spawn detected: ${matches[i].trim()}`,
              file: relPath,
              category: 'malicious-code',
              evidence: matches[i].trim(),
              recommendation: 'Declare in manifest.capabilities.process.spawn or remove; only @quickport/orchestrator/mcp-spawner may spawn',
            });
          }
        }
      }
    }

    return findings;
  }
}
