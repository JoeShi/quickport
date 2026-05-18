/**
 * R2 — FS Path Diff Module
 * Detects file system writes outside allowed paths
 * and reads of sensitive paths
 */

import * as fs from 'fs';
import * as path from 'path';
import { ScanContext, ScanFinding, ScannerModule } from '../types';

const SENSITIVE_PATHS = [
  '~/.ssh',
  '~/.aws',
  '~/.gnupg',
  '~/.bashrc',
  '~/.zshrc',
  '/etc',
  '/usr/bin',
  '/usr/local/bin',
  '~/Library/LaunchAgents',
  '/etc/cron.d',
  '~/.quickwork/mcp_config.json', // Critical shared file
];

const FS_WRITE_PATTERNS_JS = [
  /fs\.writeFile\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /fs\.writeFileSync\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /fs\.appendFile\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /fs\.appendFileSync\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /fs\.open\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /fs\.createWriteStream\s*\(\s*['"`]([^'"`]+)['"`]/g,
];

const FS_READ_PATTERNS_JS = [
  /fs\.readFile\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /fs\.readFileSync\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /fs\.createReadStream\s*\(\s*['"`]([^'"`]+)['"`]/g,
];

function isSensitivePath(targetPath: string): boolean {
  const normalized = targetPath.replace(/^~\//, process.env.HOME + '/');
  for (const sensitive of SENSITIVE_PATHS) {
    const sensNorm = sensitive.replace(/^~\//, process.env.HOME + '/');
    if (normalized.startsWith(sensNorm) || normalized === sensNorm) {
      return true;
    }
  }
  return false;
}

function isOutsideSkillDir(targetPath: string, skillName: string): boolean {
  const normalized = targetPath.replace(/^~\//, process.env.HOME + '/');
  const allowedPrefix = path.join(
    process.env.HOME || '/tmp',
    '.quickwork',
    'quickport',
    'skills',
    skillName
  );
  return !normalized.startsWith(allowedPrefix);
}

function extractPathsFromFile(
  filePath: string,
  patterns: RegExp[]
): Array<{ path: string; line: number }> {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const results: Array<{ path: string; line: number }> = [];

  for (let i = 0; i < lines.length; i++) {
    for (const pattern of patterns) {
      const lineContent = lines[i];
      let match;
      pattern.lastIndex = 0;
      while ((match = pattern.exec(lineContent)) !== null) {
        results.push({ path: match[1], line: i + 1 });
      }
    }
  }

  return results;
}

export class FsDiffModule implements ScannerModule {
  name = 'fs-path-diff';

  scan(ctx: ScanContext): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const codeFiles = ctx.sourceFiles.filter((f) =>
      /\.(js|ts|jsx|tsx|mjs|cjs)$/.test(f)
    );

    for (const relPath of codeFiles) {
      const fullPath = path.join(ctx.skillPath, relPath);

      // Check writes
      const writes = extractPathsFromFile(fullPath, FS_WRITE_PATTERNS_JS);
      for (const w of writes) {
        if (isSensitivePath(w.path)) {
          findings.push({
            ruleId: 'R2-fs-write-sensitive',
            tier: 'blocker',
            severity: 'P0',
            criticalTag: '[critical:security]',
            message: `Writing to sensitive path: ${w.path}`,
            file: relPath,
            line: w.line,
            category: 'privilege-escalation',
            evidence: w.path,
            recommendation: `Avoid writing to ${w.path}. Use ~/.quickwork/quickport/skills/${ctx.skillName}/ instead`,
          });
        } else if (isOutsideSkillDir(w.path, ctx.skillName)) {
          findings.push({
            ruleId: 'R2-fs-write-outside-skill-dir',
            tier: 'blocker',
            severity: 'P0',
            criticalTag: '[critical:security]',
            message: `Writing outside skill directory: ${w.path}`,
            file: relPath,
            line: w.line,
            category: 'privilege-escalation',
            evidence: w.path,
            recommendation: `Write to ~/.quickwork/quickport/skills/${ctx.skillName}/ or declare in manifest.capabilities.fs.write`,
          });
        }
      }

      // Check reads of sensitive paths
      const reads = extractPathsFromFile(fullPath, FS_READ_PATTERNS_JS);
      for (const r of reads) {
        if (isSensitivePath(r.path)) {
          findings.push({
            ruleId: 'R2-fs-read-sensitive',
            tier: 'blocker',
            severity: 'P0',
            criticalTag: '[critical:security]',
            message: `Reading sensitive path: ${r.path}`,
            file: relPath,
            line: r.line,
            category: 'privilege-escalation',
            evidence: r.path,
            recommendation: `Avoid reading ${r.path} unless explicitly declared in manifest.capabilities.fs.read`,
          });
        }
      }
    }

    return findings;
  }
}
