/**
 * R6 — Secrets / Hardcoded Credentials Scan Module
 * Detects AWS keys, GitHub tokens, private key blocks
 */

import * as fs from 'fs';
import * as path from 'path';
import { ScanContext, ScanFinding, ScannerModule } from '../types';

const SECRET_PATTERNS: Array<{
  name: string;
  regex: RegExp;
  message: string;
}> = [
  {
    name: 'aws-access-key',
    regex: /AKIA[0-9A-Z]{16}/g,
    message: 'Hardcoded AWS access key detected',
  },
  {
    name: 'github-token',
    regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    message: 'Hardcoded GitHub token detected',
  },
  {
    name: 'private-key-block',
    regex: /-----BEGIN (RSA |OPENSSH |PGP |EC )?PRIVATE KEY-----/g,
    message: 'Private key block detected',
  },
  {
    name: 'slack-token',
    regex: /xox[baprs]-[0-9a-zA-Z\-]+/g,
    message: 'Hardcoded Slack token detected',
  },
  {
    name: 'generic-api-key',
    regex: /(?:api[_-]?key|apikey|api[_-]?secret)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']/gi,
    message: 'Possible hardcoded API key detected',
  },
];

export class SecretsScanModule implements ScannerModule {
  name = 'secrets-scan';

  scan(ctx: ScanContext): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const codeFiles = ctx.sourceFiles.filter((f) =>
      /\.(js|ts|jsx|tsx|py|mjs|cjs|json|yaml|yml|md)$/.test(f)
    );

    for (const relPath of codeFiles) {
      const fullPath = path.join(ctx.skillPath, relPath);
      const content = fs.readFileSync(fullPath, 'utf-8');

      for (const pattern of SECRET_PATTERNS) {
        const matches = content.match(pattern.regex);
        if (matches) {
          for (const match of matches) {
            findings.push({
              ruleId: 'R6-secrets-scan',
              tier: 'blocker',
              severity: 'P0',
              criticalTag: '[critical:security]',
              message: `${pattern.message}: ${match.substring(0, 20)}...`,
              file: relPath,
              category: 'malicious-code',
              evidence: match.substring(0, 40),
              recommendation: 'Remove hardcoded secrets; use @quickport/orchestrator/credentials/* API',
            });
          }
        }
      }
    }

    return findings;
  }
}
