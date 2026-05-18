/**
 * Semgrep Runner Module
 * Wraps semgrep CLI, handles $SKILL_NAME template substitution,
 * and converts Semgrep JSON output to ScanFinding[]
 */

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ScanContext, ScanFinding, ScannerModule } from './types';

export interface SemgrepRule {
  id: string;
  languages: string[];
  severity: string;
  message: string;
  metadata?: {
    hf?: string[];
    tier?: string;
    severity?: string;
    dimension?: string[];
    [key: string]: unknown;
  };
}

function substituteMessage(msg: string, skillName: string): string {
  return msg.replace(/\$SKILL_NAME/g, skillName);
}

function parseSeverity(sev: string): 'P0' | 'P1' | 'P2' {
  switch (sev.toUpperCase()) {
    case 'ERROR':
      return 'P0';
    case 'WARNING':
      return 'P1';
    default:
      return 'P2';
  }
}

function parseTier(sev: string): 'blocker' | 'suggestion' | 'nit' {
  switch (sev.toUpperCase()) {
    case 'ERROR':
      return 'blocker';
    case 'WARNING':
      return 'suggestion';
    default:
      return 'nit';
  }
}

function determineCategory(ruleId: string): string {
  if (ruleId.includes('R1')) return 'data-exfiltration';
  if (ruleId.includes('R2')) return 'privilege-escalation';
  if (ruleId.includes('R3') || ruleId.includes('R7')) return 'malicious-code';
  if (ruleId.includes('R5')) return 'privilege-escalation';
  if (ruleId.includes('R6')) return 'malicious-code';
  if (ruleId.includes('R8')) return 'supply-chain-poisoning';
  return 'malicious-code';
}

/**
 * Run semgrep with given config file on skill path
 */
export async function runSemgrep(
  configPath: string,
  skillPath: string,
  skillName: string
): Promise<ScanFinding[]> {
  return new Promise((resolve, reject) => {
    const args = [
      'scan',
      '--config', configPath,
      '--json',
      '--no-error',
      '--disable-nosem',
      skillPath,
    ];

    const proc = spawn('semgrep', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (chunk) => { stdout += chunk; });
    proc.stderr.on('data', (chunk) => { stderr += chunk; });

    let notFound = false;

    proc.on('close', (code) => {
      if (notFound) {
        resolve([]);
        return;
      }
      if (code !== 0 && code !== 1) {
        reject(new Error(`semgrep exited ${code}: ${stderr}`));
        return;
      }
      try {
        const findings = parseSemgrepOutput(stdout, skillName, skillPath);
        resolve(findings);
      } catch (e) {
        reject(e);
      }
    });

    proc.on('error', (err) => {
      if ((err as any).code === 'ENOENT') {
        notFound = true;
      } else {
        reject(err);
      }
    });
  });
}

function parseSemgrepOutput(
  jsonStr: string,
  skillName: string,
  skillPath: string
): ScanFinding[] {
  const data = JSON.parse(jsonStr);
  const results = data.results || [];
  const findings: ScanFinding[] = [];

  for (const r of results) {
    const ruleId = r.check_id || 'unknown';
    const rawMessage = r.extra?.message || '';
    const severity = parseSeverity(r.extra?.severity || 'INFO');
    const tier = parseTier(r.extra?.severity || 'INFO');
    const dimensions = r.extra?.metadata?.dimension || [];
    const criticalTag = dimensions.includes('critical:security')
      ? '[critical:security]' as const
      : dimensions.includes('critical:perf')
        ? '[critical:perf]' as const
        : undefined;

    const finding: ScanFinding = {
      ruleId: ruleId.replace(/^quickwork-/, ''),
      tier,
      severity,
      criticalTag,
      message: substituteMessage(rawMessage, skillName),
      file: r.path ? path.relative(skillPath, r.path) : undefined,
      line: r.start?.line,
      column: r.start?.col,
      category: determineCategory(ruleId) as any,
      evidence: r.extra?.lines?.trim(),
    };
    findings.push(finding);
  }

  return findings;
}

/**
 * Scanner module wrapper for Semgrep rules
 */
export class SemgrepScannerModule implements ScannerModule {
  name = 'semgrep-ast-scanner';
  private configPath: string;

  constructor(configPath: string) {
    this.configPath = configPath;
  }

  async scan(ctx: ScanContext): Promise<ScanFinding[]> {
    if (!fs.existsSync(this.configPath)) {
      throw new Error(`Semgrep config not found: ${this.configPath}`);
    }
    return runSemgrep(this.configPath, ctx.skillPath, ctx.skillName);
  }
}
