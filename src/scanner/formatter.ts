/**
 * Output Formatter
 * Format: <tier> <severity> [critical:*] ref:skill-name#<rule-id>
 * Aligned with v0.1 review protocol
 */

import { ScanResult, ScanFinding, CriticalTag } from './types';

export function formatFinding(
  finding: ScanFinding,
  skillName: string
): string {
  const parts: string[] = [];
  parts.push(finding.tier);
  parts.push(finding.severity);
  if (finding.criticalTag) {
    parts.push(finding.criticalTag);
  }
  parts.push(`ref:${skillName}#${finding.ruleId}`);

  let line = parts.join(' ');
  if (finding.message) {
    line += ` — ${finding.message}`;
  }
  if (finding.file) {
    line += ` (${finding.file}`;
    if (finding.line) {
      line += `:${finding.line}`;
    }
    line += ')';
  }
  return line;
}

export function formatReport(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(`# Scan Report: ${result.skillName}@${result.skillVersion}`);
  lines.push(`Scanner: v${result.scannerVersion} | Duration: ${result.durationMs}ms | At: ${result.scannedAt}`);
  lines.push('');
  lines.push(`## Summary: P0=${result.summary.P0} P1=${result.summary.P1} P2=${result.summary.P2}`);
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('✅ No findings');
    return lines.join('\n');
  }

  // Group by severity
  const bySeverity = {
    P0: result.findings.filter((f) => f.severity === 'P0'),
    P1: result.findings.filter((f) => f.severity === 'P1'),
    P2: result.findings.filter((f) => f.severity === 'P2'),
  };

  for (const sev of ['P0', 'P1', 'P2'] as const) {
    const findings = bySeverity[sev];
    if (findings.length === 0) continue;
    lines.push(`### ${sev} (${findings.length})`);
    for (const f of findings) {
      lines.push(`- ${formatFinding(f, result.skillName)}`);
      if (f.evidence) {
        lines.push(`  Evidence: \`${f.evidence}\``);
      }
      if (f.recommendation) {
        lines.push(`  Recommendation: ${f.recommendation}`);
      }
    }
    lines.push('');
  }

  return lines.join('\n');
}

export function formatReportJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

/**
 * Check if scan result blocks installation (any P0 finding)
 */
export function isBlocked(result: ScanResult): boolean {
  return result.findings.some((f) => f.severity === 'P0');
}

/**
 * Check if scan result requires explicit user acceptance (P1 findings)
 */
export function requiresAcceptance(result: ScanResult): boolean {
  return result.findings.some((f) => f.severity === 'P1');
}
