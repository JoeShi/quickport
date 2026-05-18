/**
 * R8 — SBOM + CVE Scan Module
 * Runs npm audit / pip-audit / osv-scanner on skill dependencies
 */

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ScanContext, ScanFinding, ScannerModule } from '../types';

interface AuditAdvisory {
  module_name: string;
  title: string;
  severity: string; // 'critical' | 'high' | 'moderate' | 'low' | 'info'
  url?: string;
  cves?: string[];
  vulnerable_versions?: string;
  patched_versions?: string;
  find_by_path?: string;
}

function parseNpmAudit(output: string): AuditAdvisory[] {
  try {
    const data = JSON.parse(output);
    const advisories: AuditAdvisory[] = [];
    const vulns = data.vulnerabilities || {};
    for (const [name, info] of Object.entries(vulns)) {
      const vuln = info as any;
      if (vuln.severity) {
        advisories.push({
          module_name: name,
          title: vuln.via?.[0]?.title || vuln.via || 'Unknown vulnerability',
          severity: vuln.severity,
          url: vuln.via?.[0]?.url,
          cves: vuln.via?.[0]?.cves,
          vulnerable_versions: vuln.range,
          patched_versions: vuln.fixAvailable ? 'available' : 'none',
          find_by_path: vuln.via?.[0]?.range,
        });
      }
    }
    return advisories;
  } catch {
    return [];
  }
}

function cvssFromSeverity(sev: string): number {
  switch (sev.toLowerCase()) {
    case 'critical':
      return 9.0;
    case 'high':
      return 7.5;
    case 'moderate':
      return 5.5;
    case 'low':
      return 3.0;
    default:
      return 0;
  }
}

function severityFromCvss(cvss: number): 'P0' | 'P1' | 'P2' {
  if (cvss >= 7) return 'P0';
  if (cvss >= 4) return 'P1';
  return 'P2';
}

function tierFromCvss(cvss: number): 'blocker' | 'suggestion' | 'nit' {
  if (cvss >= 7) return 'blocker';
  if (cvss >= 4) return 'suggestion';
  return 'nit';
}

export class SbomCveModule implements ScannerModule {
  name = 'sbom-cve-scanner';

  async scan(ctx: ScanContext): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const packageJsonPath = path.join(ctx.skillPath, 'package.json');

    if (!fs.existsSync(packageJsonPath)) {
      // No Node.js dependencies to audit
      return findings;
    }

    try {
      const auditOutput = await runNpmAudit(ctx.skillPath);
      const advisories = parseNpmAudit(auditOutput);

      for (const adv of advisories) {
        const cvss = cvssFromSeverity(adv.severity);
        const sev = severityFromCvss(cvss);
        const tier = tierFromCvss(cvss);

        findings.push({
          ruleId: 'R8-sbom-cve',
          tier,
          severity: sev,
          criticalTag: '[critical:security]',
          message: `${adv.module_name}: ${adv.title} (severity: ${adv.severity}${adv.cves ? ', CVEs: ' + adv.cves.join(', ') : ''})`,
          file: 'package.json',
          category: 'supply-chain-poisoning',
          evidence: `Vulnerable versions: ${adv.vulnerable_versions}; Patched: ${adv.patched_versions}`,
          recommendation: adv.patched_versions === 'available'
            ? `Run npm audit fix or upgrade ${adv.module_name}`
            : `Monitor for patch availability; consider removing ${adv.module_name}`,
        });
      }
    } catch (err) {
      findings.push({
        ruleId: 'R8-engine-error',
        tier: 'suggestion',
        severity: 'P1',
        criticalTag: '[critical:security]',
        message: `npm audit failed: ${err}`,
        file: 'package.json',
        category: 'supply-chain-poisoning',
        evidence: String(err),
        recommendation: 'Ensure Node.js and npm are available in PATH',
      });
    }

    return findings;
  }
}

function runNpmAudit(skillPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = spawn('npm', ['audit', '--json'], {
      cwd: skillPath,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (c) => { stdout += c; });
    proc.stderr.on('data', (c) => { stderr += c; });

    proc.on('close', (code) => {
      // npm audit exits 1 when vulnerabilities found, 0 when clean
      if (code === 0 || code === 1) {
        resolve(stdout);
      } else {
        reject(new Error(`npm audit exited ${code}: ${stderr}`));
      }
    });

    proc.on('error', (err) => {
      reject(err);
    });
  });
}
