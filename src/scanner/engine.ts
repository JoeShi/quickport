/**
 * Core Scanner Engine
 * Plugin-based pipeline for R1-R11 capability validation rules
 */

import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import {
  ScanContext,
  ScanResult,
  ScanFinding,
  ScannerModule,
} from './types';
import { parseManifestWithRaw } from './manifest';
import { ManifestValidationModule } from './modules/manifest-validation';
import { NetworkDiffModule } from './modules/network-diff';
import { FsDiffModule } from './modules/fs-diff';
import { SbomCveModule } from './modules/sbom-cve';
import { ProcessSpawnModule } from './modules/process-spawn';
import { DangerousApiModule } from './modules/dangerous-api';
import { SecretsScanModule } from './modules/secrets-scan';
import { NarrowWaistBypassModule } from './modules/narrow-waist-bypass';
import { SemgrepScannerModule } from './semgrep-runner';

export const SCANNER_VERSION = '1.0.0';

export class ScannerEngine {
  private modules: ScannerModule[] = [];

  register(module: ScannerModule): void {
    this.modules.push(module);
  }

  async scan(skillPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const skillName = path.basename(skillPath);

    // Parse manifest
    const { manifest, raw: manifestRaw } = parseManifestWithRaw(skillPath);

    // Collect source files
    const sourceFiles = this.collectSourceFiles(skillPath);

    const ctx: ScanContext = {
      skillName,
      skillPath,
      manifest,
      manifestRaw,
      sourceFiles,
    };

    // Run all modules
    const findings: ScanFinding[] = [];
    for (const mod of this.modules) {
      try {
        const modFindings = await mod.scan(ctx);
        findings.push(...modFindings);
      } catch (err) {
        findings.push({
          ruleId: 'R0-engine-error',
          tier: 'blocker',
          severity: 'P0',
          criticalTag: '[critical:security]',
          message: `Scanner module "${mod.name}" crashed: ${err}`,
          category: 'malicious-code',
          evidence: String(err),
        });
      }
    }

    const durationMs = Date.now() - startTime;

    // Build summary
    const summary = {
      P0: findings.filter((f) => f.severity === 'P0').length,
      P1: findings.filter((f) => f.severity === 'P1').length,
      P2: findings.filter((f) => f.severity === 'P2').length,
    };

    // Determine decision
    let decision: ScanResult['decision'] = 'allowed';
    if (summary.P0 > 0) {
      decision = 'blocked';
    } else if (summary.P1 > 0) {
      decision = 'requires-user-consent';
    }

    const result: ScanResult = {
      eventId: randomUUID(),
      skillName: manifest.name || skillName,
      skillVersion: manifest.version || 'unknown',
      findings,
      summary,
      durationMs,
      scannerVersion: SCANNER_VERSION,
      scannedAt: new Date().toISOString(),
      coverage: [
        'manifest-validation',
        'declared-vs-actual',
        'static-analysis',
        'fs-boundary',
        'sbom-cve',
      ],
      confidence: 'medium',
      knownBlindSpots: [
        'polymorphic-malware',
        'supply-chain-zero-day',
        'dynamic-host-construction',
      ],
      decision,
    };

    return result;
  }

  private collectSourceFiles(skillPath: string): string[] {
    const files: string[] = [];
    const ignoreDirs = new Set([
      'node_modules',
      '.git',
      'dist',
      'build',
      'coverage',
      '.quickwork',
    ]);

    const walk = (dir: string, prefix: string) => {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const relPath = prefix ? `${prefix}/${entry.name}` : entry.name;
        if (entry.isDirectory()) {
          if (!ignoreDirs.has(entry.name)) {
            walk(path.join(dir, entry.name), relPath);
          }
        } else {
          files.push(relPath);
        }
      }
    };

    walk(skillPath, '');
    return files;
  }
}

/**
 * Convenience factory: create engine with all R1-R11 modules registered
 */
export function createDefaultEngine(): ScannerEngine {
  const engine = new ScannerEngine();
  engine.register(new ManifestValidationModule());
  engine.register(new NetworkDiffModule());
  engine.register(new FsDiffModule());
  engine.register(new ProcessSpawnModule());
  engine.register(new DangerousApiModule());
  engine.register(new SecretsScanModule());
  engine.register(new NarrowWaistBypassModule());
  engine.register(new SbomCveModule());

  // Semgrep rules (if config exists)
  const semgrepConfig = path.join(__dirname, '..', 'rules', 'quickwork-semgrep-rules.yml');
  if (fs.existsSync(semgrepConfig)) {
    engine.register(new SemgrepScannerModule(semgrepConfig));
  }

  return engine;
}
