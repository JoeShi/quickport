/**
 * R0 — Manifest Structure Validation Module
 * Validates required fields, semver, capabilities schema
 */

import { ScanContext, ScanFinding, ScannerModule } from '../types';
import { validateManifestStructure } from '../manifest';

export class ManifestValidationModule implements ScannerModule {
  name = 'manifest-validation';

  scan(ctx: ScanContext): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const errors = validateManifestStructure(ctx.manifest);

    for (const err of errors) {
      findings.push({
        ruleId: 'R0-manifest-structure',
        tier: 'blocker',
        severity: 'P0',
        criticalTag: '[critical:security]',
        message: `Manifest structure violation: ${err}`,
        file: 'manifest.json',
        category: 'malicious-code',
        recommendation: 'Fix manifest.json to comply with required schema',
      });
    }

    // Check for required capability declarations (v1 must declare)
    if (!ctx.manifest.capabilities || ctx.manifest.capabilities.length === 0) {
      findings.push({
        ruleId: 'R0-missing-capabilities',
        tier: 'blocker',
        severity: 'P0',
        criticalTag: '[critical:security]',
        message: 'Manifest missing capabilities declaration. v1 requires explicit capability listing.',
        file: 'manifest.json',
        category: 'privilege-escalation',
        recommendation: 'Add capabilities section to manifest.json',
      });
    }

    // Check for credentials.via = install-orchestrator
    const creds = (ctx.manifest as any).capabilities?.credentials;
    if (creds && creds.via !== 'install-orchestrator') {
      findings.push({
        ruleId: 'R5-credentials-bypass',
        tier: 'blocker',
        severity: 'P0',
        criticalTag: '[critical:security]',
        message: `Credentials.via must be "install-orchestrator", found: ${creds.via}`,
        file: 'manifest.json',
        category: 'privilege-escalation',
        recommendation: 'Set capabilities.credentials.via to "install-orchestrator"',
      });
    }

    return findings;
  }
}
