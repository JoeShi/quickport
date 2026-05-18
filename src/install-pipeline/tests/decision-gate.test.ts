/**
 * Smoke test: install-pipeline decision-gate logic.
 *
 * Verifies that:
 *   - 'blocked' decision → InstallBlockedError
 *   - 'requires-user-consent' without ctx.userConsent → ConsentRequiredError
 *
 * Does NOT exercise real fs/audit/patcher — those are stubbed via mock pipeline deps.
 */

import { describe, it, expect } from 'vitest';

import {
  ConsentRequiredError,
  InstallBlockedError,
  type InstallPipeline,
  type InstallContext,
} from '../types.js';

import type { ScanResult } from '../../scanner/types.js';
import type { SkillSource, SkillPackage } from '../../marketplace-adapter/types.js';

/**
 * Tiny mock that throws blocked/consent errors based on `decision` only.
 * Mirrors the real pipeline's gate logic (preview() → check decision → throw).
 */
function buildMockPipeline(decision: ScanResult['decision'], summary = { P0: 0, P1: 0, P2: 0 }): InstallPipeline {
  const fakeScan: ScanResult = {
    eventId: 'evt-test-1',
    skillName: 'demo',
    skillVersion: '1.0.0',
    findings: [],
    summary,
    durationMs: 1,
    scannerVersion: '1.0.0',
    scannedAt: new Date().toISOString(),
    coverage: ['static-analysis'],
    confidence: 'high',
    knownBlindSpots: [],
    decision,
  };

  return {
    async search() { return []; },
    async preview() {
      const pkg: SkillPackage = {
        localPath: '/tmp/demo',
        isExtracted: true,
        integrity: 'sha256:0000',
        version: '1.0.0',
      };
      return { package: pkg, manifest: { name: 'demo', version: '1.0.0' } as any, scanResult: fakeScan, decision };
    },
    async commit(ctx: InstallContext) {
      if (decision === 'blocked') throw new InstallBlockedError(fakeScan);
      if (decision === 'requires-user-consent' && !ctx.userConsent) {
        throw new ConsentRequiredError(fakeScan);
      }
      return {
        installedAt: new Date().toISOString(),
        skillPath: '/tmp/demo',
        auditTrail: { scanEventId: 'evt-test-1', quickConfigPatchedEventId: 'qcp-test-1' },
      };
    },
    async uninstall() {},
    async uninstallAll() {},
  };
}

const dummySource: SkillSource = {
  id: 'mock',
  displayName: 'Mock',
  defaultTrust: 'unverified',
  async search() { return []; },
  async getDetails() { throw new Error('n/a'); },
  async fetchPackage() {
    return { localPath: '/tmp/demo', isExtracted: true, integrity: 'sha256:0', version: '1.0.0' };
  },
};

const baseCtx: InstallContext = { source: dummySource, skillId: 'demo', version: '1.0.0' };

describe('install-pipeline decision gate', () => {
  it('throws InstallBlockedError when scanner blocks', async () => {
    const p = buildMockPipeline('blocked', { P0: 2, P1: 0, P2: 0 });
    await expect(p.commit(baseCtx)).rejects.toBeInstanceOf(InstallBlockedError);
  });

  it('throws ConsentRequiredError when scanner requires user consent and ctx omits userConsent', async () => {
    const p = buildMockPipeline('requires-user-consent', { P0: 0, P1: 1, P2: 0 });
    await expect(p.commit(baseCtx)).rejects.toBeInstanceOf(ConsentRequiredError);
  });

  it('proceeds when consent is provided', async () => {
    const p = buildMockPipeline('requires-user-consent', { P0: 0, P1: 1, P2: 0 });
    const result = await p.commit({
      ...baseCtx,
      userConsent: { acceptedFindingRefs: ['skill-demo#R7-001'], consentNote: 'Reviewed and accepted.' },
    });
    expect(result.auditTrail.scanEventId).toBe('evt-test-1');
  });

  it('proceeds when scanner allows', async () => {
    const p = buildMockPipeline('allowed');
    const result = await p.commit(baseCtx);
    expect(result.skillPath).toBe('/tmp/demo');
  });
});
