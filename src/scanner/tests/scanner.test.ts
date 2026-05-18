import * as path from 'path';
import { ScannerEngine, createDefaultEngine } from '../engine';
import { isBlocked, formatReport } from '../formatter';

describe('ScannerEngine', () => {
  let engine: ScannerEngine;

  beforeEach(() => {
    engine = createDefaultEngine();
  });

  test('clean-skill has no blockers', async () => {
    const skillPath = path.join(__dirname, 'fixtures', 'clean-skill');
    const result = await engine.scan(skillPath);

    expect(result.skillName).toBe('clean-skill');
    expect(result.summary.P0).toBe(0);
    expect(isBlocked(result)).toBe(false);
    expect(result.durationMs).toBeLessThan(5000);
  });

  test('bad-skill has multiple P0 blockers', async () => {
    const skillPath = path.join(__dirname, 'fixtures', 'bad-skill');
    const result = await engine.scan(skillPath);

    expect(result.skillName).toBe('bad-skill');
    expect(result.summary.P0).toBeGreaterThan(0);
    expect(isBlocked(result)).toBe(true);

    // Check specific rule violations
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('R0-manifest-structure');
    expect(ruleIds).toContain('R1-network-domain-diff');
    expect(ruleIds).toContain('R2-fs-write-sensitive');
    expect(ruleIds).toContain('R3-process-spawn-diff');
    expect(ruleIds).toContain('R7-dangerous-api');
  });

  test('output format follows v0.1 protocol', async () => {
    const skillPath = path.join(__dirname, 'fixtures', 'bad-skill');
    const result = await engine.scan(skillPath);
    const report = formatReport(result);

    // Should contain QuickPort-style refs
    expect(report).toContain('ref:bad-skill#');
    expect(report).toContain('P0');
    expect(report).toContain('[critical:security]');
  });
});
