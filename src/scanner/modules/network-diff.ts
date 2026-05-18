/**
 * R1 — Network Domain Diff Module
 * Statically extracts network call targets from JS/TS/Python source
 * and compares against manifest.capabilities.network.domains
 */

import * as fs from 'fs';
import * as path from 'path';
import { ScanContext, ScanFinding, ScannerModule } from '../types';

// Patterns to detect network calls in JS/TS
const JS_NETWORK_PATTERNS = [
  /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /axios\.[a-z]+\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /http\.request\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /https?\.get\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /new\s+URL\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /WebSocket\s*\(\s*['"`]([^'"`]+)['"`]/g,
];

// Patterns for Python
const PY_NETWORK_PATTERNS = [
  /requests\.[a-z]+\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /urllib\.request\.urlopen\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /httpx\.[a-z]+\s*\(\s*['"`]([^'"`]+)['"`]/g,
];

function extractHost(urlStr: string): string | null {
  try {
    // Handle bare hostnames
    if (!urlStr.includes('://') && !urlStr.startsWith('//')) {
      urlStr = 'http://' + urlStr;
    }
    const url = new URL(urlStr);
    return url.hostname;
  } catch {
    // Try to extract hostname from string like "api.example.com/path"
    const match = urlStr.match(/^([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)/);
    return match ? match[1] : null;
  }
}

function extractHostsFromFile(filePath: string, patterns: RegExp[]): string[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  const hosts = new Set<string>();

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const url = match[1];
      const host = extractHost(url);
      if (host) {
        hosts.add(host);
      }
    }
  }

  return Array.from(hosts);
}

export class NetworkDiffModule implements ScannerModule {
  name = 'network-domain-diff';

  scan(ctx: ScanContext): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const declaredDomains = new Set(ctx.manifest.domains || []);
    const declaredCapabilityDomains = new Set<string>(
      ((ctx.manifest as any).capabilities?.network?.domains || []) as string[]
    );
    const allDeclared = new Set([...declaredDomains, ...declaredCapabilityDomains]);

    const codeFiles = ctx.sourceFiles.filter((f) =>
      /\.(js|ts|jsx|tsx|py|mjs|cjs)$/.test(f)
    );

    const actualHosts = new Set<string>();
    const hostToFiles = new Map<string, string[]>();

    for (const relPath of codeFiles) {
      const fullPath = path.join(ctx.skillPath, relPath);
      const isPython = relPath.endsWith('.py');
      const patterns = isPython ? PY_NETWORK_PATTERNS : JS_NETWORK_PATTERNS;
      const hosts = extractHostsFromFile(fullPath, patterns);

      for (const host of hosts) {
        actualHosts.add(host);
        if (!hostToFiles.has(host)) hostToFiles.set(host, []);
        hostToFiles.get(host)!.push(relPath);
      }
    }

    for (const host of actualHosts) {
      if (!allDeclared.has(host)) {
        findings.push({
          ruleId: 'R1-network-domain-diff',
          tier: 'blocker',
          severity: 'P0',
          criticalTag: '[critical:security]',
          message: `Code accesses "${host}" but it is not declared in manifest capabilities.network.domains`,
          file: hostToFiles.get(host)?.[0],
          category: 'data-exfiltration',
          evidence: `Found in: ${hostToFiles.get(host)?.join(', ')}`,
          recommendation: `Add "${host}" to manifest.capabilities.network.domains or remove the network call`,
        });
      }
    }

    // R9: declared but unused
    for (const declared of allDeclared) {
      if (!actualHosts.has(declared) && declared) {
        findings.push({
          ruleId: 'R9-capability-overclaim',
          tier: 'suggestion',
          severity: 'P1',
          criticalTag: '[critical:security]',
          message: `Domain "${declared}" declared in manifest but never used in code`,
          file: 'manifest.json',
          category: 'privilege-escalation',
          recommendation: 'Remove unused domain declaration to follow least privilege',
        });
      }
    }

    return findings;
  }
}
