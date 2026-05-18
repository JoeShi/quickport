#!/usr/bin/env node
/**
 * QuickPort Skill Scanner CLI
 * Usage: npx @quickport/scanner <skill-path>
 */

import * as path from 'path';
import { ScannerEngine, createDefaultEngine } from './engine';
import { formatReport, formatReportJson, isBlocked } from './formatter';

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.error('Usage: quickport-scan <skill-path>');
    process.exit(1);
  }

  const skillPath = path.resolve(args[0]);
  const format = args.includes('--json') ? 'json' : 'markdown';

  const engine = createDefaultEngine();
  const result = await engine.scan(skillPath);

  if (format === 'json') {
    console.log(formatReportJson(result));
  } else {
    console.log(formatReport(result));
  }

  process.exit(isBlocked(result) ? 1 : 0);
}

main().catch((err) => {
  console.error('Scanner crashed:', err);
  process.exit(2);
});
