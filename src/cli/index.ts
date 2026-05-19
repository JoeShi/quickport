#!/usr/bin/env node
/**
 * QuickPort unified CLI — `quickport <subcommand>`
 *
 * Subcommands:
 *   scan <skill-path>              — run capability scanner only (no install)
 *   install <skill-path> [--feishu] [--accept-warnings]
 *                                  — preview + commit; --feishu adds lark-cli pre-flight
 *   uninstall <skill-name>         — remove single skill
 *   uninstall --all                — full QuickPort uninstall (AC-11 diff-merge restore)
 *   list                           — list managed MCP servers
 *
 * Status: M1+M2 v0 — minimal but functional. Built on top of:
 *   - @quickport/scanner (KimiCoder, main)
 *   - @quickport/install-pipeline (Cody scaffold, this branch)
 *   - @quickport/orchestrator/quick-config-patcher (Jack 83657215)
 *   - @quickport/installer/lark-token-verifier (Jack dda81a6)
 *   - @quickport/installer/preflight-check (Jack)
 */

import { resolve } from 'node:path';
import { exit } from 'node:process';

import { createDefaultEngine } from '../scanner/engine.js';
import { formatReport, isBlocked, requiresAcceptance } from '../scanner/formatter.js';

import { createDefaultInstallPipeline, listManagedServers } from '../install-pipeline/index.js';
import { LocalDirSource } from '../marketplace-adapter/sources/local-dir-source.js';
import {
  ConsentRequiredError,
  InstallBlockedError,
  PatchFailedError,
} from '../install-pipeline/types.js';

import { runPreflightChecks } from '../installer/preflight-check.js';
import { verifyOrMigrateLarkCliToken, checkLarkCliAuthStatus } from '../installer/lark-token-verifier.js';

// ─── Utilities ──────────────────────────────────────────────────────────────

function fail(msg: string, code = 1): never {
  process.stderr.write(`✗ ${msg}\n`);
  exit(code);
}

function info(msg: string): void {
  process.stdout.write(`${msg}\n`);
}

function ok(msg: string): void {
  process.stdout.write(`✓ ${msg}\n`);
}

function warn(msg: string): void {
  process.stdout.write(`⚠ ${msg}\n`);
}

// ─── Subcommands ────────────────────────────────────────────────────────────

async function cmdScan(args: string[]): Promise<number> {
  if (args.length < 1) fail('Usage: quickport scan <skill-path>');
  const skillPath = resolve(args[0]);
  const json = args.includes('--json');

  const engine = createDefaultEngine();
  const result = await engine.scan(skillPath);

  if (json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(formatReport(result) + '\n');
  }
  return isBlocked(result) ? 1 : 0;
}

async function cmdInstall(args: string[]): Promise<number> {
  // Parse args, treating known value-flags so their values aren't mistaken for positional paths.
  const VALUE_FLAGS = new Set(['--consent-note']);
  const flagSet = new Set<string>();
  const positional: string[] = [];
  let consentNote = '';
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (VALUE_FLAGS.has(a)) {
      const v = args[++i] ?? '';
      if (a === '--consent-note') consentNote = v;
      continue;
    }
    if (a.startsWith('--')) {
      flagSet.add(a);
      continue;
    }
    positional.push(a);
  }
  if (positional.length < 1) fail('Usage: quickport install <skill-path> [--feishu] [--accept-warnings] [--consent-note <note>]');

  const skillPath = resolve(positional[0]);
  const isFeishu = flagSet.has('--feishu');
  const acceptWarnings = flagSet.has('--accept-warnings');

  // ── Stage 0: preflight ──
  info('• Running preflight checks (Node.js / disk / platform)...');
  const pre = await runPreflightChecks();
  if (!pre.ok) {
    for (const e of pre.errors) {
      process.stderr.write(`✗ preflight: ${e.code}: ${e.message}\n  → ${e.resolution}\n`);
    }
    return 1;
  }
  for (const w of pre.warnings) warn(`preflight: ${w.code}: ${w.message}`);
  ok(`preflight: Node.js ${pre.nodeVersion}, ${pre.platform}/${pre.arch}`);

  // ── Stage 0.5: feishu-specific lark-cli verify-or-migrate ──
  if (isFeishu) {
    info('• Verifying lark-cli credentials (F-HF-1: Keychain master key invariant)...');
    const auth = await checkLarkCliAuthStatus();
    if (!auth.authenticated) {
      process.stderr.write(`✗ lark-cli not authenticated.\n`);
      process.stderr.write(`  → Run: lark-cli auth login\n`);
      process.stderr.write(`  → Then re-run: quickport install --feishu <skill-path>\n`);
      return 1;
    }
    ok(`lark-cli authenticated as: ${auth.userName ?? '(user)'}`);

    const verify = await verifyOrMigrateLarkCliToken();
    if (!verify.ok) {
      process.stderr.write(`✗ lark-cli token security check failed (F-HF-1):\n`);
      for (const i of verify.issues) process.stderr.write(`  - ${i}\n`);
      return 1;
    }
    ok(
      `lark-cli ${verify.larkCliVersion ?? 'unknown'} ` +
        `(keychain=${verify.keychainMasterKeyPresent ? 'ok' : 'missing'} ` +
        `plaintext-config=${verify.noPlaintextTokensInConfig ? 'absent' : 'PRESENT⚠'})` +
        (verify.legacyMigrationRan ? ' [legacy migration ran]' : ''),
    );
  }

  // ── Stage 1: build pipeline ──
  const engine = createDefaultEngine();
  const source = new LocalDirSource();
  const pipeline = createDefaultInstallPipeline({ scanner: engine, sources: [source] });

  // ── Stage 2: preview (fetch + scan) ──
  info('• Fetching package + running scanner...');
  const preview = await pipeline.preview({
    source,
    skillId: skillPath,
    version: '0.0.0', // local-dir source ignores version
  });

  process.stdout.write('\n' + formatReport(preview.scanResult) + '\n\n');

  // ── Stage 3: decision gate ──
  let userConsent;
  if (preview.decision === 'blocked') {
    process.stderr.write(
      `✗ Install blocked: ${preview.scanResult.summary.P0} P0 finding(s). Cannot proceed.\n`,
    );
    return 1;
  }
  if (preview.decision === 'requires-user-consent') {
    if (!acceptWarnings) {
      process.stderr.write(
        `✗ Install requires explicit consent: ${preview.scanResult.summary.P1} P1 finding(s).\n`,
      );
      process.stderr.write(`  → Re-run with --accept-warnings --consent-note "<reason>" to proceed.\n`);
      return 1;
    }
    if (!consentNote) {
      process.stderr.write(
        `✗ --accept-warnings requires --consent-note "<reason>" (per ADR-001 5-子字段例外条款).\n`,
      );
      return 1;
    }
    const refs = preview.scanResult.findings
      .filter(f => f.tier === 'suggestion' && (f.severity === 'P1' || f.severity === 'P2'))
      .map(f => `skill-${preview.scanResult.skillName}#${f.ruleId}`);
    userConsent = { acceptedFindingRefs: refs, consentNote };
    warn(`Consent acknowledged for ${refs.length} finding(s); note recorded in audit log.`);
  }

  // ── Stage 4: commit ──
  info('• Committing install...');
  try {
    const result = await pipeline.commit({
      source,
      skillId: skillPath,
      version: preview.package.version,
      userConsent,
    });
    ok(`Installed: ${result.skillPath}`);
    if (result.mcpServerId) ok(`MCP server registered: ${result.mcpServerId}`);
    info('Audit trail:');
    info(`  scanEventId           : ${result.auditTrail.scanEventId}`);
    if (result.auditTrail.consentEventId) info(`  consentEventId        : ${result.auditTrail.consentEventId}`);
    info(`  quickConfigPatchedRef : ${result.auditTrail.quickConfigPatchedEventId}`);
    return 0;
  } catch (err: unknown) {
    if (err instanceof InstallBlockedError) {
      fail(`Install blocked: ${err.message}`);
    }
    if (err instanceof ConsentRequiredError) {
      fail(`Install requires consent: ${err.message}`);
    }
    if (err instanceof PatchFailedError) {
      fail(`Patch failed: ${err.message}`);
    }
    throw err;
  }
}

async function cmdUninstall(args: string[]): Promise<number> {
  const flags = new Set(args.filter(a => a.startsWith('--')));
  const positional = args.filter(a => !a.startsWith('--'));

  const engine = createDefaultEngine();
  const source = new LocalDirSource();
  const pipeline = createDefaultInstallPipeline({ scanner: engine, sources: [source] });

  if (flags.has('--all')) {
    info('• Uninstalling all QuickPort-managed servers (AC-11 diff-merge restore)...');
    await pipeline.uninstallAll();
    ok('QuickPort fully uninstalled. Quick mcp_config.json restored to pre-install state (Quick own entries preserved).');
    return 0;
  }

  if (positional.length < 1) fail('Usage: quickport uninstall <skill-name> | quickport uninstall --all');
  const skillName = positional[0];
  info(`• Uninstalling ${skillName}...`);
  await pipeline.uninstall(skillName);
  ok(`Uninstalled: ${skillName}`);
  return 0;
}

async function cmdList(_args: string[]): Promise<number> {
  const ids = await listManagedServers();
  if (ids.length === 0) {
    info('(no QuickPort-managed MCP servers)');
    return 0;
  }
  info('Managed MCP servers:');
  for (const id of ids) info(`  • ${id}`);
  return 0;
}

// ─── Main ──────────────────────────────────────────────────────────────────

const HELP = `
quickport — Amazon Quick companion CLI for China ecosystem

Usage:
  quickport scan       <skill-path>                                 Run capability scanner only
  quickport install    <skill-path> [--feishu] [--accept-warnings]
                                    [--consent-note <reason>]       Install skill / MCP server
  quickport uninstall  <skill-name>                                 Remove a single managed server
  quickport uninstall  --all                                        Full uninstall (AC-11 diff-merge)
  quickport list                                                    List managed MCP servers
  quickport help                                                    Show this help

Flags:
  --feishu            Run F-HF-1 lark-cli verify-or-migrate as install pre-flight
  --accept-warnings   Acknowledge P1 findings (requires --consent-note)
  --consent-note <s>  Audit-logged reason for accepting P1 findings
  --json              (scan only) Output JSON instead of markdown report

See: https://github.com/JoeShi/quickport
`;

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case 'scan':
      return cmdScan(rest);
    case 'install':
      return cmdInstall(rest);
    case 'uninstall':
      return cmdUninstall(rest);
    case 'list':
      return cmdList(rest);
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      info(HELP);
      return cmd ? 0 : 1;
    default:
      process.stderr.write(`Unknown command: ${cmd}\n`);
      info(HELP);
      return 1;
  }
}

main()
  .then(code => exit(code))
  .catch(err => {
    process.stderr.write(`✗ quickport crashed: ${err?.message ?? err}\n`);
    if (process.env.QUICKPORT_DEBUG) {
      process.stderr.write(`${err?.stack ?? ''}\n`);
    }
    exit(2);
  });
