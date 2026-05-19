/**
 * LocalDirSource — install a skill from an already-extracted local directory.
 *
 * Status: M1 v0 — supports the demo flow `quickport install ./feishu-demo`.
 * Real network sources (skills.sh, GitHub) come in a later milestone.
 */

import { resolve, basename } from 'node:path';
import { stat, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

import type {
  SkillSource,
  SkillListing,
  SkillDetails,
  SkillPackage,
  SearchOpts,
} from '../types.js';

export class LocalDirSource implements SkillSource {
  readonly id = 'local';
  readonly displayName = 'Local Directory';
  readonly defaultTrust = 'unverified' as const;

  async search(_query: string, _opts?: SearchOpts): Promise<SkillListing[]> {
    // Local source doesn't search; pass directory path directly to install.
    return [];
  }

  async getDetails(skillId: string): Promise<SkillDetails> {
    const pkgPath = resolve(skillId);
    const manifestPath = resolve(pkgPath, 'manifest.json');
    const raw = await readFile(manifestPath, 'utf8');
    const m = JSON.parse(raw) as Record<string, unknown>;
    return {
      skillId: pkgPath,
      name: String(m.name ?? basename(pkgPath)),
      latestVersion: String(m.version ?? '0.0.0'),
      versions: [String(m.version ?? '0.0.0')],
      description: typeof m.description === 'string' ? m.description : undefined,
      publisher: typeof m.author === 'string' ? m.author : undefined,
      homepage: undefined,
      marketplaceTrust: 'unverified',
    };
  }

  async fetchPackage(skillId: string, _version: string): Promise<SkillPackage> {
    const pkgPath = resolve(skillId);
    const s = await stat(pkgPath);
    if (!s.isDirectory()) {
      throw new Error(`LocalDirSource: not a directory: ${pkgPath}`);
    }
    const manifestPath = resolve(pkgPath, 'manifest.json');
    const manifestRaw = await readFile(manifestPath, 'utf8');
    const integrity = `sha256:${createHash('sha256').update(manifestRaw).digest('hex')}`;
    const m = JSON.parse(manifestRaw) as { version?: unknown };
    return {
      localPath: pkgPath,
      isExtracted: true,
      integrity,
      version: typeof m.version === 'string' ? m.version : '0.0.0',
    };
  }
}
