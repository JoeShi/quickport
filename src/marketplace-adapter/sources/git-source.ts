/**
 * GitSourceAdapter — fetch skill packages by git clone (or skill repo URL).
 *
 * Status: STUB — interface only. Real implementation awaits Arch ADR-002 §network段:
 *   - shallow clone vs full clone
 *   - integrity hash strategy (commit SHA vs tarball SHA-256)
 *   - rate limiting / retry policy
 *   - private repo OAuth flow (relies on @quickport/orchestrator/credentials)
 */

import type {
  SkillSource,
  SkillListing,
  SkillDetails,
  SkillPackage,
  SearchOpts,
} from '../types.js';

export class GitSourceAdapter implements SkillSource {
  readonly id = 'git';
  readonly displayName = 'Git Repository';
  readonly defaultTrust = 'unverified' as const;

  async search(_query: string, _opts?: SearchOpts): Promise<SkillListing[]> {
    // Git source does not support search semantically.
    // Use getDetails(<owner/repo>) directly.
    return [];
  }

  async getDetails(_skillId: string): Promise<SkillDetails> {
    throw new Error('GitSourceAdapter.getDetails: not implemented (awaits ADR-002 §network)');
  }

  async fetchPackage(_skillId: string, _version: string): Promise<SkillPackage> {
    throw new Error('GitSourceAdapter.fetchPackage: not implemented (awaits ADR-002 §network)');
  }
}
