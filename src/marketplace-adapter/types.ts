/**
 * @quickport/marketplace-adapter — public types
 *
 * Marketplace abstraction layer: each marketplace (skills.sh, GitHub, custom URL etc.)
 * implements SkillSource. The install-pipeline only talks to this interface,
 * not to specific marketplaces.
 *
 * Status: SCAFFOLD v0 — not finalized. Awaits Arch ADR-002 §network段 for fetch/TLS details.
 *
 * Design notes:
 *   - We keep this layer minimal (stable v1 interface) so adding marketplace types
 *     is non-breaking.
 *   - fetchPackage returns a local tarball/dir path; install-pipeline owns
 *     unpacking + scan + install. The source does NOT know about scanning or
 *     install paths.
 *   - integrity (SHA-256) is set by the source for HF-8 binary integrity.
 */

/** A skill listing returned from search (lightweight, for UI). */
export interface SkillListing {
  /** Source-scoped unique identifier (e.g. "skills-sh:feishu-mcp") */
  skillId: string;
  /** Human-readable name */
  name: string;
  /** Latest version available */
  latestVersion: string;
  /** Short description (for list view) */
  description?: string;
  /** Author/publisher (for trust display) */
  publisher?: string;
  /** Marketplace trust level (informational; final decision is from scanner) */
  marketplaceTrust: 'official' | 'community' | 'unverified';
}

/** Detailed metadata for a single skill (fetched on demand). */
export interface SkillDetails extends SkillListing {
  /** Full readme/long description */
  readme?: string;
  /** All available versions (newest first) */
  versions: string[];
  /** Repo / homepage URL */
  homepage?: string;
}

/** Result of fetchPackage — local artifact ready for scan + install. */
export interface SkillPackage {
  /** Path to local tarball (.tar.gz / .zip) OR extracted directory */
  localPath: string;
  /** Whether localPath is already extracted (true) or still archive (false) */
  isExtracted: boolean;
  /** SHA-256 integrity hash (HF-8 binary integrity gate) */
  integrity: string;
  /** Source-confirmed version that was fetched */
  version: string;
}

/** Search options (forward-compatible — extend later). */
export interface SearchOpts {
  /** Max results to return */
  limit?: number;
  /** Filter by skill type */
  type?: 'mcp-server' | 'skill';
}

/**
 * SkillSource — marketplace abstraction.
 *
 * Implementations: skills-sh, github, http-url (plain tarball), git-source.
 * Each source is registered once at app startup and dispatched by skillId prefix.
 */
export interface SkillSource {
  /** Stable id (e.g. 'skills-sh', 'github', 'git') */
  readonly id: string;
  /** UI display name */
  readonly displayName: string;
  /** Default trust level for skills from this source */
  readonly defaultTrust: 'official' | 'community' | 'unverified';

  /** Search this source. May return [] if source doesn't support search semantically. */
  search(query: string, opts?: SearchOpts): Promise<SkillListing[]>;

  /** Fetch detailed metadata for a single skill. */
  getDetails(skillId: string): Promise<SkillDetails>;

  /** Download package bytes to a local temp location. Does NOT extract or install. */
  fetchPackage(skillId: string, version: string): Promise<SkillPackage>;
}
