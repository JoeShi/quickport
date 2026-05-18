import * as fs from 'fs';
import * as path from 'path';
import { SkillManifest, CapabilityDeclaration } from './types';

export const REQUIRED_MANIFEST_FIELDS = [
  'name',
  'version',
  'description',
  'main',
  'author',
  'license',
];

/**
 * Parse skill manifest from JSON file
 */
export function parseManifest(skillPath: string): SkillManifest {
  const manifestPath = path.join(skillPath, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`manifest.json not found at ${manifestPath}`);
  }
  const raw = fs.readFileSync(manifestPath, 'utf-8');
  const manifest = JSON.parse(raw) as SkillManifest;
  return manifest;
}

/**
 * Parse manifest with raw text preserved
 */
export function parseManifestWithRaw(skillPath: string): {
  manifest: SkillManifest;
  raw: string;
} {
  const manifestPath = path.join(skillPath, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`manifest.json not found at ${manifestPath}`);
  }
  const raw = fs.readFileSync(manifestPath, 'utf-8');
  const manifest = JSON.parse(raw) as SkillManifest;
  return { manifest, raw };
}

/**
 * Validate manifest structure (required fields, semver, etc.)
 * Returns array of validation error messages
 */
export function validateManifestStructure(
  manifest: SkillManifest
): string[] {
  const errors: string[] = [];

  for (const field of REQUIRED_MANIFEST_FIELDS) {
    if (!(field in manifest) || manifest[field] == null) {
      errors.push(`Missing required field: ${field}`);
    }
  }

  // semver check
  if (manifest.version) {
    const semverRegex =
      /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([\da-z-]+(?:\.[\da-z-]+)*))?(?:\+([\da-z-]+(?:\.[\da-z-]+)*))?$/i;
    if (!semverRegex.test(manifest.version)) {
      errors.push(`Invalid semver: ${manifest.version}`);
    }
  }

  // capability declarations validation
  // v1 schema: capabilities is an object with network/fs/process/credentials keys
  if (manifest.capabilities) {
    if (typeof manifest.capabilities !== 'object') {
      errors.push('capabilities must be an object');
    }
  }

  // domains validation
  if (manifest.domains) {
    if (!Array.isArray(manifest.domains)) {
      errors.push('domains must be an array');
    }
  }

  return errors;
}

/**
 * Extract declared capabilities as a map for diff scanning
 */
export function extractDeclaredCapabilities(
  manifest: SkillManifest
): Map<string, string> {
  const map = new Map<string, string>();
  if (!manifest.capabilities) return map;
  for (const cap of manifest.capabilities) {
    const key = cap.scope ? `${cap.resource}:${cap.scope}` : cap.resource;
    map.set(key, cap.name);
  }
  return map;
}

/**
 * Extract declared domains as a Set
 */
export function extractDeclaredDomains(manifest: SkillManifest): Set<string> {
  return new Set(manifest.domains || []);
}
