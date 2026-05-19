/**
 * @quickport/installer/lark-token-verifier
 *
 * F-HF-1 version-aware verify-or-migrate (replaces lark-token-migration.ts).
 *
 * Architecture finding (Jack b39dfd6, ratified by @Arch #dev:ae174c0d,
 * @Gatekeeper verdict #dev:4708892a, @Arch ratify #dev:afd7b793):
 *
 *   lark-cli ≥ v1.0.0: credentials stored via OS Keychain master key
 *     (service="lark-cli", acct="master.key"). Token is NOT in plaintext.
 *     → Action: verify Keychain master key exists; refuse install if missing.
 *
 *   lark-cli < v1.0.0 (legacy): credentials may be in plaintext config.
 *     → Action: run full plaintext-to-Keychain migration (legacy path).
 *
 * F-HF-1 contract (ADR-002 §F-mode-feishu-flow §HF-1):
 *   "QuickPort does NOT introduce plaintext token degradation.
 *    QuickPort verifies at install time that lark-cli ≥ v1.0.0 is present
 *    and its Keychain master key invariant holds; or migrates tokens to
 *    Keychain for legacy lark-cli versions before proceeding."
 *
 * [critical:security] Token material is only accessed in the legacy migration
 * path, and only via @quickport/orchestrator/credentials/keychain-adapter
 * (R5 narrow waist). The verify path uses `security` CLI in metadata-only
 * mode (no -w flag) — no token material passes through.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, writeFile, access } from "node:fs/promises";
import { join } from "node:path";
import os from "node:os";
import { setToken } from "../orchestrator/credentials/keychain-adapter.js";

const execFileAsync = promisify(execFile);

// ─── Public API ────────────────────────────────────────────────────────────

export const FEISHU_TOKEN_SERVICE = "@quickport/feishu-token";
export const FEISHU_REFRESH_TOKEN_SERVICE = "@quickport/feishu-refresh-token";

export interface VerifyResult {
  ok: boolean;
  larkCliVersion: string | null;
  versionSatisfied: boolean;
  keychainMasterKeyPresent: boolean;
  noPlaintextTokensInConfig: boolean;
  legacyMigrationRan: boolean;
  issues: string[];
}

/**
 * Version-aware verify-or-migrate. Called by install-pipeline pre-flight.
 *
 * - lark-cli ≥ v1.0.0: verify Keychain master key present; block if missing.
 * - lark-cli < v1.0.0: run legacy plaintext-to-Keychain migration.
 *
 * Returns VerifyResult; if ok=false, install-pipeline should block.
 */
export async function verifyOrMigrateLarkCliToken(): Promise<VerifyResult> {
  const versionResult = await checkLarkCliVersion();

  if (versionResult.satisfied) {
    // Modern path: verify-only
    const result = await verifyLarkCliTokenSecurity();
    return { ...result, legacyMigrationRan: false };
  }

  // Legacy path: lark-cli < v1.0.0 — attempt migration
  const migrationResult = await runLegacyMigration();
  return {
    ok: migrationResult.success,
    larkCliVersion: versionResult.version,
    versionSatisfied: false,
    keychainMasterKeyPresent: migrationResult.success,
    noPlaintextTokensInConfig: migrationResult.success,
    legacyMigrationRan: true,
    issues: migrationResult.error ? [migrationResult.error] : [],
  };
}

/**
 * Run F-HF-1 invariant checks for lark-cli ≥ v1.0.0.
 * Called by verifyOrMigrateLarkCliToken when version is satisfied.
 */
export async function verifyLarkCliTokenSecurity(): Promise<VerifyResult> {
  const issues: string[] = [];

  const versionResult = await checkLarkCliVersion();
  if (!versionResult.satisfied) {
    issues.push(
      versionResult.version
        ? `lark-cli version ${versionResult.version} is below minimum v1.0.0 — Keychain storage not guaranteed`
        : "lark-cli not found or not executable — please install lark-cli first"
    );
  }

  const keychainOk = await checkKeychainMasterKey();
  if (!keychainOk && versionResult.satisfied) {
    issues.push(
      "lark-cli Keychain master key not found (service=lark-cli, acct=master.key) — " +
        "run `lark-cli auth login` to complete OAuth and establish the master key"
    );
  }

  const plaintextResult = await checkNoPlaintextTokensInConfig();
  if (!plaintextResult.clean) {
    issues.push(
      `Plaintext token fields detected in ${plaintextResult.configPath} — ` +
        "this indicates a pre-v1.0.0 lark-cli configuration; please re-run `lark-cli auth login`"
    );
  }

  return {
    ok: issues.length === 0,
    larkCliVersion: versionResult.version,
    versionSatisfied: versionResult.satisfied,
    keychainMasterKeyPresent: keychainOk,
    noPlaintextTokensInConfig: plaintextResult.clean,
    legacyMigrationRan: false,
    issues,
  };
}

/**
 * Check that lark-cli is authenticated (auth status reports tokenStatus=valid).
 * Used to gate `quickport install --feishu` — if not authed, direct user to
 * `lark-cli auth login` before proceeding.
 */
export async function checkLarkCliAuthStatus(): Promise<{
  authenticated: boolean;
  userName?: string;
  expiresAt?: string;
  error?: string;
}> {
  try {
    const { stdout } = await execFileAsync("lark-cli", ["auth", "status"], {
      timeout: 10_000,
      env: { ...process.env },
    });
    const status = JSON.parse(stdout.trim());
    const tokenStatus = status?.tokenStatus ?? status?.data?.tokenStatus;
    if (tokenStatus !== "valid") {
      return { authenticated: false, error: `Token status: ${tokenStatus ?? "unknown"}` };
    }
    return {
      authenticated: true,
      userName: status?.userName ?? status?.data?.userName,
      expiresAt: status?.expiresAt ?? status?.data?.expiresAt,
    };
  } catch (err: any) {
    return { authenticated: false, error: err.message };
  }
}

// ─── Internal checks ───────────────────────────────────────────────────────

const LARK_CLI_MIN_VERSION = [1, 0, 0];

async function checkLarkCliVersion(): Promise<{ version: string | null; satisfied: boolean }> {
  try {
    const { stdout } = await execFileAsync("lark-cli", ["--version"], {
      timeout: 5_000,
      env: { ...process.env },
    });
    const match = stdout.trim().match(/(\d+)\.(\d+)\.(\d+)/);
    if (!match) return { version: null, satisfied: false };
    const version = `${match[1]}.${match[2]}.${match[3]}`;
    const parts = [parseInt(match[1]), parseInt(match[2]), parseInt(match[3])];
    const satisfied = parts.every((v, i) => v >= LARK_CLI_MIN_VERSION[i]);
    return { version, satisfied };
  } catch {
    return { version: null, satisfied: false };
  }
}

async function checkKeychainMasterKey(): Promise<boolean> {
  if (process.platform !== "darwin" && process.platform !== "win32") {
    return true; // Unsupported platform — skip check, not a blocker
  }
  if (process.platform === "darwin") {
    try {
      // Use metadata-only query (no -w flag) — we never read the key material
      await execFileAsync("security", [
        "find-generic-password",
        "-s", "lark-cli",
        "-a", "master.key",
      ], { timeout: 5_000 });
      return true;
    } catch {
      return false;
    }
  }
  if (process.platform === "win32") {
    try {
      const script = `
$cred = Get-StoredCredential -Target "lark-cli" -ErrorAction SilentlyContinue
if ($null -ne $cred) { exit 0 } else { exit 1 }
`.trim();
      await execFileAsync("powershell", ["-NoProfile", "-NonInteractive", "-Command", script], {
        timeout: 5_000,
      });
      return true;
    } catch {
      return false;
    }
  }
  return true;
}

const LARK_CLI_CONFIG_PATHS = [
  join(os.homedir(), ".lark-cli", "config.json"),
  join(os.homedir(), ".lark-cli.json"),
  join(os.homedir(), ".config", "lark-cli", "config.json"),
];

const PLAINTEXT_TOKEN_FIELDS = [
  "access_token", "accessToken", "token", "user_access_token",
  "refresh_token", "refreshToken",
];

async function checkNoPlaintextTokensInConfig(): Promise<{
  clean: boolean;
  configPath: string | null;
}> {
  for (const configPath of LARK_CLI_CONFIG_PATHS) {
    try {
      await access(configPath);
      const raw = await readFile(configPath, "utf8");
      const parsed = JSON.parse(raw);

      if (hasPlaintextToken(parsed)) {
        return { clean: false, configPath };
      }
      return { clean: true, configPath };
    } catch {
      continue;
    }
  }
  return { clean: true, configPath: null }; // No config found = no plaintext = ok
}

function hasPlaintextToken(obj: unknown, depth = 0): boolean {
  if (depth > 4 || typeof obj !== "object" || obj === null) return false;
  for (const field of PLAINTEXT_TOKEN_FIELDS) {
    const val = (obj as Record<string, unknown>)[field];
    if (typeof val === "string" && val.length > 20) return true;
  }
  for (const val of Object.values(obj as Record<string, unknown>)) {
    if (typeof val === "object" && hasPlaintextToken(val, depth + 1)) return true;
    if (Array.isArray(val)) {
      for (const item of val) {
        if (hasPlaintextToken(item, depth + 1)) return true;
      }
    }
  }
  return false;
}

// ─── Legacy migration (lark-cli < v1.0.0) ────────────────────────────────

interface LegacyMigrationResult {
  success: boolean;
  error?: string;
}

/**
 * Legacy migration path for lark-cli < v1.0.0.
 * Reads plaintext token from config, writes to Keychain via keychain-adapter,
 * then zeros out the plaintext. Skips gracefully if no token found.
 * [critical:security] Token handled only via @quickport/orchestrator/credentials/keychain-adapter.
 */
async function runLegacyMigration(): Promise<LegacyMigrationResult> {
  for (const configPath of LARK_CLI_CONFIG_PATHS) {
    try {
      await access(configPath);
      const raw = await readFile(configPath, "utf8");
      const parsed: Record<string, unknown> = JSON.parse(raw);

      const accessToken = extractFirstToken(parsed, [
        "access_token", "accessToken", "token", "user_access_token",
      ]);
      const refreshToken = extractFirstToken(parsed, ["refresh_token", "refreshToken"]);

      if (!accessToken) continue;

      // Write to Keychain via R5 narrow waist [critical:security]
      await setToken(FEISHU_TOKEN_SERVICE, accessToken);
      if (refreshToken) await setToken(FEISHU_REFRESH_TOKEN_SERVICE, refreshToken);

      // Zero out plaintext tokens
      await scrubTokensFromConfig(configPath, parsed);
      return { success: true };
    } catch (err: any) {
      return { success: false, error: `Legacy migration failed for ${configPath}: ${err.message}` };
    }
  }
  return { success: true }; // No plaintext config found — nothing to migrate
}

function extractFirstToken(
  config: Record<string, unknown>,
  keys: string[]
): string | null {
  for (const key of keys) {
    const val =
      (config[key] as string | undefined) ??
      ((config.auth as Record<string, unknown> | undefined)?.[key] as string | undefined) ??
      ((config.credentials as Record<string, unknown> | undefined)?.[key] as string | undefined);
    if (typeof val === "string" && val.length > 0) return val;
  }
  return null;
}

async function scrubTokensFromConfig(
  configPath: string,
  rawConfig: Record<string, unknown>
): Promise<void> {
  const fields = [
    "access_token", "accessToken", "token", "user_access_token",
    "refresh_token", "refreshToken",
  ];
  const scrubbed = { ...rawConfig };
  for (const field of fields) {
    if (field in scrubbed) scrubbed[field] = "";
    for (const nested of ["auth", "credentials"] as const) {
      if (scrubbed[nested] && typeof scrubbed[nested] === "object") {
        const obj = { ...(scrubbed[nested] as Record<string, unknown>) };
        if (field in obj) obj[field] = "";
        scrubbed[nested] = obj;
      }
    }
  }
  await writeFile(configPath, JSON.stringify(scrubbed, null, 2), "utf8");
}
