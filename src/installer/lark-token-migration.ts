/**
 * @quickport/installer/lark-token-migration
 *
 * F-HF-1 implementation: migrate lark-cli OAuth token from plaintext config
 * to OS Keychain. This is a v1 MUST requirement (P0 security blocker per
 * @Gatekeeper 8a01c06a, @Arch e787e301).
 *
 * Background:
 *   Current lark-cli workaround stores OAuth token at ~/.lark-cli/<config>
 *   in plaintext/weakly-encrypted form. Any local process can read and
 *   impersonate the user to the Feishu API.
 *
 * Migration strategy (v1, method-a — non-invasive, no upstream fork needed):
 *   1. Call `lark-cli auth login` (standard OAuth browser flow)
 *   2. After completion, read token from ~/.lark-cli/ config
 *   3. Write token to OS Keychain via @quickport/orchestrator/credentials/keychain-adapter
 *   4. Zero out / delete the plaintext token from lark-cli config
 *   5. Subsequent lark-cli invocations: inject LARK_ACCESS_TOKEN from Keychain via env
 *
 * [critical:security] This module handles credentials — all token ops go
 * through keychain-adapter (R5 narrow waist enforcement).
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, writeFile, access } from "node:fs/promises";
import { join } from "node:path";
import os from "node:os";
import { getToken, setToken, deleteToken } from "../orchestrator/credentials/keychain-adapter.js";

const execFileAsync = promisify(execFile);

// Service names — must be @quickport/ namespace (R5 enforcement)
export const FEISHU_TOKEN_SERVICE = "@quickport/feishu-token";
export const FEISHU_REFRESH_TOKEN_SERVICE = "@quickport/feishu-refresh-token";

export interface MigrationResult {
  success: boolean;
  alreadyMigrated: boolean;
  tokenFound: boolean;
  error?: string;
}

/**
 * Run lark-cli auth login and immediately migrate the resulting token to Keychain.
 * Blocks until the OAuth flow completes in the user's browser.
 */
export async function loginAndMigrateToken(): Promise<MigrationResult> {
  // Step 1: Run lark-cli auth login (blocks until user completes OAuth)
  try {
    await execFileAsync("lark-cli", ["auth", "login"], {
      stdio: "inherit" as any,
      env: { ...process.env },
    });
  } catch (err: any) {
    return {
      success: false,
      alreadyMigrated: false,
      tokenFound: false,
      error: `lark-cli auth login failed: ${err.message}`,
    };
  }

  // Step 2-4: Migrate the resulting token
  return await migrateExistingToken();
}

/**
 * Migrate an already-existing lark-cli token from plaintext config to Keychain.
 * Idempotent: if already migrated (token in Keychain, not in plaintext), returns alreadyMigrated=true.
 */
export async function migrateExistingToken(): Promise<MigrationResult> {
  // Check if already migrated
  const existingKeychainToken = await getToken(FEISHU_TOKEN_SERVICE);
  const larkConfig = await readLarkCliConfig();

  if (!larkConfig) {
    if (existingKeychainToken) {
      // Token already in Keychain, no plaintext config found → already migrated
      return { success: true, alreadyMigrated: true, tokenFound: true };
    }
    return {
      success: false,
      alreadyMigrated: false,
      tokenFound: false,
      error: "lark-cli config file not found. Please run lark-cli auth login first.",
    };
  }

  const { accessToken, refreshToken, configPath } = larkConfig;

  if (!accessToken) {
    if (existingKeychainToken) {
      return { success: true, alreadyMigrated: true, tokenFound: true };
    }
    return {
      success: false,
      alreadyMigrated: false,
      tokenFound: false,
      error: "No access token found in lark-cli config. Please run lark-cli auth login first.",
    };
  }

  // Step 3: Write token to Keychain [critical:security]
  await setToken(FEISHU_TOKEN_SERVICE, accessToken);
  if (refreshToken) {
    await setToken(FEISHU_REFRESH_TOKEN_SERVICE, refreshToken);
  }

  // Step 4: Remove plaintext token from lark-cli config
  await scrubPlaintextTokenFromConfig(configPath, larkConfig.rawConfig);

  return { success: true, alreadyMigrated: false, tokenFound: true };
}

/**
 * Get the current access token from Keychain (for injecting into lark-cli env).
 * Usage: spawn lark-cli with env { LARK_ACCESS_TOKEN: await getFeishuToken() }
 */
export async function getFeishuToken(): Promise<string | null> {
  return getToken(FEISHU_TOKEN_SERVICE);
}

/**
 * Revoke and delete stored tokens (used during uninstall / account switch).
 */
export async function revokeAndDeleteTokens(): Promise<void> {
  await deleteToken(FEISHU_TOKEN_SERVICE);
  await deleteToken(FEISHU_REFRESH_TOKEN_SERVICE);
}

// ─── lark-cli config parsing ──────────────────────────────────────────────

interface LarkCliConfig {
  accessToken: string | null;
  refreshToken: string | null;
  configPath: string;
  rawConfig: Record<string, unknown>;
}

const LARK_CLI_CONFIG_PATHS = [
  join(os.homedir(), ".lark-cli", "config.json"),
  join(os.homedir(), ".lark-cli", "config.yaml"),
  join(os.homedir(), ".lark-cli.json"),
  join(os.homedir(), ".config", "lark-cli", "config.json"),
];

async function readLarkCliConfig(): Promise<LarkCliConfig | null> {
  for (const configPath of LARK_CLI_CONFIG_PATHS) {
    try {
      await access(configPath);
      const raw = await readFile(configPath, "utf8");
      let parsed: Record<string, unknown>;

      if (configPath.endsWith(".json")) {
        parsed = JSON.parse(raw);
      } else {
        // Basic YAML key: value parsing for token fields
        parsed = parseMinimalYaml(raw);
      }

      const accessToken = extractToken(parsed, [
        "access_token",
        "accessToken",
        "token",
        "user_access_token",
      ]);
      const refreshToken = extractToken(parsed, [
        "refresh_token",
        "refreshToken",
      ]);

      return { accessToken, refreshToken, configPath, rawConfig: parsed };
    } catch {
      continue;
    }
  }
  return null;
}

function extractToken(
  config: Record<string, unknown>,
  keys: string[]
): string | null {
  for (const key of keys) {
    const val = config[key] ?? (config.auth as any)?.[key] ?? (config.credentials as any)?.[key];
    if (typeof val === "string" && val.length > 0) return val;
  }
  return null;
}

function parseMinimalYaml(content: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const line of content.split("\n")) {
    const match = line.match(/^(\w+):\s*(.+)$/);
    if (match) {
      result[match[1]] = match[2].trim().replace(/^["']|["']$/g, "");
    }
  }
  return result;
}

/**
 * Overwrite the lark-cli config file with tokens zeroed out.
 * [critical:security] Prevents residual plaintext credential exposure.
 */
async function scrubPlaintextTokenFromConfig(
  configPath: string,
  rawConfig: Record<string, unknown>
): Promise<void> {
  const tokenFields = [
    "access_token", "accessToken", "token", "user_access_token",
    "refresh_token", "refreshToken",
  ];

  const scrubbed = { ...rawConfig };
  for (const field of tokenFields) {
    if (field in scrubbed) {
      scrubbed[field] = ""; // Zero out in place (preserve schema)
    }
    // Also scrub nested auth/credentials objects
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
