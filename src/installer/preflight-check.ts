/**
 * @quickport/installer/preflight-check
 *
 * Runtime dependency verification before installation proceeds.
 * Called by Tauri frontend on first launch and before any install step.
 *
 * Per ADR-002 §deploy-constraints:
 *   - Node.js ≥ 18 is required (MCP server sidecar is Node.js)
 *   - macOS 12+ or Windows 10+ required
 *   - 50MB free disk space required
 *
 * Design: fail loudly with actionable guidance — never silently install
 * missing dependencies (user sovereignty + security per @Arch cd1f2965).
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { statfs } from "node:fs/promises";
import os from "node:os";

const execFileAsync = promisify(execFile);

export interface PreflightResult {
  ok: boolean;
  errors: PreflightError[];
  warnings: PreflightWarning[];
  nodeVersion?: string;
  platform: string;
  arch: string;
}

export interface PreflightError {
  code: string;
  message: string;
  resolution: string;
  url?: string;
}

export interface PreflightWarning {
  code: string;
  message: string;
}

const MIN_NODE_MAJOR = 18;
const MIN_DISK_MB = 50;

/**
 * Run all preflight checks.
 * Returns a PreflightResult — callers should show errors in UI and block installation.
 */
export async function runPreflightChecks(installDir?: string): Promise<PreflightResult> {
  const errors: PreflightError[] = [];
  const warnings: PreflightWarning[] = [];
  let nodeVersion: string | undefined;

  // ── Check 1: Node.js ≥ 18 ────────────────────────────────────────────────
  try {
    const { stdout } = await execFileAsync("node", ["--version"]);
    const versionStr = stdout.trim(); // "v22.1.0"
    nodeVersion = versionStr;

    const major = parseInt(versionStr.replace(/^v/, "").split(".")[0], 10);
    if (isNaN(major) || major < MIN_NODE_MAJOR) {
      errors.push({
        code: "NODE_VERSION_TOO_OLD",
        message: `Node.js ${versionStr} is installed, but QuickPort requires ≥ v${MIN_NODE_MAJOR}.`,
        resolution: `Upgrade Node.js using nvm: \`nvm install ${MIN_NODE_MAJOR} && nvm use ${MIN_NODE_MAJOR}\``,
        url: "https://nodejs.org/en/download",
      });
    }
  } catch {
    errors.push({
      code: "NODE_NOT_FOUND",
      message: "Node.js is not installed or not in PATH.",
      resolution: `Install Node.js ≥ v${MIN_NODE_MAJOR} via nvm (recommended) or the official installer.`,
      url: "https://nodejs.org/en/download",
    });
  }

  // ── Check 2: lark-cli present (warning if missing — can be installed later) ──
  try {
    await execFileAsync("lark-cli", ["--version"]);
  } catch {
    warnings.push({
      code: "LARK_CLI_NOT_FOUND",
      message:
        "lark-cli is not installed. It will be installed automatically as part of QuickPort setup.",
    });
  }

  // ── Check 3: Disk space ──────────────────────────────────────────────────
  try {
    const dir = installDir ?? os.homedir();
    const stats = await statfs(dir);
    const freeMB = (stats.bfree * stats.bsize) / (1024 * 1024);
    if (freeMB < MIN_DISK_MB) {
      errors.push({
        code: "INSUFFICIENT_DISK",
        message: `Only ${Math.round(freeMB)}MB free in ${dir}. QuickPort requires at least ${MIN_DISK_MB}MB.`,
        resolution: "Free up disk space and try again.",
      });
    }
  } catch {
    warnings.push({
      code: "DISK_CHECK_FAILED",
      message: "Could not determine available disk space. Proceeding with caution.",
    });
  }

  // ── Check 4: OS version ──────────────────────────────────────────────────
  const platform = os.platform();
  const release = os.release();

  if (platform === "darwin") {
    // macOS release format: "21.x.x" = macOS 12 Monterey
    const majorRelease = parseInt(release.split(".")[0], 10);
    if (!isNaN(majorRelease) && majorRelease < 21) {
      errors.push({
        code: "MACOS_TOO_OLD",
        message: `macOS ${release} is below the minimum required version (macOS 12 Monterey).`,
        resolution: "Upgrade to macOS 12 or later in System Preferences → Software Update.",
      });
    }
  } else if (platform === "win32") {
    // Windows 10 = release "10.0.xxxxx"
    const [majorStr] = release.split(".");
    const major = parseInt(majorStr, 10);
    if (!isNaN(major) && major < 10) {
      errors.push({
        code: "WINDOWS_TOO_OLD",
        message: `Windows ${release} is below the minimum required version (Windows 10).`,
        resolution: "Upgrade to Windows 10 or later.",
      });
    }
  } else {
    warnings.push({
      code: "UNSUPPORTED_PLATFORM",
      message: `Platform "${platform}" is not officially supported. QuickPort supports macOS and Windows.`,
    });
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    nodeVersion,
    platform,
    arch: os.arch(),
  };
}

// ── CLI entrypoint (node src/installer/preflight-check.js) ───────────────
if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await runPreflightChecks();
  if (!result.ok) {
    console.error("❌ QuickPort preflight checks FAILED:\n");
    for (const err of result.errors) {
      console.error(`  [${err.code}] ${err.message}`);
      console.error(`  ✅ How to fix: ${err.resolution}`);
      if (err.url) console.error(`  🔗 ${err.url}`);
      console.error();
    }
    process.exit(1);
  }
  if (result.warnings.length > 0) {
    console.warn("⚠️  Warnings:\n");
    for (const w of result.warnings) {
      console.warn(`  [${w.code}] ${w.message}`);
    }
  }
  console.log(
    `✅ Preflight checks passed (Node.js ${result.nodeVersion}, ${result.platform}/${result.arch})`
  );
}
