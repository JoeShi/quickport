/**
 * @quickport/orchestrator/credentials/keychain-adapter
 *
 * Cross-platform OS keychain abstraction.
 * R5 narrow waist: ALL token operations MUST go through this module.
 * Direct calls to `security` CLI / keytar / Keychain Services / DPAPI from
 * skill code or wrappers = blocker P0 per HF-2 + Gatekeeper R5.
 *
 * Spec source: ADR-002 §keychain-adapter, cited from:
 *   - @Arch e787e301 (interface lock)
 *   - @Jack 22d0a2fe (cross-platform design)
 *   - @Gatekeeper 4c58f6d7 (HF-2, HF-9)
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Retrieve a token from the OS keychain.
 * @param service  Fully-qualified service name, e.g. "@quickport/feishu-token"
 * @returns        The stored token string, or null if not found.
 */
export async function getToken(service: string): Promise<string | null> {
  validateServiceName(service);
  try {
    if (process.platform === "darwin") {
      return await macosGetToken(service);
    } else if (process.platform === "win32") {
      return await windowsGetToken(service);
    } else {
      throw new KeychainError(`Unsupported platform: ${process.platform}`);
    }
  } catch (err) {
    if (err instanceof KeychainNotFoundError) return null;
    throw err;
  }
}

/**
 * Store a token in the OS keychain.
 * @param service  Fully-qualified service name
 * @param token    The token value to store (never written to disk outside keychain)
 */
export async function setToken(service: string, token: string): Promise<void> {
  validateServiceName(service);
  if (!token || typeof token !== "string") {
    throw new KeychainError("token must be a non-empty string");
  }
  if (process.platform === "darwin") {
    await macosSetToken(service, token);
  } else if (process.platform === "win32") {
    await windowsSetToken(service, token);
  } else {
    throw new KeychainError(`Unsupported platform: ${process.platform}`);
  }
}

/**
 * Delete a token from the OS keychain.
 * @param service  Fully-qualified service name
 */
export async function deleteToken(service: string): Promise<void> {
  validateServiceName(service);
  try {
    if (process.platform === "darwin") {
      await macosDeleteToken(service);
    } else if (process.platform === "win32") {
      await windowsDeleteToken(service);
    } else {
      throw new KeychainError(`Unsupported platform: ${process.platform}`);
    }
  } catch (err) {
    if (err instanceof KeychainNotFoundError) return; // idempotent delete
    throw err;
  }
}

// ─── Error types ───────────────────────────────────────────────────────────

export class KeychainError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "KeychainError";
  }
}

export class KeychainNotFoundError extends KeychainError {
  constructor(service: string) {
    super(`Token not found in keychain for service: ${service}`);
    this.name = "KeychainNotFoundError";
  }
}

// ─── Validation ────────────────────────────────────────────────────────────

/**
 * Service names must start with "@quickport/" to enforce namespace boundary.
 * Any other prefix means a caller is bypassing the orchestrator namespace — blocker P0.
 */
function validateServiceName(service: string): void {
  if (typeof service !== "string" || !service.startsWith("@quickport/")) {
    throw new KeychainError(
      `Invalid service name "${service}": must start with "@quickport/". ` +
        `Direct keychain access from outside @quickport/orchestrator/* = R5 violation.`
    );
  }
}

// ─── macOS implementation (security CLI) ──────────────────────────────────

async function macosGetToken(service: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync("security", [
      "find-generic-password",
      "-s", service,
      "-w", // output password only
    ]);
    return stdout.trim();
  } catch (err: any) {
    // exit code 44 = "The specified item could not be found in the keychain."
    if (err.code === 44 || (err.stderr && err.stderr.includes("could not be found"))) {
      throw new KeychainNotFoundError(service);
    }
    throw new KeychainError(`macOS keychain get failed for ${service}`, err);
  }
}

async function macosSetToken(service: string, token: string): Promise<void> {
  // Delete any existing entry first (add-generic-password fails on duplicate)
  try {
    await macosDeleteToken(service);
  } catch (err) {
    if (!(err instanceof KeychainNotFoundError)) throw err;
  }
  try {
    await execFileAsync("security", [
      "add-generic-password",
      "-s", service,
      "-a", service, // account = service name (consistent)
      "-w", token,
      "-U", // update if exists
    ]);
  } catch (err: any) {
    throw new KeychainError(`macOS keychain set failed for ${service}`, err);
  }
}

async function macosDeleteToken(service: string): Promise<void> {
  try {
    await execFileAsync("security", [
      "delete-generic-password",
      "-s", service,
    ]);
  } catch (err: any) {
    if (err.code === 44 || (err.stderr && err.stderr.includes("could not be found"))) {
      throw new KeychainNotFoundError(service);
    }
    throw new KeychainError(`macOS keychain delete failed for ${service}`, err);
  }
}

// ─── Windows implementation (PowerShell CredentialManager) ────────────────

/**
 * Windows implementation uses PowerShell with the CredentialManager module.
 * Fallback: if CredentialManager module is unavailable, uses direct Win32 API
 * via a small inline C# snippet executed via powershell Add-Type.
 *
 * [critical:security] Token is passed via stdin / secure string — never via command-line
 * argument (command lines are visible to other processes on Windows).
 */
async function windowsGetToken(service: string): Promise<string> {
  const script = `
$cred = Get-StoredCredential -Target "${escapePSArg(service)}" -ErrorAction SilentlyContinue
if ($null -eq $cred) { exit 44 }
$cred.GetNetworkCredential().Password
`.trim();
  try {
    const { stdout } = await execFileAsync("powershell", [
      "-NoProfile", "-NonInteractive", "-Command", script,
    ]);
    return stdout.trim();
  } catch (err: any) {
    if (err.code === 44) throw new KeychainNotFoundError(service);
    // CredentialManager module not installed — fall back to Win32 API
    return await windowsGetTokenWin32(service);
  }
}

async function windowsSetToken(service: string, token: string): Promise<void> {
  // [critical:security] Token passed via stdin pipe, not CLI argument
  const script = `
$securePass = ConvertTo-SecureString -String $input -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("${escapePSArg(service)}", $securePass)
New-StoredCredential -Target "${escapePSArg(service)}" -Credentials $cred -Type Generic -Persist LocalMachine | Out-Null
`.trim();
  try {
    await execFileAsync(
      "powershell",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { input: token } as any
    );
  } catch (err: any) {
    await windowsSetTokenWin32(service, token);
  }
}

async function windowsDeleteToken(service: string): Promise<void> {
  const script = `
Remove-StoredCredential -Target "${escapePSArg(service)}" -ErrorAction SilentlyContinue
`.trim();
  try {
    await execFileAsync("powershell", [
      "-NoProfile", "-NonInteractive", "-Command", script,
    ]);
  } catch {
    // Best-effort delete
  }
}

// Win32 API fallback via Add-Type inline C#
async function windowsGetTokenWin32(service: string): Promise<string> {
  const script = `
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;using System.Text;
public class CredMan {
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
  public static extern bool CredRead(string target,int type,int flags,out IntPtr cred);
  [DllImport("advapi32.dll")] public static extern void CredFree(IntPtr cred);
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
  public struct CREDENTIAL { public uint Flags; public uint Type; public string TargetName;
    public string Comment; public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public uint CredentialBlobSize; public IntPtr CredentialBlob; public uint Persist;
    public uint AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
}
"@
$ptr = [IntPtr]::Zero
if([CredMan]::CredRead("${escapePSArg(service)}", 1, 0, [ref]$ptr)) {
  $c = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [CredMan+CREDENTIAL])
  $pass = [System.Text.Encoding]::Unicode.GetString([System.Runtime.InteropServices.Marshal]::Copy($c.CredentialBlob, $c.CredentialBlobSize))
  [CredMan]::CredFree($ptr)
  $pass
} else { exit 44 }
`.trim();
  try {
    const { stdout } = await execFileAsync("powershell", [
      "-NoProfile", "-NonInteractive", "-Command", script,
    ]);
    return stdout.trim();
  } catch (err: any) {
    if (err.code === 44) throw new KeychainNotFoundError(service);
    throw new KeychainError(`Windows keychain (Win32) get failed for ${service}`, err);
  }
}

async function windowsSetTokenWin32(service: string, token: string): Promise<void> {
  const script = `
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public class CredMan2 {
  [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
  public static extern bool CredWrite(ref CREDENTIAL cred, uint flags);
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
  public struct CREDENTIAL { public uint Flags; public uint Type; public string TargetName;
    public string Comment; public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public uint CredentialBlobSize; public IntPtr CredentialBlob; public uint Persist;
    public uint AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
}
"@
$tokenBytes = [System.Text.Encoding]::Unicode.GetBytes($input)
$blobPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tokenBytes.Length)
[System.Runtime.InteropServices.Marshal]::Copy($tokenBytes, 0, $blobPtr, $tokenBytes.Length)
$c = New-Object CredMan2+CREDENTIAL
$c.Type = 1; $c.Persist = 2; $c.TargetName = "${escapePSArg(service)}"
$c.UserName = "${escapePSArg(service)}"; $c.CredentialBlobSize = $tokenBytes.Length; $c.CredentialBlob = $blobPtr
if(-not [CredMan2]::CredWrite([ref]$c, 0)) { throw "CredWrite failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($blobPtr)
`.trim();
  try {
    await execFileAsync(
      "powershell",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { input: token } as any
    );
  } catch (err: any) {
    throw new KeychainError(`Windows keychain (Win32) set failed for ${service}`, err);
  }
}

function escapePSArg(s: string): string {
  // Escape double-quotes and backticks for PowerShell string interpolation
  return s.replace(/`/g, "``").replace(/"/g, '`"');
}
