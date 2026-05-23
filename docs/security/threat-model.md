# QuickPort Threat Model

> Living document. Last updated: 2026-05-23.
> Each new industry event is evaluated against R1-R11 coverage and either (a) already covered,
> (b) triggers a new rule, or (c) deferred to v2+ as known limitation.

---

## 1. Known Attack Vectors (by Severity)

### P0 — Blocker (Install Prevented)

| Vector | Description | QuickPort Rule |
|---|---|---|
| **Network Exfiltration** | Code sends data to domains not declared in manifest | R1 network-domain-diff |
| **Sensitive FS Write** | Writing to `~/.ssh`, `/etc`, keychain paths, or outside skill directory | R2 fs-write-sensitive + R2-outside-skill-dir |
| **Unauthorized Process Spawn** | Spawning child processes without manifest declaration | R3 process-spawn-diff |
| **Narrow Waist Bypass** | Direct write to `mcp_config.json`, capability-registry, audit log, or direct keychain access | R5 narrow-waist-bypass |
| **Hardcoded Secrets** | AWS keys, GitHub tokens, private keys, Slack tokens embedded in code | R6 secrets-scan |
| **Eval / Code Injection** | `eval()`, `Function()`, `vm.runIn*Context()` | R7-eval-exec-inject |
| **Shell Injection** | `exec()` with template literal interpolation, string concatenation, or dynamic variables | R7-bis-shell-injection |
| **Manifest Structure Violation** | Missing required fields, invalid semver, missing capabilities declaration | R0 manifest-validation |

### P1 — Requires User Consent

| Vector | Description | QuickPort Rule |
|---|---|---|
| **Dynamic Require** | `require(variable)` enabling arbitrary module loading at runtime | R7-dynamic-require |
| **SBOM CVE** | Dependencies with known CVEs (currently stub, v0.3 full integration) | R8 sbom-cve |

### P2 — Suggestion

| Vector | Description | QuickPort Rule |
|---|---|---|
| **Capability Completeness** | Declared capabilities vs actual usage gaps | R9 (deferred) |
| **Version Freshness** | Outdated dependencies | R10 (deferred) |

---

## 2. Industry Event Timeline

### 2025

| Date | Event | Platform | Attack Vector | Impact | QuickPort Coverage |
|---|---|---|---|---|---|
| 2025-09 | **Postmark-MCP** — first known malicious MCP server | npm | Name typosquatting + token exfiltration | Email credentials stolen | R1 + R6 ✅ |
| 2025-Q4 | **ClawHavoc** — 341 malicious Claude Skills | ClawHub | Malicious manifest declarations | Large-scale skill marketplace pollution | R0 + R7 ✅ |

### 2026

| Date | Event | Platform | Attack Vector | Impact | QuickPort Coverage |
|---|---|---|---|---|---|
| 2026-Q1 | **Snyk ToxicSkills** research | ClawHub | 36% of skills contain prompt injection | Full ClawHub sampling | R7 (manifest taint) ✅ |
| 2026-02 | **Straiker** — 71 malicious Claude Skills | ClawHub | Malicious manifest + token exfiltration | 3,505 skills scanned, 71 malicious + 73 high-risk | R0 + R6 ✅ |
| 2026-04-15 | **OX Security MCP "By Design" RCE** | MCP Protocol | stdio spawn design flaw | ~200,000 MCP servers, 10 CVEs, 9 marketplaces contaminated | **HF-7 spawn whitelist + HF-3'F sandbox directly mitigates** ✅ |
| 2026-04-29 | **ClawHub Cryptomining** — 30 skills | ClawHub | "Consent-free" resource abuse | Single author, 30 skills silently mining crypto | R3 + R8 (capability overreach) ✅ |
| 2026-05-11 | **TanStack "Mini Shai-Hulud"** | npm | GitHub Actions OIDC abuse + dependency poisoning | 42 packages / 84 malicious versions / 6-minute propagation / CVSS 9.6 | R8 SBOM CVE + supply chain ⚠️ stub |
| 2026-05-18~20 | **Nx Console VS Code Extension** → GitHub internal breach | VS Code / GitHub | Developer credential leak → backdoored versions | 3,800 GitHub internal repositories, data sold at $50K-$95K | R5 narrow waist + R6 (token storage) ✅ |
| 2026-05-22 | **arXiv 2604.03081** — SKILL.md prompt injection | Academic | Manifest natural-language prompt injection | "Minor edits make agents go rogue"; regex/AST cannot detect | **❌ Beyond R1-R11 static analysis — v2+ deferred** |

---

## 3. R1-R11 Coverage Matrix

| Industry Vector | Our Coverage | Status | Known Gap |
|---|---|---|---|
| Token exfiltration | R1 / R6 | ✅ v0.2 | Dynamic host construction (cross-file taint, v2) |
| Sensitive FS write | R2 | ✅ v0.2 | — |
| Unauthorized process spawn | R3 + HF-7 | ✅ v0.2 | — |
| Narrow waist bypass | R5 | ✅ v0.2 | Win credential bindings (v0.3) |
| Hardcoded secrets | R6 | ✅ v0.2 | — |
| Eval / shell injection | R7 + R7-bis | ✅ v0.2 | Multi-line concatenation (v2) |
| Dependency CVE | R8 | ⚠️ stub | osv-scanner integration (v0.3) |
| Malicious manifest declarations | R0 / R1 / R9 | ✅ v0.2 | — |
| **Prompt injection in SKILL.md** | ❌ | **v2+** | **LLM-based semantic review required** |
| Protocol-design RCE (OX MCP) | HF-7 + HF-3'F | ✅ v0.2 | — |
| Slopsquatting (AI-hallucinated package names) | ⚠️ partial | v0.3+ | Dependency name novelty check |
| Native FFI Security.framework | ❌ | v2+ | Cross-file taint analysis |

---

## 4. Known Limitations / v2+ Deferred

### 4.1 Prompt Injection in SKILL.md (arXiv 2604.03081)

**Statement**: R1-R11 static analysis based on regex and AST cannot detect malicious natural-language instructions embedded in `SKILL.md` or manifest descriptions.

**Evidence**: arXiv 2604.03081 (2026-05-22) demonstrates that "minor edits to SKILL.md make agents go rogue" and that regex/AST-based detection is insufficient.

**Mitigation Path**: LLM-based semantic review of manifest descriptions. Deferred to v2+.

**Why Not v1**: Adds significant latency and cost to the scan pipeline. v1 prioritizes fast static analysis for install-time gatekeeping.

### 4.2 Cross-File Taint Analysis

**Statement**: Multi-step attacks where sensitive data flows across files (e.g., `const cmd = base + suffix; exec(cmd)` across separate statements/modules) are not reliably detected by per-file regex scanning.

**Evidence**: Industry events show attackers increasingly using multi-file/multi-step obfuscation.

**Mitigation Path**: `ts-morph` or `babel` post-processor integrated with Semgrep for cross-file data flow analysis. Deferred to v2+.

### 4.3 Native FFI Bindings

**Statement**: Skills using `node-ffi-napi` or similar to directly call OS-native security APIs (e.g., Apple Security.framework, Windows Credential Manager) bypass JS-level regex detection.

**Mitigation Path**: Binary analysis / N-API call graph inspection. Deferred to v2+.

---

## 5. References

| Source | URL | Relevance |
|---|---|---|
| OX Security MCP RCE | https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/ | HF-7 rationale |
| The Hacker News — GitHub breach via Nx Console | https://thehackernews.com/2026/05/github-internal-repositories-breached.html | R5 + R6 validation |
| Snyk ToxicSkills | https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ | R7 (manifest taint) |
| Koi.ai ClawHavoc 341 | https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-target... | R0 + R7 |
| arXiv 2604.03081 SKILL.md injection | https://arxiv.org/abs/2604.03081 | §known-limitations |
| The Register — 30 ClawHub crypto miners | https://www.theregister.com/2026/04/29/30_clawhub_skills_mine_crypto/ | R3 + R8 |
| BeyondMachines TanStack | https://beyondmachines.net/event_details/tanstack-npm-packages-compromised-in-mini-shai-hulud-supply-chain-attack-e-5-d-8-3 | R8 supply chain |
| StepSecurity Nx Console | https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised | R5 + R6 |

---

## 6. Update Protocol

1. New industry event reported → evaluate against R1-R11 coverage matrix
2. If **already covered**: Add event to §2 timeline, no code change needed
3. If **partially covered**: Add to §3 matrix with ⚠️, schedule for next minor version
4. If **not covered**: Add to §4 known limitations, assess whether v0.x patch or v2+ deferred
5. Commit to this file with date + event name in commit message
