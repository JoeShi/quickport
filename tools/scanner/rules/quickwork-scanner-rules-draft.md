# QuickWork Skill Scanner — capability validation rules (draft v0)

> 状态：v0 草稿，等 ADR-003 起稿时与 @Arch 协同 finalize。
> 来源 anchor：6652affb / 9f62d2ea / c733a5e5 / f29e2adb / f2b34f8d。

## 设计原则
1. **manifest 必须显式声明 capability**（声明侧 v1 必须；enforcement 通过沙箱属于 v2）
2. **静态 AST 扫描代码实际调用**，与 manifest 声明做 diff
3. **diff 不一致 = blocker P0**，要求 skill 修正或拒装
4. **install-orchestrator 是唯一合规凭证操作通道**（绕过 = blocker P0）
5. **输出格式遵循 v0.1 协议**：`<tier> <severity> [critical:*] ref:skill-<name>#<rule-id>`

## Manifest schema slots（待 ADR-003 锁定）
```yaml
capabilities:
  network:
    domains: [api.feishu.cn, ...]      # outbound HTTP(S) 白名单
  fs:
    read: [~/.quickwork/<skill>/, ...]
    write: [~/.quickwork/<skill>/]
  process:
    spawn: [/usr/bin/git, ...]         # 默认空，spawn 任何子进程必须显式声明
  ipc:
    listen: []                         # local socket / named pipe（v2 schema slot）
    connect: []
  credentials:
    via: install-orchestrator          # 默认且唯一合法值
```

## AST 规则集

### R1: network domain diff
- 检测 `fetch / axios / http.request / urllib / requests` 的 host 参数
- 静态提取：字面量、模板拼接可解析部分、def-use 链
- 比对：实际 host vs `manifest.capabilities.network.domains`
- 实际 ⊄ 声明 → `blocker P0` + 动态 host 标记 unknown

### R2: FS path diff
- 检测 `fs.read*/write*/open/Path/pathlib` path 参数
- 写入 `~/.quickwork/<skill>/` 之外 = blocker P0
- 读取 `~/.ssh/.aws/.gnupg` 等敏感路径 = blocker P0（即使声明）

### R3: process spawn diff
- 检测 `child_process.exec/spawn / subprocess.* / os.system / Runtime.exec`
- 未声明 spawn 子进程 = blocker P0
- 命令含 shell metachar / 未 escape 用户输入 → blocker P0（command injection）

### R4: IPC endpoint diff (v2 schema slot)
- 检测 `net.createServer/.listen / unix-socket / named-pipe / dgram`
- 未声明 listen = blocker P0
- listen on 0.0.0.0 = blocker P0（外部可达）
- D-mode adapter 必须 token + ACL → R4-bis

### R4-tris: E-mode (Quick Action Connector) 6 硬底线
继承 D 模式 4 条 + HF-5 短 TTL token + auto-rotation + caller fingerprint + HF-6 audit caller_source schema (4 类事件 + caller_fingerprint)

### R5: install-orchestrator bypass detection（narrow waist）
- 检测 `keytar / Keychain Services / DPAPI / CredMan` 直接调用
- 三件套定义域：
  1. 公共 API 白名单：`@quickwork/orchestrator/*` namespace
  2. OS API 黑名单：`keytar / Keychain Services / DPAPI / CredMan`
  3. Module boundary：import 路径不属于 orchestrator 但调用黑名单 API = blocker
- Audit log 直接写 `.audit.json` = blocker P0；必须走 orchestrator API

### R6: secrets scan
- 工具：gitleaks / trufflehog 规则集
- 命中硬编码 secrets/keys = blocker P0

### R7: dangerous API
- 检测 `eval / Function / vm.runInThisContext / exec / require(变量)`
- 使用 = blocker P0，除非 manifest 显式声明 + 走 ADR 例外条款

### R8: SBOM CVE
- 工具：osv-scanner / npm audit / pip-audit / trivy
- CVSS ≥ 7 → blocker P0 / 4–7 → suggestion P1 / <4 → nit P2

### R9: declared-vs-actual capability completeness
- manifest 声明所有 capability 都被代码实际使用
- 声明但未使用 = suggestion P1（过度声明权限，least privilege violation）

### R10: skill version freshness
- skill 安装时记录版本；后续 version bump 触发完整重扫描
- 旧版 pass 不沿用

### R11 (deferred slot, OQ-21A 触发)
- capability declaration vs MCP server.listOfferings() diff scan（如 v1 用 Resources 则 v1 启用，否则 v2 候选）

## 扫描器输出 schema
```json
{
  "skill": "example-skill",
  "version": "1.2.3",
  "scanned_at": "2026-05-18T20:00:00Z",
  "coverage": ["static-analysis", "sbom-cve", "declared-vs-actual", "secrets"],
  "confidence": "high",
  "known_blind_spots": ["polymorphic-malware", "supply-chain-zero-day"],
  "findings": [
    {
      "tier": "blocker",
      "severity": "P0",
      "dimension": ["critical:security"],
      "ref": "skill-example-skill#R1",
      "message": "代码实际访问 evil.com，未在 manifest 声明"
    }
  ],
  "decision": "blocked"
}
```

## 与 ADR-001 例外条款接口
- blocker P0 → 安装按钮 disabled（v1 不允许 user override）
- suggestion P1 → 用户显式接受 + 写 ADR-style trade-off 到 `~/.quickwork/<skill>/.audit.json`
  - `.audit.json` 必须含 5 子字段：approved_by / business_reason / expires_at / revoke_trigger / review_due
- nit P2 → 提示后默认通过
