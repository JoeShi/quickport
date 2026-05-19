# ADR-0001: PRD Tag / Severity / Trace Format Crosswalk

**Status**: STUB v0.1 (ship-first per protocol — sections marked TBD will be iterated via PR)
**Owner**: Arch
**Stakeholders**: Maya (PRD), Gatekeeper (Review), Cody / Jack / KimiCoder (Implementation)
**Date drafted**: 2026-05-18
**Date stub-committed**: 2026-05-19
**Anchor thread**: Slock `#all:edb0a7c9` + `#dev:62ac91f4`
**Source PRD**: PRD-Template v0.1 final (Slock thread `#all:edb0a7c9` msg=`2c7f510e` + 5 patches in msg=`bb796ca3`)

---

## 1. Context

The QuickPort team adopted a 4-stage pipeline for software delivery:

**PRD (Maya) → Architecture (Arch) → Implementation (Cody / Jack / KimiCoder) → Review (Gatekeeper)**

A single canonical reference is needed for:
- How constraints are tagged in PRDs
- How reviewers interpret tags
- How traces are followed across documents and code

This ADR codifies that crosswalk.

## 2. Decision

Three-layer governance: **Two orthogonal axes + Hard Floors + Exception Clauses**.

### 2.1 Two Orthogonal Axes

| Axis | Values | Determines |
|---|---|---|
| **Severity** | `P0` / `P1` / `P2` | Review action (blocker / suggestion / nit) |
| **Dimension** | `[critical:security]` / `[critical:perf]` (extensible) | Review playbook |

Combinations are explicit: `P0 [critical:security]`, `P2 [critical:perf]`, dual-tag `[critical:security] [critical:perf]`.

### 2.2 Severity → Review Action

| Severity | Review Action | Outcome |
|---|---|---|
| **P0 Mandatory** | blocker | Must fix or reject |
| **P1 Important** | suggestion | Must accept risk explicitly in ADR `已知 trade-off` |
| **P2 Advisory** | nit | Optional follow-up |

### 2.3 Strictness Direction Rule (Hard Floors)

**Strictness can only ratchet upward, never downward.** Default floors (cannot be unilaterally lowered in PRD; downgrade requires ADR exception clause):

| Dimension | Auto-tier | Note |
|---|---|---|
| PII | P0 | Granularity: contact / identity / sensitive-biometric |
| AuthN bypass | P0 | Non-negotiable |
| Cross-border data transfer | P0 | Non-negotiable |
| Externally-promised SLA (contract / public) | P0 | Non-negotiable |
| New external dependency | P1 | Business may upgrade |
| SLA p99 / capacity peak | P1 | Business may upgrade |

When a requirement crosses multiple defaults, the **highest tier wins** (consistent with upward-only rule).

### 2.4 Exception Clause (the only programmatic downgrade path)

To downgrade any hard floor:
1. Open OQ in PRD thread: `[OQ-N owner:@Arch deadline:<milestone>] §x.y request P-downgrade, reasoning: ...`
2. Arch decides: **reject** (keep floor) OR **accept** (add exception clause to this ADR)

**5 mandatory subfields** (any missing → review blocker, exception void):

- `approved_by:` Specific person/role, DPO if applicable. Vague references ("team", "business") → blocker
- `business_reason:` Concrete business rationale. Hand-waves ("launch pressure") → blocker
- `expires_at:` Milestone-anchored expiry (auto-restores to hard floor)
- `revoke_trigger:` Event-triggered re-evaluation
- `review_due:` Calendar-anchored next review

**PII downgrade additional**: Granularity (contact / identity / sensitive-biometric) must be explicit; mismatch with downgrade depth → blocker.

### 2.5 Dimension → Playbook

| Dimension | Scope |
|---|---|
| `[critical:security]` | AuthN, PII, injection surface, dependency CVEs, compliance, cross-border |
| `[critical:perf]` | Hot paths, SLA, capacity, latency, **error rate (joint observation with latency)** |

**Error rate spec**: `error_rate(window) < x%`, default window = 5min rolling. Non-default windows must be declared in PRD/ADR.

**Joint observation requirement**: Error rate and latency must be observed together (rate-limit / degradation scenarios where latency stays normal but success rate collapses cannot be missed).

### 2.6 Dual-tag Arbitration

- **Depth** is determined by the higher severity (review intensity uses the highest tier).
- **Scope** is determined by the dimension set (all `[critical:*]` playbooks must run).
- Multi-tag formatting: space-separated, alphabetic order (tooling-friendly).

### 2.7 Trace Format (grep-friendly)

- **Generic prefix**: `<tier> <severity> <dimension(s)> ref:<source>`
  - Example: `blocker P0 [critical:security] ref:PRD-FOO §3.2`
- **Review comment**: `<tier> <severity> <dimension(s)>: <content> [回链]`
  - Example: `blocker P0 [critical:security]: PII not encrypted → ADR-BAR §AuthN`
  - Example: `suggestion P1 [critical:security] [critical:perf] ref:PRD-FOO §3.2 → ADR-BAR trade-off #1`
- **ADR `已知 trade-off`**: `ref:PRD-FOO §3.2 [P1 critical:security] → trade-off #1`, with named `approved_by`
- **`ref:` no space after colon** (single-token grep stability)

Triplet (PRD / ADR / Review) grep on `PRD-FOO §3.2` → full chain.

### 2.8 OQ Rules

- Format: `[OQ-N owner:@who deadline:<milestone>] question text`
- **Deadline must be a milestone anchor** (no absolute dates, no `pre-` prefix):
  - **5 anchors (locked v0.1 final)**: `PRD-finalize | ADR-draft | ADR-finalize | code-freeze | release`
- Downgrade OQ is a regular OQ specialization: `[OQ-3 owner:@Arch deadline:ADR-draft] §3.1 PII "email" requesting P1, reasoning: marketing consent + revocable`
- Past-deadline unresolved OQ → **blocker**
- Unknown values: explicit `P?` or `[OQ: TBD]`, **no blanks**
- **ADR cannot finalize while any of its OQs is unresolved**; affected sections marked `status: pending OQ-N`

### 2.9 PRD ↔ ADR Versioning (semver)

| PRD Version Type | Trigger | ADR Action |
|---|---|---|
| **major** | Scope / SLA / compliance class change | Full re-evaluation (patch or re-decide) |
| **minor** | Clarification / AC additions / wording | Scan changelog; patch only if affected |
| **patch** | Typo / formatting | No ADR action; sync local cache |

Each version carries a 1-2 line changelog. ADR references PRD version explicitly. PRD major bump → ADR must declare action (patch / re-eval / noop with rationale).

### 2.10 Review-Time Fallback Playbook (Gatekeeper)

For any item triggering an auto-P0 hard floor (PII / AuthN bypass / Cross-border / External-promised SLA):

1. Is severity < P0?
2. If yes → grep ADR-001 exception clauses for the **exact PRD entry ID** (precise to §x.y)
3. If not listed OR any of 5 subfields missing → `blocker P0 [critical:*] ref:PRD-X §y.z: ADR-001 exception missing/incomplete; restore P0 or complete clause`

### 2.11 Dimension Governance (Arch-owned)

- **New `[critical:*]` dimension**: ADR proposal containing definition / discrimination rules / canonical examples / review-depth recommendation. After merge, broadcast in `#dev` (pinned message).
- **Retired dimensions**: Same ADR process (avoid zombie vocabulary).
- **Initial set**: `security` + `perf`. Candidates for future ADR: `data` (data integrity), `availability` (fault tolerance).

## 3. Rationale (TBD — full prose to follow in PR iteration)

Two-line ceiling/floor framing (will expand):
- **Hard Floor (ceiling rule)**: Auto-applied; cannot be unilaterally lowered. Defends against "unintentional downgrade" of safety/compliance constraints.
- **Exception Clause (programmatic downgrade channel)**: Bounded (5 subfields), time-limited (`expires_at`), traceable (`approved_by` + `revoke_trigger`). Defends against "permanent escape hatch" failure mode.

Two enforcement points:
- **PRD-time guidance**: Author errors trigger OQ reminders / template field warnings.
- **Review-time enforcement**: Gatekeeper grep checklist; bypass-via-OQ-skipping cannot pass review.

## 4. Consequences (TBD — full prose to follow)

### 4.1 Positive
- Single shared vocabulary across PRD / ADR / code / review (grep-friendly trace).
- Severity × Dimension orthogonal decomposition; review depth (how strict) and review scope (how many playbooks) are independent.
- Exception clauses are bounded with built-in time + revocation.

### 4.2 Negative / Trade-offs
- PRD template complexity (§0–§12, 12 sections); onboarding cost.
- Small-project / prototype scenarios may feel over-governed. Mitigation: future fast-track lane in separate ADR.
- 5-anchor OQ is current minimum-viable; future may extend if real-world cases require.

### 4.3 Phase-2 Metrics (Maya-proposed; evaluate after first real-world cycle)
- Which `[critical:*]` triggers blockers most frequently?
- Which PRD assumptions get overturned most often by review?
- ADR decision stability (rewrite frequency)

## 5. References

- Anchor threads: Slock `#all:edb0a7c9` (protocol formation) + `#dev:62ac91f4` (QuickPort first-real-world-need)
- PRD-Template v0.1 final: msg=`2c7f510e` + 5 patches (`bb796ca3`)
- QuickPort PRD v0.1-FINAL (实战首跑): msg=`d505c8a3`
- Working notes: `notes/protocols.md` (private)
- Implementation references (实战首跑 evidence chain):
  - Jack 5-invariants quick-config-patcher: msg=`83657215` / `434c117b`
  - Gatekeeper 9 HF mode-dependent table: msg=`4c58f6d7`
  - Cody Quick MCP empirical study: msg=`d8b41585`
  - KimiCoder Scanner engine R0-R8: PR-merged commit `6591ea5`

## 6. Sign-off

- [ ] Maya
- [ ] Gatekeeper
- [x] Arch (author, stub-committed; full Rationale/Consequences prose pending PR iteration)

## 7. Broadcast Plan (executed at FINAL state)

When this ADR moves from STUB → FINAL, broadcast in `#dev` (pinned message):

```
📐 ADR-0001 LANDED: PRD Tag / Severity / Trace Format Crosswalk
- PRD-Template v0.1 final and ADR-0001 take effect together
- Tags: [critical:security] / [critical:perf]
- Severity: P0 / P1 / P2
- Review comment format: <tier> <severity> <dimension(s)>: <content> [回链]
- Full doc: https://github.com/JoeShi/quickport/blob/main/docs/adr/0001-prd-tag-severity-trace-crosswalk.md
- New/retired dimensions follow ADR governance
```

---

**STUB v0.1 commit notes**:
- §1, §2 (full subsections), §5 are CANONICAL (no further changes expected; if any, semver minor).
- §3, §4 have prose TBD; iterations via PR with `docs(adr-001):` commit prefix.
- §6 sign-offs to be filled by Maya / Gatekeeper after they review committed STUB.
