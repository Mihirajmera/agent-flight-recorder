# Agent Flight Report

**7 tool calls** by release-bot on behalf of dana@example.com, across 1 session (2026-10-12T00:00:00.000Z to 2026-10-12T00:00:00.000Z).

**3 findings** (0 high, 2 medium, 1 low).

## Log integrity

- **Entries:** 16, chain intact
- **Signatures:** 16 signed entries; all verified
- **Anchor:** none given
- **Log file sha256:** `32e81423ebf0bc80ea50b48390c7d070faf24b27a101e0a953851d196a80f1c4`
- **Head (store this elsewhere to detect truncation):** `15:711fe81addb8f148b815bb097a47a953b3291c529bccaadaeae7d4f2d2058e91`

## Decisions

| Tool | allow | approval-required | approved | deny |
|---|---:|---:|---:|---:|
| delete_branch | 0 | 1 | 1 | 0 |
| get_pull_request | 1 | 0 | 0 | 0 |
| merge_pull_request | 0 | 2 | 1 | 0 |
| push_files | 0 | 0 | 0 | 1 |

## Control results

| Check | Control | Result | Frameworks |
|---|---|---|---|
| AFR-01 | The flight log is complete and unaltered | NOTE | NIST 800-53 AU-9, AU-9(3), AU-10; SOC 2 CC7.2; ISO 42001 A.6.2.8; EU AI Act Art. 12 |
| AFR-02 | Every tool call is attributed to an agent and the person it acts for | PASS | NIST 800-53 AU-3; SOC 2 CC7.2; ISO 42001 A.6.2.8; EU AI Act Art. 12 |
| AFR-03 | Calls that need approval ran only with a valid, single-use human approval | PASS | NIST 800-53 AC-3, AC-6; SOC 2 CC6.1, CC8.1; EU AI Act Art. 14 |
| AFR-04 | Nobody approved an agent acting on their own behalf | FAIL | NIST 800-53 AC-5; SOC 2 CC6.3; EU AI Act Art. 14 |
| AFR-05 | Policy decisions were enforced | PASS | NIST 800-53 AC-3; SOC 2 CC6.1 |
| AFR-06 | Tool definitions did not change without review | FAIL | NIST 800-53 CM-3, SI-7; SOC 2 CC8.1 |
| AFR-07 | Every forwarded call has a recorded outcome | PASS | NIST 800-53 AU-12; SOC 2 CC7.2; ISO 42001 A.6.2.8; EU AI Act Art. 12 |

## Findings

| Check | Severity | Entry | Finding |
|---|---|---:|---|
| AFR-04 | medium | 11 | dana@example.com approved a delete_branch call that the agent made on their own behalf. |
| AFR-06 | medium | 14 | Tool merge_pull_request on github changed its description since entry 1. Review what it now tells the agent. |
| AFR-01 | low |  | No anchor was given, so removal of the most recent entries can't be ruled out. Store the head from `afr verify` outside this system. |

## Approvals

| Entry | Time | Tool | Requested for | Approver | Decision | Expires |
|---:|---|---|---|---|---|---|
| 6 | 2026-10-12T00:00:00.000Z | merge_pull_request | dana@example.com | priya@example.com | approved | 2026-10-12T01:00:00.000Z |
| 11 | 2026-10-12T00:00:00.000Z | delete_branch | dana@example.com | dana@example.com | approved | 2026-10-12T01:00:00.000Z |

Evidence: `evidence.json` (sha256 `d3f6c20ac38d8db5…`). Every call, with its hashes, is in `calls.csv`.

## Sign-off

| Role | Name | Date |
|---|---|---|
| Agent owner | | |
| Reviewer | | |
