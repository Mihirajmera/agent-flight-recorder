# Changelog

## 0.1.0 (2026-10-26)

First release.

- `afr proxy`: wraps any stdio MCP server and applies a YAML policy to every `tools/call`. The policy can allow, deny, or require approval, with first-match rules on tool name patterns, server and argument regexes. It fails closed if the call can't be recorded.
- Approvals bound to the exact call (server, tool, arguments), with an expiry, single use, and the approver recorded in the log (`afr pending`, `afr approve`).
- Tamper-evident log: SHA-256 hash chain, optional Ed25519 signature on every entry, a cross-process lock so the proxy and approvers share one chain, and anchors to detect truncation (`afr keygen`, `afr verify`).
- `afr report`: seven controls (AFR-01 to AFR-07) re-performed from the log and mapped to NIST SP 800-53, SOC 2, ISO/IEC 42001 and the EU AI Act. Outputs a reviewer report, a CSV of calls, hashed evidence JSON and OSCAL 1.1.2 assessment results, reproducible with `SOURCE_DATE_EPOCH`. Supports `--fail-on` for CI gates.
- Tool definition drift: description and schema hashes recorded on every `tools/list`, with changes flagged.
- `afr demo`: a signed sample session, its evidence, and a tampered copy that verification rejects.
