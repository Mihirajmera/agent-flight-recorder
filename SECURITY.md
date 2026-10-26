# Security policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Report them privately through GitHub's private vulnerability reporting:

**https://github.com/Mihirajmera/agent-flight-recorder/security/advisories/new**

What to expect:

- **Acknowledgement within 5 business days.**
- **An assessment within 14 days**: whether it's accepted as a vulnerability, its severity, and a planned fix.
- **Coordinated disclosure**: a fix is released and the advisory published together, normally within 90 days of the report. You'll be credited in the advisory unless you'd rather not be.

Useful things to include: the version or commit, the log, policy or message sequence that triggers the problem (with real secrets removed), and what you expected to happen.

## Scope

This tool is a security control: it decides whether an agent's tool call runs, and it produces evidence that auditors rely on. Especially relevant reports:

- A tool call that reaches the MCP server although the policy denies it, or requires an approval that wasn't given. This includes tricks with batching, unusual JSON-RPC IDs or argument encodings.
- An approval that can be reused, used after it expires, or used for a different call.
- A change to a signed log (edit, deletion, reordering or insertion) that `afr verify` or `afr report` doesn't detect. Cutting off the most recent entries when no anchor is given is a documented limit, not a vulnerability.
- A secret in tool arguments that survives `redacted` mode into the log or report.
- A crafted log or policy that causes code execution, writes outside the `--out` folder, or hangs the verifier.

A check that should fire but doesn't is a normal bug: please open an issue.

## Design notes

- The proxy fails closed: if a call can't be written to the log, it's blocked.
- Policies are loaded with `yaml.safe_load`; logs are parsed as JSON lines and never executed.
- Result bodies are never stored, only their SHA-256.
- Private keys are created with mode 0600 and never overwritten.
- The tool makes no network calls of its own.
- Dependencies are pinned by hash, GitHub Actions are pinned to commit SHAs, and CodeQL, OpenSSF Scorecard and ClusterFuzzLite run in CI.
