"""Policy as code. Every tool call is matched against the rules in order; the first match decides
allow, deny or approve (a human must approve this exact call before it runs). No match falls
through to the default, which should be deny or approve for anything that can change state.

policy.yaml:

  agent: release-bot                 # recorded on every entry
  on_behalf_of: env:USER             # the human the agent acts for (literal, or env:VAR)
  default: approve
  record_arguments: redacted         # digest | redacted | full
  approval_ttl_minutes: 60
  rules:
    - id: read-only
      tools: ["get_*", "list_*", "search_*"]
      decision: allow
    - id: no-force-push
      tools: ["push_files"]
      when: {arg: branch, matches: "^(main|master)$"}
      decision: deny
      reason: Agents don't push to protected branches.
    - id: merges-need-a-human
      tools: ["merge_pull_request"]
      decision: approve
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DECISIONS = {'allow', 'deny', 'approve'}
ARG_MODES = {'digest', 'redacted', 'full'}


class PolicyError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    tools: list[str]
    decision: str
    server: str | None = None
    when_arg: str | None = None
    when_pattern: re.Pattern | None = None
    reason: str | None = None

    def matches(self, server: str, tool: str, args: dict) -> bool:
        if self.server and not fnmatch.fnmatchcase(server, self.server):
            return False
        if not any(fnmatch.fnmatchcase(tool, t) for t in self.tools):
            return False
        if self.when_arg is not None:
            value = args.get(self.when_arg) if isinstance(args, dict) else None
            return value is not None and bool(self.when_pattern.search(str(value)))
        return True


@dataclass
class Decision:
    decision: str
    rule: str
    reason: str | None = None


@dataclass
class Policy:
    agent: str
    on_behalf_of: str
    default: str
    rules: list[Rule] = field(default_factory=list)
    record_arguments: str = 'redacted'
    approval_ttl_minutes: int = 60
    source_sha256: str = ''
    raw: dict = field(default_factory=dict)

    def decide(self, server: str, tool: str, args: dict) -> Decision:
        for r in self.rules:
            if r.matches(server, tool, args):
                return Decision(r.decision, r.id, r.reason)
        return Decision(self.default, 'default', None)


def _resolve(value: str) -> str:
    if isinstance(value, str) and value.startswith('env:'):
        return os.environ.get(value[4:], '') or f'unknown ({value[4:]} not set)'
    return str(value)


def load(path: Path) -> Policy:
    try:
        text = path.read_text(encoding='utf-8')
        data = yaml.safe_load(text)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PolicyError(f'{path}: not valid YAML: {exc}') from None
    if not isinstance(data, dict):
        raise PolicyError(f'{path}: expected a mapping')
    for key in ('agent', 'on_behalf_of', 'default'):
        if not data.get(key):
            raise PolicyError(f'{path}: "{key}" is required')
    if data['default'] not in DECISIONS:
        raise PolicyError(f'{path}: default must be one of {", ".join(sorted(DECISIONS))}')
    mode = data.get('record_arguments', 'redacted')
    if mode not in ARG_MODES:
        raise PolicyError(f'{path}: record_arguments must be one of {", ".join(sorted(ARG_MODES))}')
    if not isinstance(data.get('rules') or [], list):
        raise PolicyError(f'{path}: rules must be a list')
    rules, seen = [], set()
    for i, r in enumerate(data.get('rules') or [], 1):
        if not isinstance(r, dict) or not isinstance(r.get('id'), (str, int)) or not r.get('tools')                 or r.get('decision') not in DECISIONS:
            raise PolicyError(f'{path}: rule {i} needs an id, a tools list and a decision (allow, deny or approve)')
        if r['id'] in seen:
            raise PolicyError(f'{path}: rule id {r["id"]} is used twice')
        seen.add(r['id'])
        when = r.get('when') or {}
        pattern = None
        if when:
            if not isinstance(when, dict) or 'arg' not in when or 'matches' not in when:
                raise PolicyError(f'{path}: rule {r["id"]}: "when" needs arg and matches')
            try:
                pattern = re.compile(str(when['matches']))
            except re.error as exc:
                raise PolicyError(f'{path}: rule {r["id"]}: bad regex: {exc}') from None
        tools = r['tools'] if isinstance(r['tools'], list) else [r['tools']]
        rules.append(Rule(str(r['id']), [str(t) for t in tools], r['decision'],
                          str(r['server']) if r.get('server') else None,
                          str(when['arg']) if when else None, pattern, r.get('reason')))
    try:
        ttl = int(data.get('approval_ttl_minutes', 60))
    except (TypeError, ValueError):
        raise PolicyError(f'{path}: approval_ttl_minutes must be a number') from None
    return Policy(str(data['agent']), _resolve(data['on_behalf_of']), data['default'], rules, mode, ttl,
                  hashlib.sha256(text.encode('utf-8')).hexdigest(), data)
