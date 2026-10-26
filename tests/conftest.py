from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_flight_recorder.chain import Recorder, entry_hash, canonical
from agent_flight_recorder.policy import load
from agent_flight_recorder.proxy import Session

POLICY = """
agent: test-agent
on_behalf_of: dana@example.com
default: deny
record_arguments: redacted
rules:
  - id: reads
    tools: ["get_*"]
    decision: allow
  - id: protect-main
    tools: ["push_files"]
    when: {arg: branch, matches: "^main$"}
    decision: deny
    reason: Use a pull request.
  - id: pushes
    tools: ["push_files"]
    decision: allow
  - id: risky
    tools: ["delete_*", "merge_*"]
    decision: approve
"""


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / 'policy.yaml'
    p.write_text(POLICY, encoding='utf-8')
    return p


@pytest.fixture
def session(tmp_path: Path, policy_file: Path) -> Session:
    s = Session(load(policy_file), Recorder(tmp_path / 'flight.jsonl'), 'github')
    s.start(['fake-server'], None)
    return s


def call(s: Session, i, tool: str, **arguments):
    return s.from_client({'jsonrpc': '2.0', 'id': i, 'method': 'tools/call',
                          'params': {'name': tool, 'arguments': arguments}})


def ok(i):
    return {'jsonrpc': '2.0', 'id': i, 'result': {'content': [{'type': 'text', 'text': 'ok'}]}}


def rewrite(log: Path, edit) -> None:
    """Edit entries and rebuild a valid (unsigned) chain, as someone with write access but no key could."""
    entries = [json.loads(l) for l in log.read_text(encoding='utf-8').splitlines()]
    entries = edit(entries)
    prev = '0' * 64
    for i, e in enumerate(entries):
        e.pop('sig', None)
        e['seq'], e['prev'] = i, prev
        e['hash'] = entry_hash(e)
        prev = e['hash']
    log.write_text(''.join(canonical(e) + '\n' for e in entries), encoding='utf-8')
