from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agent_flight_recorder import approvals
from agent_flight_recorder.__main__ import main
from agent_flight_recorder.chain import read, verify
from agent_flight_recorder.report import assess
from conftest import call, ok, rewrite

REPO = Path(__file__).resolve().parent.parent
FAKE = Path(__file__).resolve().parent / 'fake_server.py'


def findings(log, pubkey=None):
    res = assess(read(log), verify(log, pubkey))
    return {cid: [f.message for f in fs] for cid, fs in res.items() if fs}


def approved_session(session):
    log = session.recorder.log
    call(session, 1, 'delete_repo', repo='api')
    [rid] = approvals.pending(log)
    approvals.decide(log, session.recorder, rid, 'priya@example.com', True, 60)
    call(session, 2, 'delete_repo', repo='api')
    session.from_server(ok(2))
    return log


def test_clean_session_only_notes_missing_signature_and_anchor(session):
    log = approved_session(session)
    f = findings(log)
    assert set(f) == {'AFR-01'} and any('not signed' in m for m in f['AFR-01'])


def test_forged_approval_reference_is_caught(session):
    log = approved_session(session)

    def forge(entries):                       # point the approved call at an approval that doesn't exist
        for e in entries:
            if e['type'] == 'tool-call' and e.get('decision') == 'approved':
                e['approval']['approval_entry'] = '99:' + '0' * 64
        return entries
    rewrite(log, forge)
    assert any('not an earlier approval entry' in m for m in findings(log)['AFR-03'])


def test_approval_reused_for_a_different_call_is_caught(session):
    log = approved_session(session)

    def swap(entries):                        # claim the approval for a different repository
        for e in entries:
            if e['type'] == 'tool-call' and e.get('decision') == 'approved':
                e['request_key'] = approvals.request_key('github', 'delete_repo', {'repo': 'prod'})
        return entries
    rewrite(log, swap)
    assert any('approved a different call' in m for m in findings(log)['AFR-03'])


def test_decision_that_contradicts_policy_is_caught(session):
    call(session, 1, 'push_files', branch='main')
    log = session.recorder.log

    def allow(entries):
        entries[-1]['decision'] = 'allow'
        return entries
    rewrite(log, allow)
    assert any('rule protect-main says "deny"' in m for m in findings(log)['AFR-05'])


def test_blocked_call_with_a_result_is_caught(session):
    call(session, 1, 'push_files', branch='main')
    log = session.recorder.log
    seq = read(log)[-1]['seq']
    session.recorder.append('tool-result', call_id=1, call_entry=seq, tool='push_files', is_error=False)
    assert any('reached the server' in m for m in findings(log)['AFR-05'])


def test_self_approval_and_tool_change(session):
    log = session.recorder.log
    call(session, 1, 'merge_pr', pr=1)
    [rid] = approvals.pending(log)
    approvals.decide(log, session.recorder, rid, 'Dana@Example.com', True, 60)
    for i, desc in ((2, 'Merge'), (3, 'Merge without review')):
        session.from_client({'jsonrpc': '2.0', 'id': f'L{i}', 'method': 'tools/list'})
        session.from_server({'jsonrpc': '2.0', 'id': f'L{i}', 'result': {'tools': [{'name': 'merge_pr', 'description': desc}]}})
    f = findings(log)
    assert 'AFR-04' in f and any('changed its description' in m for m in f['AFR-06'])


def test_forwarded_call_without_result(session):
    call(session, 1, 'get_issue')
    assert 'AFR-07' in findings(session.recorder.log)


def test_demo_outputs(tmp_path, monkeypatch):
    monkeypatch.setenv('SOURCE_DATE_EPOCH', '1791763200')
    out = tmp_path / 'demo'
    assert main(['demo', '--out', str(out)]) == 0
    ev = json.loads((out / 'evidence' / 'evidence.json').read_text(encoding='utf-8'))
    assert ev['verification']['ok'] is True and ev['verification']['signed_entries'] == ev['log']['entries']
    status = {r['check_id']: r['status'] for r in ev['results']}
    assert status['AFR-04'] == 'FAIL' and status['AFR-06'] == 'FAIL' and status['AFR-03'] == 'PASS'
    assert not verify(out / 'flight-tampered.jsonl', out / 'demo-signing.pub')['chain_intact']


def test_demo_is_reproducible(tmp_path, monkeypatch):
    monkeypatch.setenv('SOURCE_DATE_EPOCH', '1791763200')
    a, b = tmp_path / 'a', tmp_path / 'b'
    main(['demo', '--out', str(a)])
    main(['demo', '--out', str(b)])
    for p in a.rglob('*'):
        if p.is_file():
            assert p.read_bytes() == (b / p.relative_to(a)).read_bytes(), p


def afr(*args, input_=None, cwd=None):
    return subprocess.run([sys.executable, '-m', 'agent_flight_recorder', *args], input=input_, capture_output=True,
                          cwd=cwd or REPO, env={**__import__('os').environ, 'PYTHONPATH': str(REPO)})


def lines(*msgs) -> bytes:
    return b''.join(json.dumps(m).encode() + b'\n' for m in msgs)


def test_end_to_end_through_a_real_server_process(tmp_path, policy_file):
    log, seen = tmp_path / 'flight.jsonl', tmp_path / 'seen.txt'
    afr('keygen', '--out', str(tmp_path / 'k'))
    msgs = lines(
        {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'get_issue', 'arguments': {'n': 1}}},
        {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'delete_repo', 'arguments': {'repo': 'api'}}},
    )
    proc = afr('proxy', '--policy', str(policy_file), '--log', str(log), '--key', str(tmp_path / 'k.key'),
               '--server-name', 'fake', '--', sys.executable, str(FAKE), str(seen), input_=msgs)
    assert proc.returncode == 0, proc.stderr
    replies = {r['id']: r for r in map(json.loads, proc.stdout.decode().splitlines())}
    assert replies[2]['result']['content'][0]['text'] == 'did get_issue'
    assert replies[3]['result']['isError']
    assert seen.read_text().split() == ['get_issue']                    # the delete never reached the server

    rid = afr('pending', '--log', str(log)).stdout.decode().split()[0]
    assert afr('approve', rid, '--approver', 'priya@example.com', '--log', str(log),
               '--key', str(tmp_path / 'k.key')).returncode == 0
    proc = afr('proxy', '--policy', str(policy_file), '--log', str(log), '--key', str(tmp_path / 'k.key'),
               '--server-name', 'fake', '--', sys.executable, str(FAKE), str(seen), input_=lines(
                   {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call',
                    'params': {'name': 'delete_repo', 'arguments': {'repo': 'api'}}}))
    assert json.loads(proc.stdout)['result']['content'][0]['text'] == 'did delete_repo'
    assert seen.read_text().split() == ['get_issue', 'delete_repo']

    v = afr('verify', '--log', str(log), '--pubkey', str(tmp_path / 'k.pub'))
    assert v.returncode == 0, v.stdout
    head = v.stdout.decode().split('Head: ')[1].split()[0]
    r = afr('report', '--log', str(log), '--pubkey', str(tmp_path / 'k.pub'), '--anchor', head,
            '--out', str(tmp_path / 'ev'), '--fail-on', 'medium')
    assert r.returncode == 0, r.stdout
    assert (tmp_path / 'ev' / 'oscal' / 'assessment-results.json').exists()


def test_malformed_log_is_reported_not_crashed(tmp_path):
    log = tmp_path / 'flight.jsonl'
    log.write_bytes(b'\xff\xfe not utf-8\n[1, 2]\n{"seq": 0, "type": "tool-call", "decision": null, "tool": ["x"],'
                    b' "approval": [], "time": "yesterday"}\n{"type": "approval"}\n')
    entries, v = read(log), verify(log)
    paths = __import__('agent_flight_recorder.report', fromlist=['write_all']).write_all(entries, v, assess(entries, v),
                                                                                        tmp_path / 'ev')
    assert not v['chain_intact'] and paths['report'].exists()


def test_malformed_policy_raises_policy_error(tmp_path):
    from agent_flight_recorder.policy import PolicyError, load
    import pytest
    for body in (b'\xff\xfe', b'agent: [unclosed', b'agent: a\non_behalf_of: b\ndefault: deny\nrules: 5\n',
                 b'agent: a\non_behalf_of: b\ndefault: deny\nrules:\n  - {id: [x], tools: [a], decision: allow}\n'):
        (tmp_path / 'p.yaml').write_bytes(body)
        with pytest.raises(PolicyError):
            load(tmp_path / 'p.yaml')
