from __future__ import annotations

import json

import pytest

from agent_flight_recorder import approvals
from agent_flight_recorder.chain import read
from agent_flight_recorder.policy import PolicyError, load
from conftest import call, ok


def test_first_matching_rule_decides(policy_file):
    p = load(policy_file)
    assert p.decide('github', 'get_issue', {}).decision == 'allow'
    assert p.decide('github', 'push_files', {'branch': 'main'}).rule == 'protect-main'
    assert p.decide('github', 'push_files', {'branch': 'feature'}).rule == 'pushes'
    assert p.decide('github', 'create_repo', {}).rule == 'default'


@pytest.mark.parametrize('body,error', [
    ('agent: a\non_behalf_of: b\n', 'default'),
    ('agent: a\non_behalf_of: b\ndefault: maybe\n', 'default must be'),
    ('agent: a\non_behalf_of: b\ndefault: deny\nrules:\n  - {id: x, tools: [a], decision: yes}\n', 'rule 1'),
    ('agent: a\non_behalf_of: b\ndefault: deny\nrules:\n  - {id: x, tools: [a], decision: allow}\n'
     '  - {id: x, tools: [b], decision: allow}\n', 'used twice'),
    ('agent: a\non_behalf_of: b\ndefault: deny\nrules:\n  - {id: x, tools: [a], decision: allow, '
     'when: {arg: p, matches: "("}}\n', 'bad regex'),
    ('agent: a\non_behalf_of: b\ndefault: deny\nrecord_arguments: everything\n', 'record_arguments'),
])
def test_invalid_policies_are_rejected(tmp_path, body, error):
    p = tmp_path / 'p.yaml'
    p.write_text(body, encoding='utf-8')
    with pytest.raises(PolicyError, match=error):
        load(p)


def test_on_behalf_of_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv('AFR_TEST_USER', 'sam@example.com')
    p = tmp_path / 'p.yaml'
    p.write_text('agent: a\non_behalf_of: env:AFR_TEST_USER\ndefault: deny\n', encoding='utf-8')
    assert load(p).on_behalf_of == 'sam@example.com'


def test_allowed_call_is_forwarded_and_recorded_with_its_result(session):
    fwd, replies = call(session, 1, 'get_issue', number=3)
    assert len(fwd) == 1 and not replies
    session.from_server(ok(1))
    entries = read(session.recorder.log)
    assert [e['type'] for e in entries] == ['session-start', 'tool-call', 'tool-result']
    assert entries[2]['call_entry'] == entries[1]['seq'] and entries[2]['is_error'] is False


def test_denied_call_never_reaches_the_server(session):
    fwd, replies = call(session, 1, 'push_files', branch='main')
    assert fwd == []
    assert replies[0]['result']['isError'] and 'Use a pull request.' in replies[0]['result']['content'][0]['text']
    assert read(session.recorder.log)[-1]['decision'] == 'deny'


def test_approval_is_bound_to_the_exact_call_and_single_use(session):
    log = session.recorder.log
    fwd, replies = call(session, 1, 'delete_repo', repo='api')
    assert fwd == [] and 'afr approve' in replies[0]['result']['content'][0]['text']
    [rid] = approvals.pending(log)
    approvals.decide(log, session.recorder, rid, 'priya@example.com', True, 60)

    assert call(session, 2, 'delete_repo', repo='web')[0] == []        # different arguments: not approved
    fwd, _ = call(session, 3, 'delete_repo', repo='api')
    assert len(fwd) == 1                                                 # approved call goes through
    assert call(session, 4, 'delete_repo', repo='api')[0] == []         # and only once
    entry = [e for e in read(log) if e.get('call_id') == 3][0]
    assert entry['decision'] == 'approved' and entry['approval']['approver'] == 'priya@example.com'


def test_rejected_request_does_not_authorise(session):
    log = session.recorder.log
    call(session, 1, 'merge_pr', pr=1)
    [rid] = approvals.pending(log)
    approvals.decide(log, session.recorder, rid, 'priya@example.com', False, 60, 'not yet')
    assert call(session, 2, 'merge_pr', pr=1)[0] == []
    with pytest.raises(ValueError, match='already rejected'):
        approvals.decide(log, session.recorder, rid, 'priya@example.com', True, 60)


def test_expired_approval_does_not_authorise(session, monkeypatch):
    log = session.recorder.log
    monkeypatch.setenv('SOURCE_DATE_EPOCH', '1791763200')
    call(session, 1, 'merge_pr', pr=1)
    [rid] = approvals.pending(log)
    approvals.decide(log, session.recorder, rid, 'priya@example.com', True, 30)
    monkeypatch.setenv('SOURCE_DATE_EPOCH', str(1791763200 + 31 * 60))
    assert call(session, 2, 'merge_pr', pr=1)[0] == []
    state = json.loads(approvals.store_path(log).read_text())
    assert state[rid]['status'] == 'expired'


def test_secret_arguments_are_redacted_and_hashed(session):
    call(session, 1, 'get_issue', number=3, api_token='abc123', body='x' * 2000)
    e = read(session.recorder.log)[-1]
    assert e['arguments']['api_token'] == '[REDACTED]' and 'abc123' not in session.recorder.log.read_text()
    assert len(e['arguments']['body']) < 600 and len(e['args_sha256']) == 64


def test_tools_list_is_recorded_as_hashes(session):
    session.from_client({'jsonrpc': '2.0', 'id': 'L', 'method': 'tools/list'})
    session.from_server({'jsonrpc': '2.0', 'id': 'L', 'result': {'tools': [{'name': 't', 'description': 'd'}]}})
    e = read(session.recorder.log)[-1]
    assert e['type'] == 'tools-listed' and e['tools'][0]['name'] == 't' and len(e['tools'][0]['description_sha256']) == 64


def test_batch_calls_are_decided_individually(session):
    fwd, replies = session.from_client([
        {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'get_issue', 'arguments': {}}},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'push_files', 'arguments': {'branch': 'main'}}},
        {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
    ])
    assert [m.get('id') for m in fwd] == [1, None] and [r['id'] for r in replies] == [2]


def test_other_messages_pass_through_untouched(session):
    msg = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}
    assert session.from_client(msg) == ([msg], [])
    assert len(read(session.recorder.log)) == 1
