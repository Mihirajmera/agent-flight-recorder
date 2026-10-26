from __future__ import annotations

import json
import threading

from agent_flight_recorder.chain import Recorder, Signer, generate_key, read, verify


def write(log, n=5, signer=None):
    r = Recorder(log, signer)
    for i in range(n):
        r.append('note', i=i)
    return r


def test_intact_chain_verifies(tmp_path):
    log = tmp_path / 'f.jsonl'
    write(log)
    res = verify(log)
    assert res['ok'] and res['chain_intact'] and res['entries'] == 5


def test_edited_entry_is_detected(tmp_path):
    log = tmp_path / 'f.jsonl'
    write(log)
    lines = log.read_text().splitlines()
    lines[2] = lines[2].replace('"i":2', '"i":7')
    log.write_text('\n'.join(lines) + '\n')
    res = verify(log)
    assert not res['chain_intact'] and 'entry 2: content does not match its hash' in res['problems'][0]


def test_deleted_and_reordered_entries_are_detected(tmp_path):
    log = tmp_path / 'f.jsonl'
    write(log)
    lines = log.read_text().splitlines()
    log.write_text('\n'.join(lines[:2] + lines[3:]) + '\n')
    assert not verify(log)['chain_intact']
    log.write_text('\n'.join([lines[1], lines[0]] + lines[2:]) + '\n')
    assert not verify(log)['chain_intact']


def test_truncation_needs_an_anchor(tmp_path):
    log = tmp_path / 'f.jsonl'
    write(log)
    anchor = verify(log)['head']
    lines = log.read_text().splitlines()
    log.write_text('\n'.join(lines[:3]) + '\n')
    assert verify(log)['chain_intact']                       # a shorter log is still a valid chain
    res = verify(log, anchor=anchor)
    assert not res['ok'] and res['anchor_matched'] is False


def test_signatures(tmp_path):
    priv, pub = generate_key(tmp_path / 'k')
    other_priv, other_pub = generate_key(tmp_path / 'other')
    log = tmp_path / 'f.jsonl'
    write(log, signer=Signer(priv))
    assert verify(log, pub)['ok']
    res = verify(log, other_pub)
    assert res['bad_signatures'] == 5 and not res['ok']


def test_rebuilt_chain_without_the_key_fails_signature_check(tmp_path):
    priv, pub = generate_key(tmp_path / 'k')
    log = tmp_path / 'f.jsonl'
    write(log, signer=Signer(priv))
    write(tmp_path / 'forged.jsonl')                          # attacker writes a fresh, valid but unsigned chain
    res = verify(tmp_path / 'forged.jsonl', pub)
    assert res['chain_intact'] and not res['ok'] and 'not signed' in res['problems'][0]


def test_keygen_never_overwrites(tmp_path):
    generate_key(tmp_path / 'k')
    import pytest
    with pytest.raises(FileExistsError):
        generate_key(tmp_path / 'k')


def test_concurrent_writers_keep_one_chain(tmp_path):
    log = tmp_path / 'f.jsonl'
    threads = [threading.Thread(target=write, args=(log, 20)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    res = verify(log)
    assert res['ok'] and res['entries'] == 80


def test_unparseable_line_is_reported(tmp_path):
    log = tmp_path / 'f.jsonl'
    write(log, 2)
    with log.open('a') as fh:
        fh.write('not json\n')
    res = verify(log)
    assert not res['chain_intact'] and any('not valid JSON' in p for p in res['problems'])
    assert len(read(log)) == 3
