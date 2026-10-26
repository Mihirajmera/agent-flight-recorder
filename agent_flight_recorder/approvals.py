"""Human approval for individual tool calls.

When policy says "approve", the proxy refuses the call and records a pending request. A person
runs `afr approve <id>`; the approval is written to the flight log (who, when, until when) and
to a small state file next to it. When the agent retries the identical call, the proxy consumes
the approval exactly once and records which approval entry authorised it.

An approval is bound to the exact server, tool and arguments: approving "merge PR 41" does not
approve "merge PR 42".
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from .chain import Recorder, digest, file_lock, now


def request_key(server: str, tool: str, args) -> str:
    return digest({'server': server, 'tool': tool, 'args': args})


def store_path(log: Path) -> Path:
    return log.with_name(log.name + '.approvals.json')


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding='utf-8') or '{}')


def _save(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    tmp.replace(path)


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace('Z', '+00:00'))


def request(log: Path, key: str, server: str, tool: str, args_view, agent: str, on_behalf_of: str) -> tuple[str, bool]:
    """Record a pending request. Returns (request_id, created) so a retry doesn't log twice."""
    path = store_path(log)
    with file_lock(path):
        data = _load(path)
        same = [rid for rid, r in data.items() if r['request_key'] == key]
        for rid in same:
            if data[rid]['status'] == 'pending':
                return rid, False
        rid = f'{key[:8]}-{len(same) + 1}'        # one id per request, so history is never overwritten
        data[rid] = {'request_key': key, 'server': server, 'tool': tool, 'arguments': args_view, 'agent': agent,
                     'on_behalf_of': on_behalf_of, 'requested_at': now(), 'status': 'pending'}
        _save(path, data)
    return rid, True


def decide(log: Path, recorder: Recorder, rid: str, approver: str, approve: bool, ttl_minutes: int,
           note: str | None = None) -> dict:
    """Approve or reject a pending request, recording the decision in the flight log."""
    path = store_path(log)
    with file_lock(path):
        data = _load(path)
        req = data.get(rid)
        if not req:
            raise KeyError(f'no request {rid}')
        if req['status'] != 'pending':
            raise ValueError(f'request {rid} is already {req["status"]}')
        decided = now()
        expires = (_parse(decided) + timedelta(minutes=ttl_minutes)).isoformat(timespec='milliseconds') \
            .replace('+00:00', 'Z') if approve else None
        entry = recorder.append('approval', request_id=rid, request_key=req['request_key'], server=req['server'],
                                tool=req['tool'], agent=req['agent'], on_behalf_of=req['on_behalf_of'],
                                decision='approved' if approve else 'rejected', approver=approver,
                                expires=expires, note=note)
        req.update(status='approved' if approve else 'rejected', approver=approver, decided_at=decided,
                   expires=expires, approval_entry=f'{entry["seq"]}:{entry["hash"]}')
        _save(path, data)
    return req


def consume(log: Path, key: str) -> dict | None:
    """Use an approval for this exact call, once. None if there is no valid, unused approval."""
    path = store_path(log)
    with file_lock(path):
        data = _load(path)
        current = now()
        found = None
        for rid, req in data.items():
            if req['request_key'] != key or req['status'] != 'approved':
                continue
            if _parse(req['expires']) < _parse(current):
                req['status'] = 'expired'
                continue
            req.update(status='used', used_at=current)
            found = {'request_id': rid, **req}
            break
        _save(path, data)
    return found


def pending(log: Path) -> dict:
    return {rid: r for rid, r in _load(store_path(log)).items() if r['status'] == 'pending'}
