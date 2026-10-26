"""MCP stdio proxy. It sits between an agent (the MCP client) and one MCP server:

  agent  <-- stdio -->  afr proxy  <-- stdio -->  MCP server

Every `tools/call` is checked against the policy before the server sees it. Allowed calls are
forwarded and recorded with their result; denied calls and calls waiting for approval are
answered by the proxy and never reach the server. `tools/list` responses are recorded as a hash
of each tool's description and schema, so a server that changes what a tool claims to do
between sessions shows up in the report. Everything else passes through untouched.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__, approvals
from .chain import Recorder, digest
from .policy import Policy

SECRET_KEY = re.compile(r'(^|_|-)(api_?key|key|secret|token|password|passwd|credentials?|authorization|cookie|'
                        r'private_key|access_key|session)$', re.I)
MAX_STRING = 500


def redact(obj):
    """Argument view for the log: secret-looking fields removed, long strings truncated."""
    if isinstance(obj, dict):
        return {k: ('[REDACTED]' if SECRET_KEY.search(str(k)) and not isinstance(v, (dict, list)) else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str) and len(obj) > MAX_STRING:
        return obj[:MAX_STRING] + f'… [{len(obj) - MAX_STRING} more characters]'
    return obj


def arguments_view(args, mode: str):
    if mode == 'full':
        return args
    if mode == 'redacted':
        return redact(args)
    return None


def blocked_result(msg_id, text: str) -> dict:
    """A tool result the agent can read and relay, rather than a protocol error."""
    return {'jsonrpc': '2.0', 'id': msg_id, 'result': {'content': [{'type': 'text', 'text': text}], 'isError': True}}


@dataclass
class Session:
    policy: Policy
    recorder: Recorder
    server: str
    calls: dict = field(default_factory=dict)        # json(id) -> (entry seq, start time, tool)
    list_requests: set = field(default_factory=set)  # json(id) of pending tools/list requests
    stats: dict = field(default_factory=lambda: {'allowed': 0, 'denied': 0, 'approval_required': 0, 'approved': 0})

    def start(self, command: list[str], key_id: str | None) -> dict:
        p = self.policy
        return self.recorder.append(
            'session-start', recorder=f'agent-flight-recorder {__version__}', agent=p.agent,
            on_behalf_of=p.on_behalf_of, server=self.server, server_command=command[:1],
            server_command_sha256=digest(command), policy_sha256=p.source_sha256,
            policy={'default': p.default, 'rules': [{'id': r.id, 'decision': r.decision} for r in p.rules]},
            key_id=key_id)

    def end(self, exit_code: int | None) -> dict:
        return self.recorder.append('session-end', agent=self.policy.agent, server=self.server,
                                    exit_code=exit_code, **self.stats,
                                    unanswered_calls=len(self.calls))

    # ------------------------------------------------------------------ client -> server

    def from_client(self, msg) -> tuple[list, list]:
        """Returns (messages to forward to the server, replies to send back to the client)."""
        if isinstance(msg, list):                    # JSON-RPC batch: decide each call on its own
            forward, replies = [], []
            for item in msg:
                f, r = self.from_client(item)
                forward += f
                replies += r
            return forward, replies
        if not isinstance(msg, dict):
            return [msg], []
        method = msg.get('method')
        if method == 'tools/list' and 'id' in msg:
            self.list_requests.add(json.dumps(msg['id']))
        if method != 'tools/call':
            return [msg], []
        return self._call(msg)

    def _call(self, msg: dict) -> tuple[list, list]:
        p = self.policy
        params = msg.get('params') if isinstance(msg.get('params'), dict) else {}
        tool = str(params.get('name', ''))
        args = params.get('arguments') if isinstance(params.get('arguments'), dict) else {}
        key = approvals.request_key(self.server, tool, args)
        decision = p.decide(self.server, tool, args)
        base = dict(call_id=msg.get('id'), agent=p.agent, on_behalf_of=p.on_behalf_of, server=self.server, tool=tool,
                    rule=decision.rule, args_sha256=digest(args), arguments=arguments_view(args, p.record_arguments),
                    request_key=key)

        if decision.decision == 'deny':
            self.stats['denied'] += 1
            self.recorder.append('tool-call', decision='deny', reason=decision.reason, **base)
            text = f'Blocked by policy rule "{decision.rule}".' + (f' {decision.reason}' if decision.reason else '')
            return [], ([blocked_result(msg['id'], text)] if 'id' in msg else [])

        approval = None
        if decision.decision == 'approve':
            approval = approvals.consume(self.recorder.log, key)
            if approval is None:
                self.stats['approval_required'] += 1
                rid, _ = approvals.request(self.recorder.log, key, self.server, tool, base['arguments'],
                                           p.agent, p.on_behalf_of)
                self.recorder.append('tool-call', decision='approval-required', request_id=rid, **base)
                text = (f'This call needs human approval (policy rule "{decision.rule}"). '
                        f'Ask a reviewer to run: afr approve {rid} --log {self.recorder.log}  '
                        f'Then retry the same call.')
                return [], ([blocked_result(msg['id'], text)] if 'id' in msg else [])
            self.stats['approved'] += 1
        else:
            self.stats['allowed'] += 1

        entry = self.recorder.append(
            'tool-call', decision='approved' if approval else 'allow',
            approval={'request_id': approval['request_id'], 'approver': approval['approver'],
                      'approval_entry': approval['approval_entry']} if approval else None, **base)
        if 'id' in msg:
            self.calls[json.dumps(msg['id'])] = (entry['seq'], time.monotonic(), tool)
        return [msg], []

    # ------------------------------------------------------------------ server -> client

    def from_server(self, msg) -> None:
        if isinstance(msg, list):
            for item in msg:
                self.from_server(item)
            return
        if not isinstance(msg, dict) or 'id' not in msg or 'method' in msg:
            return
        mid = json.dumps(msg['id'])
        if mid in self.list_requests:
            self.list_requests.discard(mid)
            tools = (msg.get('result') or {}).get('tools') if isinstance(msg.get('result'), dict) else None
            if isinstance(tools, list):
                self.recorder.append('tools-listed', agent=self.policy.agent, server=self.server, tools=[
                    {'name': str(t.get('name')), 'description_sha256': digest(t.get('description')),
                     'schema_sha256': digest(t.get('inputSchema'))} for t in tools if isinstance(t, dict)])
            return
        call = self.calls.pop(mid, None)
        if call is None:
            return
        seq, started, tool = call
        result = msg.get('result') if isinstance(msg.get('result'), dict) else None
        error = msg.get('error') if isinstance(msg.get('error'), dict) else None
        self.recorder.append('tool-result', call_id=msg['id'], call_entry=seq, server=self.server, tool=tool,
                             is_error=bool(error) or bool(result and result.get('isError')),
                             error_code=error.get('code') if error else None,
                             result_sha256=digest(result if result is not None else error),
                             duration_ms=round((time.monotonic() - started) * 1000))


# --------------------------------------------------------------------------- stdio plumbing

def _fail_closed(msg) -> tuple[list, list]:
    items = msg if isinstance(msg, list) else [msg]
    forward = [m for m in items if not (isinstance(m, dict) and m.get('method') == 'tools/call')]
    replies = [blocked_result(m['id'], 'Blocked: the flight recorder could not write its log, so the call was '
                              'not run.') for m in items
               if isinstance(m, dict) and m.get('method') == 'tools/call' and 'id' in m]
    return forward, replies


def _parse(line: bytes):
    try:
        return json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def run(session: Session, command: list[str], key_id: str | None, stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    exe = shutil.which(command[0]) or command[0]
    proc = subprocess.Popen([exe, *command[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    session.start(command, key_id)
    out_lock = threading.Lock()

    def send_client(obj_or_line) -> None:
        data = obj_or_line if isinstance(obj_or_line, bytes) else (json.dumps(obj_or_line) + '\n').encode('utf-8')
        with out_lock:
            stdout.write(data)
            stdout.flush()

    def pump_server() -> None:
        for line in iter(proc.stdout.readline, b''):
            msg = _parse(line)
            if msg is not None:
                try:
                    session.from_server(msg)
                except Exception as exc:             # never drop traffic because recording failed
                    print(f'afr: could not record server message: {exc}', file=sys.stderr)
            send_client(line if line.endswith(b'\n') else line + b'\n')

    reader = threading.Thread(target=pump_server, daemon=True)
    reader.start()
    try:
        for line in iter(stdin.readline, b''):
            msg = _parse(line)
            if msg is None:
                forward, replies = [line], []
            else:
                try:
                    forward, replies = session.from_client(msg)
                except Exception as exc:                 # fail closed: an unrecorded call doesn't run
                    print(f'afr: could not record, blocking: {exc}', file=sys.stderr)
                    forward, replies = _fail_closed(msg)
                # Pass the original bytes through when nothing was held back.
                if len(forward) == 1 and forward[0] is msg:
                    forward = [line]
            for item in forward:
                data = item if isinstance(item, bytes) else (json.dumps(item) + '\n').encode('utf-8')
                proc.stdin.write(data if data.endswith(b'\n') else data + b'\n')
                proc.stdin.flush()
            for reply in replies:
                send_client(reply)
    except (BrokenPipeError, OSError):
        pass
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.terminate()
            code = proc.wait()
        reader.join(timeout=5)
        session.end(code)
    return code or 0


def default_log(policy: Policy) -> Path:
    return Path('.afr') / f'{re.sub(r"[^A-Za-z0-9_.-]+", "-", policy.agent)}.jsonl'
