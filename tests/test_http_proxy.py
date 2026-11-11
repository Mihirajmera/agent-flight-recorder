"""The Streamable HTTP proxy, end to end: a fake remote MCP server, the proxy on a free local
port, and plain HTTP requests as the agent."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_flight_recorder.chain import Recorder, read, verify
from agent_flight_recorder.http_proxy import HttpProxy, public_url, serve
from agent_flight_recorder.policy import load
from agent_flight_recorder.proxy import Session

TOKEN = 'Bearer sk-live-do-not-log-me'


class Upstream(BaseHTTPRequestHandler):
    """Answers tools/list and tools/call. `get_stream` replies as SSE; everything else as JSON."""
    protocol_version = 'HTTP/1.1'
    seen: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        Upstream.seen.append((self.path, dict(self.headers), body))
        items = body if isinstance(body, list) else [body]
        answers = []
        for m in items:
            if 'id' not in m:
                continue
            if m['method'] == 'tools/list':
                answers.append({'jsonrpc': '2.0', 'id': m['id'], 'result': {'tools': [
                    {'name': 'get_issue', 'description': 'Read an issue', 'inputSchema': {}}]}})
            else:
                answers.append({'jsonrpc': '2.0', 'id': m['id'],
                                'result': {'content': [{'type': 'text', 'text': 'ok'}]}})
        if not answers:
            self.send_response(202)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if items[0].get('params', {}).get('name') == 'get_stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Mcp-Session-Id', 'abc123')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(b': keep-alive\n\n')
            for a in answers:
                self.wfile.write(b'event: message\ndata: ' + json.dumps(a).encode() + b'\n\n')
            self.close_connection = True
            return
        data = json.dumps(answers if isinstance(body, list) else answers[0]).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Mcp-Session-Id', 'abc123')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def proxy_url(tmp_path, policy_file):
    Upstream.seen = []
    up = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    upstream = f'http://127.0.0.1:{up.server_address[1]}/mcp?api_key=secret-in-url'
    proxy = HttpProxy(Session(load(policy_file), Recorder(tmp_path / 'flight.jsonl'), 'github'), upstream)
    bound = threading.Event()
    holder = {}

    def ready(server):
        holder['server'] = server
        bound.set()

    t = threading.Thread(target=serve, args=(proxy, '127.0.0.1', 0, None, ready), daemon=True)
    t.start()
    bound.wait(5)
    server = holder['server']
    yield f'http://127.0.0.1:{server.server_address[1]}/mcp'
    server.shutdown()
    t.join(5)
    up.shutdown()


def post(url, msg, **headers):
    req = urllib.request.Request(url, data=json.dumps(msg).encode(), method='POST', headers={
        'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
        'Authorization': TOKEN, **headers})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, dict(r.headers), r.read().decode()


def call(i, tool, **arguments):
    return {'jsonrpc': '2.0', 'id': i, 'method': 'tools/call', 'params': {'name': tool, 'arguments': arguments}}


def test_allowed_call_is_forwarded_with_its_headers_and_recorded(proxy_url, tmp_path):
    status, headers, body = post(proxy_url, call(1, 'get_issue', number=3), **{'Mcp-Session-Id': 'abc123'})
    assert status == 200 and json.loads(body)['result']['content'][0]['text'] == 'ok'
    assert headers['Mcp-Session-Id'] == 'abc123'
    path, sent, _ = Upstream.seen[0]
    assert path == '/mcp?api_key=secret-in-url'
    assert sent['Authorization'] == TOKEN and sent['Mcp-Session-Id'] == 'abc123'
    entries = read(tmp_path / 'flight.jsonl')
    assert [e['type'] for e in entries] == ['session-start', 'tool-call', 'tool-result']
    assert entries[1]['decision'] == 'allow' and entries[2]['call_entry'] == entries[1]['seq']


def test_credentials_never_reach_the_log(proxy_url, tmp_path):
    post(proxy_url, call(1, 'get_issue', number=3))
    log = (tmp_path / 'flight.jsonl').read_text(encoding='utf-8')
    assert 'sk-live' not in log and 'secret-in-url' not in log
    [upstream] = read(tmp_path / 'flight.jsonl')[0]['server_command']
    assert upstream.startswith('http://127.0.0.1:') and upstream.endswith('/mcp')


def test_denied_call_never_leaves_the_machine(proxy_url, tmp_path):
    status, _, body = post(proxy_url, call(7, 'push_files', branch='main'))
    reply = json.loads(body)
    assert status == 200 and reply['id'] == 7 and reply['result']['isError']
    assert 'protect-main' in reply['result']['content'][0]['text']
    assert Upstream.seen == []
    assert read(tmp_path / 'flight.jsonl')[-1]['decision'] == 'deny'


def test_sse_responses_are_recorded_and_relayed(proxy_url, tmp_path):
    _, headers, body = post(proxy_url, call(2, 'get_stream'))
    assert headers['Content-Type'].startswith('text/event-stream')
    data = [json.loads(l[5:]) for l in body.splitlines() if l.startswith('data:')]
    assert data[0]['id'] == 2
    entries = read(tmp_path / 'flight.jsonl')
    assert entries[-1]['type'] == 'tool-result' and entries[-1]['tool'] == 'get_stream'


def test_batch_mixes_upstream_answers_and_blocked_calls(proxy_url, tmp_path):
    _, _, body = post(proxy_url, [call(1, 'get_issue'), call(2, 'push_files', branch='main'),
                                  {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/list'}])
    replies = {r['id']: r for r in json.loads(body)}
    assert set(replies) == {1, 2, 3} and replies[2]['result']['isError']
    assert [m['id'] for m in Upstream.seen[0][2]] == [1, 3]           # the denied call was held back
    types = [e['type'] for e in read(tmp_path / 'flight.jsonl')]
    assert 'tools-listed' in types and types.count('tool-call') == 2
    assert verify(tmp_path / 'flight.jsonl')['ok']


def test_notifications_pass_through(proxy_url):
    status, _, _ = post(proxy_url, {'jsonrpc': '2.0', 'method': 'notifications/initialized'})
    assert status == 202


def test_a_web_page_cannot_use_the_proxy(proxy_url):
    with pytest.raises(urllib.error.HTTPError) as e:
        post(proxy_url, call(1, 'get_issue'), Origin='https://evil.example.com')
    assert e.value.code == 403 and Upstream.seen == []
    assert post(proxy_url, call(1, 'get_issue'), Origin='http://localhost:6274')[0] == 200


def test_only_loopback_and_http_urls_are_accepted(tmp_path, policy_file):
    session = Session(load(policy_file), Recorder(tmp_path / 'f.jsonl'), 'x')
    with pytest.raises(ValueError, match='http'):
        HttpProxy(session, 'file:///etc/passwd')
    with pytest.raises(ValueError, match='loopback'):
        serve(HttpProxy(session, 'https://mcp.example.com/mcp'), '0.0.0.0', 0, None)


def test_public_url_drops_credentials():
    assert public_url('https://user:pw@mcp.example.com:8443/mcp?token=x#f') == 'https://mcp.example.com:8443/mcp'
