"""MCP Streamable HTTP proxy. Same policy and recording as the stdio proxy; only the transport differs:

  agent  <-- HTTP -->  afr proxy (127.0.0.1)  <-- HTTPS -->  remote MCP server

The agent's MCP client is pointed at the local address instead of the server's URL. Each POST is
decided by `Session.from_client` before anything leaves the machine; responses, whether plain JSON
or an SSE stream, are read by `Session.from_server` on their way back. Request headers (including
Authorization) are passed to the upstream and never written to the log. Redirects are not followed,
so a token is only ever sent to the URL that was configured.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .proxy import Session, _fail_closed

MAX_BODY = 16 * 1024 * 1024
# Headers that describe one hop, not the message; plus the ones the proxy sets itself.
HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer',
       'transfer-encoding', 'upgrade', 'host', 'content-length', 'accept-encoding', 'origin'}


def is_loopback(host: str) -> bool:
    host = host.strip('[]').rstrip('.').lower()
    if host == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def public_url(url: str) -> str:
    """The upstream as it is written to the log: no userinfo, query or fragment, which is where
    credentials end up in a URL."""
    u = urlsplit(url)
    host = u.hostname or ''
    return f'{u.scheme}://{host}{":" + str(u.port) if u.port else ""}{u.path}'


class HttpProxy:
    def __init__(self, session: Session, upstream: str, timeout: float = 300):
        u = urlsplit(upstream)
        if u.scheme not in ('http', 'https') or not u.hostname:
            raise ValueError(f'--http-upstream must be an http(s) URL, not {upstream!r}')
        self.session, self.upstream, self.timeout = session, u, timeout
        self.lock = threading.Lock()      # one log, one chain: record one message at a time

    # ------------------------------------------------------------------ policy and recording

    def decide(self, msg) -> tuple[list, list]:
        with self.lock:
            try:
                return self.session.from_client(msg)
            except Exception as exc:          # fail closed: an unrecorded call doesn't run
                print(f'afr: could not record, blocking: {exc}', file=sys.stderr)
                return _fail_closed(msg)

    def observe(self, msg) -> None:
        with self.lock:
            try:
                self.session.from_server(msg)
            except Exception as exc:          # never drop traffic because recording failed
                print(f'afr: could not record server message: {exc}', file=sys.stderr)

    # ------------------------------------------------------------------ upstream

    def target(self, path: str) -> str:
        # OAuth discovery lives at the server's origin; everything else is the MCP endpoint.
        if path.startswith('/.well-known/'):
            return path
        return (self.upstream.path or '/') + (f'?{self.upstream.query}' if self.upstream.query else '')

    def connect(self) -> http.client.HTTPConnection:
        cls = http.client.HTTPSConnection if self.upstream.scheme == 'https' else http.client.HTTPConnection
        return cls(self.upstream.hostname, self.upstream.port, timeout=self.timeout)


def make_handler(proxy: HttpProxy):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, fmt, *args):     # requests are in the flight log; keep stderr quiet
            pass

        # -------------------------------------------------------------- local guards

        def _allowed(self) -> bool:
            # The proxy has no authentication of its own, so only this machine may use it. A browser
            # page can still reach 127.0.0.1 (DNS rebinding), which is what the Origin check stops.
            origin = self.headers.get('Origin')
            if origin and not is_loopback(urlsplit(origin).hostname or ''):
                self._reply(403, {'error': 'origin not allowed'})
                return False
            return True

        def _reply(self, status: int, obj, headers: dict | None = None) -> None:
            data = json.dumps(obj).encode('utf-8')
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        # -------------------------------------------------------------- methods

        def do_POST(self):
            if not self._allowed():
                return
            length = self.headers.get('Content-Length')
            if length is None or not length.isdigit() or int(length) > MAX_BODY:
                self._reply(411 if length is None else 413, {'error': 'a Content-Length up to 16 MB is required'})
                return
            body = self.rfile.read(int(length))
            try:
                msg = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                msg = None
            if msg is None:
                forward, replies = [body], []
            else:
                forward, replies = proxy.decide(msg)
            if not forward:                        # every call in it was blocked: nothing goes upstream
                self._reply(200, replies if isinstance(msg, list) else replies[0])
                return
            if len(forward) == 1 and (forward[0] is msg or forward[0] is body):
                out = body                         # untouched: send the original bytes
            else:
                out = json.dumps(forward if isinstance(msg, list) else forward[0]).encode('utf-8')
            self._upstream('POST', out, replies)

        def do_GET(self):
            if self._allowed():
                self._upstream('GET', None, [])

        def do_DELETE(self):
            if self._allowed():
                self._upstream('DELETE', None, [])

        # -------------------------------------------------------------- forwarding

        def _upstream(self, method: str, body: bytes | None, replies: list) -> None:
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
            headers['Accept-Encoding'] = 'identity'          # the proxy has to read the response
            conn = proxy.connect()
            try:
                conn.request(method, proxy.target(self.path), body=body, headers=headers)
                resp = conn.getresponse()
            except OSError as exc:
                conn.close()
                self._reply(502, {'error': f'upstream unreachable: {exc.__class__.__name__}'})
                return
            try:
                ctype = (resp.getheader('Content-Type') or '').split(';')[0].strip().lower()
                passthrough = {k: v for k, v in resp.getheaders() if k.lower() not in HOP | {'content-type'}}
                if ctype == 'text/event-stream':
                    self._stream(resp, passthrough, replies)
                    return
                data = resp.read()
                if ctype == 'application/json' and data:
                    try:
                        answer = json.loads(data)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        answer = None
                    if answer is not None:
                        proxy.observe(answer)
                        if replies:                  # blocked calls in a batch: answer them alongside
                            answer = (answer if isinstance(answer, list) else [answer]) + replies
                            data = json.dumps(answer).encode('utf-8')
                elif replies and resp.status in (200, 202):
                    # Upstream accepted the notifications in the batch; the blocked calls still need an answer.
                    self._reply(200, replies, passthrough)
                    return
                self.send_response(resp.status)
                for k, v in passthrough.items():
                    self.send_header(k, v)
                if ctype:
                    self.send_header('Content-Type', resp.getheader('Content-Type'))
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            finally:
                conn.close()

        def _stream(self, resp, headers: dict, replies: list) -> None:
            self.send_response(resp.status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'close')        # the stream ends when the upstream's does
            self.end_headers()
            self.close_connection = True
            try:
                for reply in replies:                         # blocked calls: answer them first
                    self.wfile.write(b'event: message\ndata: ' + json.dumps(reply).encode('utf-8') + b'\n\n')
                self.wfile.flush()
                data_lines: list[bytes] = []
                for line in iter(resp.readline, b''):
                    self.wfile.write(line)
                    stripped = line.rstrip(b'\r\n')
                    if stripped.startswith(b'data:'):
                        data_lines.append(stripped[5:].removeprefix(b' '))
                    elif not stripped:                       # end of one event
                        if data_lines:
                            try:
                                proxy.observe(json.loads(b'\n'.join(data_lines)))
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                pass
                        data_lines = []
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass                                          # the agent hung up

    return Handler


def serve(proxy: HttpProxy, host: str, port: int, key_id: str | None, ready=None) -> int:
    """Run until interrupted. `ready` is called with the bound server (tests use port 0)."""
    if not is_loopback(host):
        raise ValueError('--listen must be a loopback address; the proxy has no authentication of its own')
    server = ThreadingHTTPServer((host, port), make_handler(proxy))
    server.daemon_threads = True
    proxy.session.start([public_url(proxy.upstream.geturl())], key_id)
    if ready:
        ready(server)
    else:
        h, p = server.server_address[:2]
        print(f'afr: proxying http://{h}:{p}/mcp -> {public_url(proxy.upstream.geturl())}', file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        with proxy.lock:
            proxy.session.end(None)
    return 0
