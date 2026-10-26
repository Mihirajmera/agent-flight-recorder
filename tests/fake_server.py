"""A minimal MCP server over stdio for tests: lists two tools and answers every call with the
tool name it received. It also appends each call it sees to the file named in argv[1], so tests
can prove which calls actually reached the server."""
import json
import sys

seen = open(sys.argv[1], 'a', encoding='utf-8')
for line in sys.stdin:
    msg = json.loads(line)
    if 'id' not in msg:
        continue
    if msg.get('method') == 'tools/list':
        result = {'tools': [{'name': 'get_issue', 'description': 'Read an issue', 'inputSchema': {}},
                            {'name': 'delete_repo', 'description': 'Delete a repository', 'inputSchema': {}}]}
    elif msg.get('method') == 'tools/call':
        seen.write(msg['params']['name'] + '\n')
        seen.flush()
        result = {'content': [{'type': 'text', 'text': 'did ' + msg['params']['name']}]}
    else:
        result = {}
    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': result}) + '\n')
    sys.stdout.flush()
