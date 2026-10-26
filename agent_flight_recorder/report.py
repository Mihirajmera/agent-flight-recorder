"""Turn a flight log into audit evidence. Nothing here trusts the log's own claims: the chain is
re-verified, every approved call is traced back to its approval entry, and every recorded
decision is checked against the policy that was in force for that session."""
from __future__ import annotations

import csv
import json
import uuid
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .chain import canonical, digest

CONTROLS = yaml.safe_load((Path(__file__).parent / 'controls.yaml').read_text(encoding='utf-8'))['controls']
FRAMEWORK_LABELS = {'nist_800_53': 'NIST 800-53', 'soc2': 'SOC 2', 'iso_42001': 'ISO 42001', 'eu_ai_act': 'EU AI Act'}
SEVERITY_ORDER = {'high': 3, 'medium': 2, 'low': 1}
BLOCKED = {'deny', 'approval-required'}


@dataclass
class Finding:
    check_id: str
    severity: str
    message: str
    entry: int | None = None                 # seq of the log entry the finding is about


def _ts(value) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def assess(entries: list[dict], verification: dict) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {cid: [] for cid in CONTROLS}
    good = [e for e in entries if isinstance(e.get('seq'), int)]
    by_seq = {e['seq']: e for e in good}

    # AFR-01: integrity
    if not verification['chain_intact']:
        out['AFR-01'].append(Finding('AFR-01', 'high', 'The hash chain is broken: ' + '; '.join(verification['problems'][:5])))
    elif verification['problems']:
        out['AFR-01'].append(Finding('AFR-01', 'high', '; '.join(verification['problems'][:5])))
    if verification['signed_entries'] == 0 and good:
        out['AFR-01'].append(Finding('AFR-01', 'medium', 'The log is not signed. The chain shows edits, but anyone '
                                     'who can write the file could rebuild a valid chain. Run the proxy with --key.'))
    elif not verification['signatures_checked'] and verification['signed_entries']:
        out['AFR-01'].append(Finding('AFR-01', 'low', 'Signatures were not checked: pass the public key with --pubkey.'))
    if verification['anchor_matched'] is None and good:
        out['AFR-01'].append(Finding('AFR-01', 'low', 'No anchor was given, so removal of the most recent entries '
                                     'can\'t be ruled out. Store the head from `afr verify` outside this system.'))

    # Policy in force for each entry: the most recent session-start before it.
    session_rules, current = {}, {}
    for e in good:
        if e.get('type') == 'session-start':
            pol = e.get('policy') if isinstance(e.get('policy'), dict) else {}
            rules = pol.get('rules') if isinstance(pol.get('rules'), list) else []
            current = {str(r.get('id')): r.get('decision') for r in rules if isinstance(r, dict)}
            current['default'] = pol.get('default')
        session_rules[e['seq']] = current

    approvals = {e['seq']: e for e in good if e.get('type') == 'approval'}
    used_approvals: Counter = Counter()
    results = {e['call_entry']: e for e in good if e.get('type') == 'tool-result' and isinstance(e.get('call_entry'), int)}

    for e in good:
        if e.get('type') != 'tool-call':
            continue
        seq, decision = e['seq'], e.get('decision')

        # AFR-02: attribution
        who = str(e.get('on_behalf_of') or '')
        if not e.get('agent') or not who or who.startswith('unknown'):
            out['AFR-02'].append(Finding('AFR-02', 'high', f'Call to {e.get("tool")} does not record both the agent '
                                         f'and the person it acted for.', seq))

        # AFR-05: the recorded decision matches the policy in force, and blocked calls never ran
        expected = session_rules.get(seq, {}).get(str(e.get('rule')))
        allowed_as = {'allow': {'allow'}, 'deny': {'deny'}, 'approve': {'approved', 'approval-required'}}
        if expected and decision not in allowed_as.get(expected, set()):
            out['AFR-05'].append(Finding('AFR-05', 'high', f'Call to {e.get("tool")} was recorded as "{decision}" but '
                                         f'rule {e.get("rule")} says "{expected}".', seq))
        if decision in BLOCKED and seq in results:
            out['AFR-05'].append(Finding('AFR-05', 'high', f'Call to {e.get("tool")} was {decision} but has a result: '
                                         f'it reached the server.', seq))

        # AFR-03 / AFR-04: approvals
        if decision == 'approved':
            ref = e['approval'].get('approval_entry', '') if isinstance(e.get('approval'), dict) else ''
            try:
                a_seq, a_hash = ref.split(':', 1)
                a = approvals.get(int(a_seq))
            except (ValueError, AttributeError):
                a, a_hash = None, None
            if a is None or a.get('hash') != a_hash or a['seq'] > seq:
                out['AFR-03'].append(Finding('AFR-03', 'high', f'Call to {e.get("tool")} claims an approval that is '
                                             f'not an earlier approval entry in this log.', seq))
                continue
            used_approvals[a['seq']] += 1
            if a.get('decision') != 'approved' or a.get('request_key') != e.get('request_key'):
                out['AFR-03'].append(Finding('AFR-03', 'high', f'Call to {e.get("tool")} ran under approval {a["seq"]}, '
                                             f'which approved a different call.', seq))
            elif a.get('expires'):
                ran, expires = _ts(e.get('time')), _ts(a['expires'])
                if ran is None or expires is None:
                    out['AFR-03'].append(Finding('AFR-03', 'high', f'Call to {e.get("tool")}: cannot confirm it ran '
                                                 f'before its approval expired (unreadable timestamp).', seq))
                elif ran > expires:
                    out['AFR-03'].append(Finding('AFR-03', 'high', f'Call to {e.get("tool")} ran after its approval '
                                                 f'expired at {a["expires"]}.', seq))
            if used_approvals[a['seq']] == 2:
                out['AFR-03'].append(Finding('AFR-03', 'high', f'Approval {a["seq"]} was used more than once.', seq))

    for a in approvals.values():
        if a.get('decision') == 'approved' and str(a.get('approver', '')).strip().lower() == \
                str(a.get('on_behalf_of', '')).strip().lower():
            out['AFR-04'].append(Finding('AFR-04', 'medium', f'{a.get("approver")} approved a {a.get("tool")} call '
                                         f'that the agent made on their own behalf.', a['seq']))

    # AFR-06: tool definitions that changed between listings
    seen: dict[tuple, tuple] = {}
    for e in good:
        if e.get('type') != 'tools-listed':
            continue
        for t in e.get('tools') if isinstance(e.get('tools'), list) else []:
            if not isinstance(t, dict):
                continue
            k = (str(e.get('server')), str(t.get('name')))
            v = (t.get('description_sha256'), t.get('schema_sha256'))
            if k in seen and seen[k][0] != v:
                what = ' and '.join(x for x, changed in (('description', seen[k][0][0] != v[0]),
                                                         ('input schema', seen[k][0][1] != v[1])) if changed)
                out['AFR-06'].append(Finding('AFR-06', 'medium', f'Tool {k[1]} on {k[0]} changed its {what} since entry '
                                             f'{seen[k][1]}. Review what it now tells the agent.', e['seq']))
            seen[k] = (v, e['seq'])

    # AFR-07: forwarded calls with no recorded outcome
    for e in good:
        if e.get('type') == 'tool-call' and e.get('decision') in ('allow', 'approved') and e['seq'] not in results \
                and e.get('call_id') is not None:
            out['AFR-07'].append(Finding('AFR-07', 'low', f'Call to {e.get("tool")} was forwarded but no result was '
                                         f'recorded (server crash, timeout or session cut short).', e['seq']))
    return out


def summarize(entries: list[dict]) -> dict:
    calls = [e for e in entries if e.get('type') == 'tool-call']
    return {
        'sessions': sum(1 for e in entries if e.get('type') == 'session-start'),
        'agents': sorted({str(e.get('agent')) for e in calls if e.get('agent')}),
        'on_behalf_of': sorted({str(e.get('on_behalf_of')) for e in calls if e.get('on_behalf_of')}),
        'servers': sorted({str(e.get('server')) for e in calls if e.get('server')}),
        'calls': len(calls),
        'decisions': dict(sorted(Counter(str(e.get('decision')) for e in calls).items())),
        'by_tool': {t: dict(sorted(c.items())) for t, c in sorted(
            (t, Counter(str(e.get('decision')) for e in calls if str(e.get('tool')) == t))
            for t in {str(e.get('tool')) for e in calls})},
        'approvals': sum(1 for e in entries if e.get('type') == 'approval'),
        'first': entries[0].get('time') if entries else None,
        'last': entries[-1].get('time') if entries else None,
    }


def status(findings: list[Finding]) -> str:
    return 'FAIL' if any(f.severity in ('high', 'medium') for f in findings) else ('PASS' if not findings else 'NOTE')


def _cell(v) -> str:
    return str(v).replace('|', '\\|').replace('\n', ' ')


def _frameworks(cid: str) -> str:
    c = CONTROLS[cid]
    return '; '.join(f'{label} {", ".join(c[k])}' for k, label in FRAMEWORK_LABELS.items() if c.get(k))


def write_all(entries: list[dict], verification: dict, results: dict[str, list[Finding]], out: Path) -> dict[str, Path]:
    out.mkdir(parents=True, exist_ok=True)
    entries = [e for e in entries if isinstance(e.get('seq'), int)]     # unreadable lines are already in verification
    summary = summarize(entries)
    evidence = {
        'log': {k: verification[k] for k in ('log_sha256', 'entries', 'head')},
        'verification': verification,
        'summary': summary,
        'results': [{'check_id': cid, 'title': CONTROLS[cid]['title'], 'status': status(fs),
                     'findings': [asdict(f) for f in fs]} for cid, fs in sorted(results.items())],
    }
    evidence['log']['path'] = Path(verification['log']).name
    evidence['verification'] = {**verification, 'log': Path(verification['log']).name}
    evidence['sha256'] = digest({k: evidence[k] for k in ('log', 'summary', 'results')})
    evidence['hash_scope'] = 'sha256 of canonical JSON of {log, summary, results}'
    ev = out / 'evidence.json'
    ev.write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    return {'report': _markdown(entries, verification, results, summary, out / 'flight-report.md', evidence['sha256']),
            'calls': _csv(entries, out / 'calls.csv'),
            'evidence': ev,
            'oscal': _oscal(verification, results, summary, out / 'oscal' / 'assessment-results.json', evidence['sha256'])}


def _csv(entries: list[dict], path: Path) -> Path:
    results = {e['call_entry']: e for e in entries if e.get('type') == 'tool-result' and isinstance(e.get('call_entry'), int)}
    with path.open('w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh, lineterminator='\n')
        w.writerow(['seq', 'time', 'agent', 'on_behalf_of', 'server', 'tool', 'decision', 'rule', 'approver',
                    'args_sha256', 'result', 'duration_ms', 'entry_hash'])
        for e in entries:
            if e.get('type') != 'tool-call':
                continue
            r = results.get(e['seq'])
            w.writerow([e['seq'], e.get('time'), e.get('agent'), e.get('on_behalf_of'), e.get('server'), e.get('tool'),
                        e.get('decision'), e.get('rule'), e['approval'].get('approver', '') if isinstance(e.get('approval'), dict) else '',
                        e.get('args_sha256'), '' if r is None else ('error' if r.get('is_error') else 'ok'),
                        '' if r is None else r.get('duration_ms'), e.get('hash')])
    return path


def _markdown(entries, verification, results, summary, path: Path, evidence_hash: str) -> Path:
    v = verification
    open_ = [f for fs in results.values() for f in fs]
    c = Counter(f.severity for f in open_)
    L = ['# Agent Flight Report', '',
         f'**{summary["calls"]} tool calls** by {", ".join(summary["agents"]) or "no agent"} '
         f'on behalf of {", ".join(summary["on_behalf_of"]) or "nobody recorded"}, across {summary["sessions"]} '
         f'session{"s" if summary["sessions"] != 1 else ""} ({summary["first"]} to {summary["last"]}).', '',
         f'**{len(open_)} findings** ({c["high"]} high, {c["medium"]} medium, {c["low"]} low).', '',
         '## Log integrity', '',
         f'- **Entries:** {v["entries"]}, chain {"intact" if v["chain_intact"] else "**BROKEN**"}',
         f'- **Signatures:** {v["signed_entries"]} signed entries; '
         + ('all verified' if v['signatures_checked'] and not v['bad_signatures'] else
            f'**{v["bad_signatures"]} failed**' if v['signatures_checked'] else 'not checked (no public key given)'),
         f'- **Anchor:** ' + {None: 'none given', True: 'matched', False: '**not found**'}[v['anchor_matched']],
         f'- **Log file sha256:** `{v["log_sha256"]}`',
         f'- **Head (store this elsewhere to detect truncation):** `{v["head"]}`', '',
         '## Decisions', '', '| Tool | ' + ' | '.join(sorted(summary['decisions'])) + ' |',
         '|---|' + '---:|' * len(summary['decisions'])]
    for tool, counts in summary['by_tool'].items():
        L.append(f'| {_cell(tool)} | ' + ' | '.join(str(counts.get(d, 0)) for d in sorted(summary['decisions'])) + ' |')
    L += ['', '## Control results', '', '| Check | Control | Result | Frameworks |', '|---|---|---|---|']
    for cid in sorted(CONTROLS):
        L.append(f'| {cid} | {CONTROLS[cid]["title"]} | {status(results[cid])} | {_frameworks(cid)} |')
    L += ['', '## Findings', '']
    if open_:
        L += ['| Check | Severity | Entry | Finding |', '|---|---|---:|---|']
        for f in sorted(open_, key=lambda f: (-SEVERITY_ORDER[f.severity], f.check_id, f.entry or 0)):
            L.append(f'| {f.check_id} | {f.severity} | {"" if f.entry is None else f.entry} | {_cell(f.message)} |')
    else:
        L.append('No findings.')
    approvals = [e for e in entries if e.get('type') == 'approval']
    if approvals:
        L += ['', '## Approvals', '', '| Entry | Time | Tool | Requested for | Approver | Decision | Expires |',
              '|---:|---|---|---|---|---|---|']
        L += [f'| {a["seq"]} | {a.get("time")} | {_cell(a.get("tool"))} | {_cell(a.get("on_behalf_of"))} | '
              f'{_cell(a.get("approver"))} | {a.get("decision")} | {a.get("expires") or ""} |' for a in approvals]
    L += ['', f'Evidence: `evidence.json` (sha256 `{evidence_hash[:16]}…`). Every call, with its hashes, is in '
          '`calls.csv`.', '', '## Sign-off', '', '| Role | Name | Date |', '|---|---|---|',
          '| Agent owner | | |', '| Reviewer | | |']
    path.write_text('\n'.join(L) + '\n', encoding='utf-8', newline='\n')
    return path


def _uid(*parts) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'agent-flight-recorder:' + '/'.join(map(str, parts))))


def _oscal_id(control: str) -> str:
    return control.lower().replace('(', '.').replace(')', '')


def _oscal(verification, results, summary, path: Path, evidence_hash: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = summary['last'] or '1970-01-01T00:00:00Z'
    obs = _uid(stamp, 'observation', verification['log_sha256'])
    by_control: dict[str, list[str]] = defaultdict(list)
    for cid in sorted(CONTROLS):
        for ctl in CONTROLS[cid]['nist_800_53']:
            by_control[ctl].append(cid)
    findings = [{
        'uuid': _uid(stamp, 'finding', ctl),
        'title': f'{ctl}: {", ".join(cids)}',
        'description': '; '.join(CONTROLS[c]['title'] for c in cids),
        'target': {'type': 'objective-id', 'target-id': _oscal_id(ctl),
                   'status': {'state': 'not-satisfied' if any(status(results[c]) == 'FAIL' for c in cids)
                              else 'satisfied'}},
        'related-observations': [{'observation-uuid': obs}],
    } for ctl, cids in sorted(by_control.items())]
    doc = {'assessment-results': {
        'uuid': _uid(stamp, 'assessment-results', verification['log_sha256']),
        'metadata': {'title': 'AI agent activity review (flight log)', 'last-modified': stamp,
                     'version': verification['head'] or 'empty', 'oscal-version': '1.1.2'},
        'import-ap': {'href': '#'},
        'results': [{
            'uuid': _uid(stamp, 'result'),
            'title': 'Re-performance of an agent flight log',
            'description': f'{summary["calls"]} tool calls, {summary["approvals"]} approvals, '
                           f'{verification["entries"]} log entries.',
            'start': summary['first'] or stamp, 'end': stamp,
            'reviewed-controls': {'control-selections': [
                {'include-controls': [{'control-id': _oscal_id(c)} for c in sorted(by_control)]}]},
            'observations': [{
                'uuid': obs, 'title': 'Flight log re-performance', 'methods': ['EXAMINE', 'TEST'],
                'description': 'Hash chain, signatures, approvals and policy enforcement re-checked from the log.',
                'types': ['finding' if any(results.values()) else 'control-objective'],
                'relevant-evidence': [{'href': '../evidence.json', 'description': 'Hashed evidence summary',
                                       'props': [{'name': 'sha256', 'value': evidence_hash}]}],
                'collected': stamp}],
            'findings': findings,
        }],
    }}
    path.write_text(json.dumps(doc, indent=2) + '\n', encoding='utf-8', newline='\n')
    return path


__all__ = ['assess', 'write_all', 'summarize', 'status', 'canonical']
