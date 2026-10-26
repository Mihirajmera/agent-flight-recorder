"""The flight log: an append-only JSON Lines file where every entry carries the hash of the one
before it, and optionally an Ed25519 signature over its own hash.

Editing, deleting or reordering any entry breaks the chain from that point on. Signing means a
valid chain can't be rebuilt by someone who can write the file but doesn't hold the key.
Truncating the end of a log can only be detected against a head hash kept somewhere else
(an "anchor"), which is why `verify` accepts one.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

GENESIS = '0' * 64


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(obj) -> str:
    return hashlib.sha256(canonical(obj).encode('utf-8')).hexdigest()


def entry_hash(entry: dict) -> str:
    """Hash of everything in the entry except its own hash and signature."""
    return digest({k: v for k, v in entry.items() if k not in ('hash', 'sig')})


def now() -> str:
    epoch = os.environ.get('SOURCE_DATE_EPOCH')            # fixed clock for reproducible tests and demos
    t = datetime.fromtimestamp(int(epoch), timezone.utc) if epoch else datetime.now(timezone.utc)
    return t.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


# --------------------------------------------------------------------------- keys

def generate_key(out: Path) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    priv = out.with_suffix('.key')
    pub = out.with_suffix('.pub')
    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # never overwrite a key
    with os.fdopen(fd, 'wb') as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


class Signer:
    def __init__(self, private_key_path: Path | None = None, *, _key=None):
        from cryptography.hazmat.primitives import serialization
        self._key = _key or serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
        self.key_id = key_id(self._key.public_key())

    @classmethod
    def demo(cls) -> 'Signer':
        """A fixed key derived from a public string, so the demo's output is reproducible.
        Anyone can recompute it: never use it for a real log."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        seed = hashlib.sha256(b'agent-flight-recorder demo key - public, never use for real logs').digest()
        return cls(_key=Ed25519PrivateKey.from_private_bytes(seed))

    def public_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization
        return self._key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, hash_hex: str) -> str:
        return base64.b64encode(self._key.sign(bytes.fromhex(hash_hex))).decode('ascii')


def load_public_key(path: Path):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(path.read_bytes())


def key_id(public_key) -> str:
    from cryptography.hazmat.primitives import serialization
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


# --------------------------------------------------------------------------- writing

@contextmanager
def file_lock(path: Path, timeout: float = 10.0):
    """Cross-process lock, so the proxy and `afr approve` can both append to one log
    without forking the chain."""
    lock = path.with_name(path.name + '.lock')
    deadline = time.monotonic() + timeout
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except (FileExistsError, PermissionError):   # Windows reports a lock being deleted as PermissionError
            if time.monotonic() > deadline:
                raise TimeoutError(f'could not lock {path} (remove {lock} if no recorder is running)')
            time.sleep(0.01)
    try:
        yield
    finally:
        os.close(fd)
        os.unlink(lock)


def _tail(path: Path) -> tuple[int, str]:
    """(seq, hash) of the last entry, read from the end of the file."""
    if not path.exists() or path.stat().st_size == 0:
        return -1, GENESIS
    with path.open('rb') as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        block = min(size, 65536)
        while True:
            fh.seek(size - block)
            lines = fh.read(block).rstrip(b'\n').split(b'\n')
            if len(lines) > 1 or block == size:
                last = json.loads(lines[-1])
                return int(last['seq']), str(last['hash'])
            block = min(size, block * 2)


class Recorder:
    def __init__(self, log: Path, signer: Signer | None = None):
        self.log = log
        self.signer = signer
        log.parent.mkdir(parents=True, exist_ok=True)

    def append(self, type_: str, **fields) -> dict:
        with file_lock(self.log):
            seq, prev = _tail(self.log)
            entry = {'seq': seq + 1, 'time': now(), 'type': type_, 'prev': prev, **fields}
            entry['hash'] = entry_hash(entry)
            if self.signer:
                entry['sig'] = self.signer.sign(entry['hash'])
            with self.log.open('a', encoding='utf-8', newline='\n') as fh:
                fh.write(canonical(entry) + '\n')
                fh.flush()
                os.fsync(fh.fileno())
        return entry


# --------------------------------------------------------------------------- reading and verifying

def read(log: Path) -> list[dict]:
    entries = []
    for n, line in enumerate(log.read_bytes().splitlines(), 1):
        if line.strip():
            try:
                entry = json.loads(line.decode('utf-8'))
            except (UnicodeDecodeError, json.JSONDecodeError):
                entry = None
            entries.append(entry if isinstance(entry, dict) else {'seq': None, '_unparseable_line': n})
    return entries


def verify(log: Path, public_key_path: Path | None = None, anchor: str | None = None) -> dict:
    """Re-perform the chain. Returns a result an auditor can read: whether every entry links to
    the one before, whether every hash recomputes, whether signatures check, and whether the
    log still contains the anchored entry."""
    entries = read(log)
    pub = load_public_key(public_key_path) if public_key_path else None
    expected_kid = key_id(pub) if pub else None
    problems: list[str] = []
    prev, signed, bad_sigs, broken = GENESIS, 0, 0, False
    for i, e in enumerate(entries):
        if '_unparseable_line' in e:
            problems.append(f'line {e["_unparseable_line"]} is not valid JSON')
            prev, broken = None, True
            continue
        if e.get('seq') != i:
            problems.append(f'entry {i}: sequence number is {e.get("seq")}, expected {i}')
            broken = True
        if prev is not None and e.get('prev') != prev:
            problems.append(f'entry {i}: does not link to the previous entry')
            broken = True
        if entry_hash(e) != e.get('hash'):
            problems.append(f'entry {i}: content does not match its hash (edited after it was written)')
            broken = True
        if 'sig' in e:
            signed += 1
            if pub is not None:
                try:
                    pub.verify(base64.b64decode(e['sig']), bytes.fromhex(e['hash']))
                except Exception:                  # InvalidSignature, bad base64, bad hex
                    bad_sigs += 1
                    problems.append(f'entry {i}: signature does not verify with the given public key')
        elif pub is not None:
            problems.append(f'entry {i}: not signed')
        if e.get('type') == 'session-start' and expected_kid and e.get('key_id') not in (None, expected_kid):
            problems.append(f'entry {i}: session was signed with key {e.get("key_id")}, not the one given')
        prev = e.get('hash')

    anchor_ok = None
    if anchor:
        try:
            a_seq, a_hash = anchor.split(':', 1)
            a = int(a_seq)
            anchor_ok = a < len(entries) and entries[a].get('hash') == a_hash
        except ValueError:
            anchor_ok = False
        if not anchor_ok:
            problems.append(f'anchor {anchor} is not in the log (entries removed or replaced)')

    head = entries[-1] if entries else None
    return {
        'log': str(log),
        'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest(),
        'entries': len(entries),
        'head': f'{head.get("seq")}:{head["hash"]}' if head and head.get('hash') else None,
        'chain_intact': not broken,
        'signed_entries': signed,
        'signatures_checked': pub is not None,
        'bad_signatures': bad_sigs,
        'anchor_matched': anchor_ok,
        'ok': not problems,
        'problems': problems,
    }
