"""Fuzz log verification, the evidence checks and policy loading with arbitrary bytes.

An auditor runs `afr verify` and `afr report` on logs they did not write, and the proxy loads
policy files from the repository. A malformed log must be reported as a problem, not crash the
verifier or the report; a malformed policy must raise PolicyError. Any other exception, hang or crash is a bug.
"""
import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from agent_flight_recorder.chain import read, verify
    from agent_flight_recorder.policy import PolicyError, load
    from agent_flight_recorder.report import assess, write_all

TMP = Path(tempfile.mkdtemp())


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    log, policy = TMP / 'flight.jsonl', TMP / 'policy.yaml'
    log.write_bytes(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 8192)))
    policy.write_bytes(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 2048)))
    entries, verification = read(log), verify(log, anchor=fdp.ConsumeUnicodeNoSurrogates(80) or None)
    write_all(entries, verification, assess(entries, verification), TMP / 'evidence')
    try:
        load(policy)
    except PolicyError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
