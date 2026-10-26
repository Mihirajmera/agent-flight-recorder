# Contributing

Thanks for helping. The most useful contributions are small and concrete.

## Report a wrong finding

If a check flags something that's actually fine, or misses something it should catch, open a **Bug report** with a log or message sequence that reproduces it. Remove real secrets first.

## Add a check

Each check needs:

- a block in `assess()` in [`report.py`](agent_flight_recorder/report.py) that re-performs the control from the log alone, without trusting what the log says about itself;
- an entry in [`controls.yaml`](agent_flight_recorder/controls.yaml) with its framework mappings;
- tests for the passing and failing case. For a failing case, edit a real log with `rewrite()` in `tests/conftest.py`, the way someone with write access but no signing key could.

## Code changes

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest -q
```

If your change alters the report, regenerate the sample: `SOURCE_DATE_EPOCH=1791763200 python -m agent_flight_recorder demo --out sample-output`. CI fails if `sample-output/` is stale.

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
