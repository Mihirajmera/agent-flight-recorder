"""Build the wheel without pip and check it ships everything the CLI needs at runtime:
the control catalog, the example policy, and both console scripts."""
import sys
import zipfile
from pathlib import Path

from setuptools import build_meta

dist = Path('dist')
dist.mkdir(exist_ok=True)
wheel = dist / build_meta.build_wheel(str(dist))
names = set(zipfile.ZipFile(wheel).namelist())
required = {'agent_flight_recorder/controls.yaml', 'agent_flight_recorder/examples/policy.yaml'}
missing = sorted(required - names)
entry_points = next((n for n in names if n.endswith('.dist-info/entry_points.txt')), None)
text = zipfile.ZipFile(wheel).read(entry_points).decode() if entry_points else ''
script_ok = all(f'{s} = agent_flight_recorder.__main__:main' in text for s in ('afr', 'agent-flight-recorder'))
print(f'{wheel.name}: {len(names)} files')
if missing or not script_ok:
    sys.exit(f'missing from wheel: {missing or ""} {"" if script_ok else "console scripts"}')
print('wheel contains the control catalog, example policy and console scripts')
