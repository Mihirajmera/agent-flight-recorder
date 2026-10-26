#!/bin/bash -eu
# Runtime dependencies, pinned by version and hash.
pip3 install --require-hashes -r .clusterfuzzlite/requirements.txt

# Bundle every fuzz target with the package (and any data files it loads at import time).
for fuzzer in $(find "$SRC/agent-flight-recorder/fuzz" -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer" --paths "$SRC/agent-flight-recorder" \
    --add-data "agent_flight_recorder/controls.yaml:agent_flight_recorder"
done
