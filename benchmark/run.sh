#!/bin/sh
# Real comparison runner. Requires a live target (see benchmark/README.md).
# Passes all args through to the harness, e.g.:
#   ./benchmark/run.sh --target http://localhost:5013/graphql
python benchmark/compare.py "$@"
