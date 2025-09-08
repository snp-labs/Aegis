#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

export $(grep -v '^#' "$PROJECT_ROOT/.env" | xargs)

THREADS=(1 2 4 6 8 10)

for t in "${THREADS[@]}"; do
  echo "=== RAYON_NUM_THREADS = $t ==="
  RAYON_NUM_THREADS="$t" \
    cargo test --release tests::aegis_circuit::bn254::aegis_circuit_scenario
done
