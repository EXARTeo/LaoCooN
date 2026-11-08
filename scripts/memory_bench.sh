#!/usr/bin/env bash
# ⑥ Attack memory on the eClass eval: learn -> test.
#
#   0  reference   attacks + benign + variants, no memory                 (how far the other layers get)
#   1  learn       attacks + benign, memory on (canary, honey and the user's rejections confirm on their own)
#   2  test        attacks + benign + variants, the learned memory frozen (match: it acts, it learns nothing new)
#
# Every run: proxy target, the scripted worst-case model that obeys an injection whenever it can read it
# (--obey visible), an attentive user who rejects every approval an attack causes (--reject-attacks), classifier off,
# private_data off (PRIVATE=on to keep it): with it on, the private-data layer denies I02's and I07's exfiltration
# outright, so no approval is shown, nothing is learned from them and their variants V02/V07 are stopped by that
# layer instead of the memory (the gate then reports 7/9; ASR stays 0).
#
#   scripts/memory_bench.sh [OUT_DIR]          (from the repo root; PY=... to choose the interpreter)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-../.venv/bin/python}
OUT=$(realpath -m "${1:-eval/results/memory-$(date +%Y%m%d-%H%M%S)}")
MEM=$OUT/memory.db
mkdir -p "$OUT"
rm -f "$MEM" "$MEM-wal" "$MEM-shm"
common=(--target proxy --llm mock --obey visible --reject-attacks --private "${PRIVATE:-off}")

echo "== 0 reference (no memory)"
"$PY" -m eval.run "${common[@]}" --mode both --suite attacks,benign,variants --out "$OUT/0-reference" \
  --json "$OUT/0-reference.json" | tail -n 25
echo "== 1 learn"
"$PY" -m eval.run "${common[@]}" --mode protected --suite attacks,benign --memory on --memory-db "$MEM" \
  --memory-autoconfirm canary,honey,rejected --out "$OUT/1-learn" --json "$OUT/1-learn.json" | tail -n 25
"$PY" -m laocoon memory --db "$MEM" list --limit 200 | tee "$OUT/memory-after-learning.txt"
echo "== 2 test (memory frozen)"
"$PY" -m eval.run "${common[@]}" --mode protected --suite attacks,benign,variants --memory match --memory-db "$MEM" \
  --out "$OUT/2-test" --json "$OUT/2-test.json" | tail -n 25
"$PY" scripts/memory_gate.py "$OUT/2-test.json"
echo "results: $OUT"
