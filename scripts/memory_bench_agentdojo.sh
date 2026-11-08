#!/usr/bin/env bash
# ⑥ Attack memory on AgentDojo. Worst-case agent (eval/agentdojo/mock.py: it obeys every
# injection it can read), classifier off, so every difference is the memory's.
#
#   reference  no defense · Laocoon with nobody checking approvals (approve) · with an attentive user (oracle)
#   E1         learn on `workspace` from the attentive user's rejections; test on travel, banking, slack with nobody
#              checking (the memory frozen): does one suite's experience protect the others?
#   E2         the same memory against AgentDojo's other attack templates (and those templates without memory)
#   E3         online: all suites, shuffled, the attentive user, memory on vs off: how many approvals the user faces
#
#   scripts/memory_bench_agentdojo.sh [OUT_DIR]      (needs the agentdojo package; PY=... to choose the interpreter)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-../.venv/bin/python}
OUT=$(realpath -m "${1:-eval/results/agentdojo-memory-$(date +%Y%m%d-%H%M%S)}")
W=${WORKERS:-2}
mkdir -p "$OUT"
run() { "$PY" -m eval.agentdojo.run --llm mock --out "$OUT" "$@" | grep -E "cases to run|^results" || true; }
ody=(--defense laocoon --guard off)

echo "== reference"
run --defense none --workers "$W"
run "${ody[@]}" --human approve --workers "$W"
run "${ody[@]}" --human oracle --workers "$W"

echo "== E1 learn on workspace, test on the other suites"
MEM=$OUT/memory-workspace.db
rm -f "$MEM"*
run "${ody[@]}" --human oracle --memory on --memory-db "$MEM" --suites workspace --workers 1 --tag learn-workspace
"$PY" -m laocoon memory --db "$MEM" stats
"$PY" -m laocoon memory --db "$MEM" list --limit 100 > "$OUT/memory-workspace.txt"
run "${ody[@]}" --human approve --memory match --memory-db "$MEM" --suites travel,banking,slack --workers "$W" \
  --tag test-other-suites

echo "== E2 other attack templates (nobody checking approvals), without and with the workspace memory"
for atk in important_instructions_no_names ignore_previous tool_knowledge injecagent direct system_message; do
  run "${ody[@]}" --human approve --attack "$atk" --mode attack --workers "$W" --tag "attack-$atk"
  run "${ody[@]}" --human approve --memory match --memory-db "$MEM" --attack "$atk" --mode attack --workers "$W" \
    --tag "attack-$atk"
done

echo "== E3 online: everything shuffled, the attentive user, memory learning as attacks arrive"
ON=$OUT/memory-online.db
rm -f "$ON"*
run "${ody[@]}" --human oracle --shuffle 7 --workers 1 --tag online
run "${ody[@]}" --human oracle --memory on --memory-db "$ON" --shuffle 7 --workers 1 --tag online
"$PY" -m laocoon memory --db "$ON" stats

"$PY" -m eval.agentdojo.run --summarize "$OUT" > /dev/null
echo "results: $OUT/summary.md"
