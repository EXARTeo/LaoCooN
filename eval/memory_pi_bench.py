"""⑥ Attack memory on public prompt-injection datasets: how much does remembering confirmed attacks catch on held-out
data, and how often does it fire on benign text?

    python -m eval.memory_pi_bench                         # deepset/prompt-injections + xTRam1/safe-guard-prompt-injection
    python -m eval.memory_pi_bench --dataset deepset/prompt-injections --out eval/results/memory-pi.md

Protocol per dataset: the injections of the train split are remembered (every one confirmed, as if an admin had
confirmed them all: the upper bound of what the memory can know); every text of the test split is matched at G1.
Reported: recall on the test injections (strong = would block; any = block or review), false-positive rate on the
test's benign texts, the same with only k remembered attacks, and how many test injections are near-duplicates of a
train one (datasets repeat prompts, and so do attackers). Plus the latency of one match as the memory grows.
Needs pandas + pyarrow and network access to huggingface.co (parquet files).
"""
from __future__ import annotations

import argparse
import io
import os
import random
import statistics
import tempfile
import time
from pathlib import Path

import requests

from laocoon.memory import AttackMemory, grams
from laocoon.store import Store

DATASETS = {   # name -> (text column, label column, positive label)
    "deepset/prompt-injections": ("text", "label", 1),
    "xTRam1/safe-guard-prompt-injection": ("text", "label", 1),
}


def load_split(name, split):
    import pandas as pd
    urls = requests.get(f"https://huggingface.co/api/datasets/{name}/parquet/default/{split}", timeout=60).json()
    frames = [pd.read_parquet(io.BytesIO(requests.get(u, timeout=120).content)) for u in urls]
    return pd.concat(frames, ignore_index=True)


def evaluate(mem, texts):
    strong = weak = 0
    for t in texts:
        m = mem.match(t, "G1")
        if m is not None:
            weak += 1
            strong += int(m.strong)
    return strong, weak


def bench(name, ks=(10, 50, None), seed=0):
    tcol, lcol, pos = DATASETS[name]
    train, test = load_split(name, "train"), load_split(name, "test")
    inj_train = [str(t) for t, l in zip(train[tcol], train[lcol]) if l == pos and len(grams(str(t))) >= 24]
    inj_test = [str(t) for t, l in zip(test[tcol], test[lcol]) if l == pos]
    ben_test = [str(t) for t, l in zip(test[tcol], test[lcol]) if l != pos]
    rows = []
    rng = random.Random(seed)
    for k in ks:
        seed_set = inj_train if k is None or k >= len(inj_train) else rng.sample(inj_train, k)
        d = tempfile.mkdtemp()
        mem = AttackMemory(Store(os.path.join(d, "m.db")), refresh=0)
        for t in seed_set:
            try:
                mem.add(t, "input", by="bench")
            except ValueError:
                pass
        n_mem = mem.stats()["confirmed"]
        ts, tw = evaluate(mem, inj_test)
        fs, fw = evaluate(mem, ben_test)
        rows.append({"remembered": n_mem, "recall_strong": ts / max(1, len(inj_test)),
                     "recall_any": tw / max(1, len(inj_test)), "fpr_strong": fs / max(1, len(ben_test)),
                     "fpr_any": fw / max(1, len(ben_test)), "fp_strong": fs, "fp_any": fw})
    # near-duplicates: test injections whose best match among ALL train injections is >= 0.9
    d = tempfile.mkdtemp()
    mem = AttackMemory(Store(os.path.join(d, "m.db")), refresh=0)
    for t in inj_train:
        try:
            mem.add(t, "input")
        except ValueError:
            pass
    dup = sum(1 for t in inj_test if (m := mem.match(t, "G1")) is not None and m.similarity >= 0.9)
    return {"name": name, "n_train_inj": len(inj_train), "n_test_inj": len(inj_test), "n_test_benign": len(ben_test),
            "near_dup": dup, "rows": rows}


def latency(sizes=(100, 1000, 5000), n=200, seed=1):
    """Median / p95 time of one G2 match (a ~600-character text) against a memory of N attacks."""
    rng = random.Random(seed)
    words = ("the assistant must send forward ignore previous instructions student grade course message file email "
             "calendar note admin system please routine password delete share account transfer money report "
             "deadline lecture homework exam question answer library meeting tomorrow").split()

    def text(k):
        return " ".join(rng.choice(words) for _ in range(k)) + f" {rng.randrange(10**6)}"

    out = []
    for size in sizes:
        d = tempfile.mkdtemp()
        mem = AttackMemory(Store(os.path.join(d, "m.db")), refresh=3600)
        st = mem.store
        now = time.time()
        with st.tx() as conn:
            for i in range(size):
                conn.execute("INSERT INTO attacks (fp, kind, status, label, text, origin, created_at, updated_at) "
                             "VALUES (?,?,?,?,?,?,?,?)", (f"fp{i}", "content", "confirmed", "instruction_injection",
                                                          text(60), "bench", now, now))
        t0 = time.perf_counter()
        mem._maybe_reload(force=True)
        load = time.perf_counter() - t0
        probes = [text(90) for _ in range(n)]
        ts = []
        for p in probes:
            t0 = time.perf_counter()
            mem.match(p, "G2")
            ts.append((time.perf_counter() - t0) * 1000)
        ts.sort()
        out.append({"size": size, "load_s": load, "p50_ms": statistics.median(ts), "p95_ms": ts[int(0.95 * (len(ts) - 1))]})
    return out


def markdown(results, lat):
    out = ["# Attack memory on public prompt-injection datasets", "",
           "Train-split injections remembered (all confirmed), test split matched at G1. `strong` = the memory would "
           "act (block at G1), `any` = act or ask for review. Character 5-gram containment, threshold 0.6, review "
           "0.45 (the defaults).", ""]
    for r in results:
        out += [f"## {r['name']}", "",
                f"{r['n_train_inj']} train injections · test: {r['n_test_inj']} injections, {r['n_test_benign']} benign "
                f"· {r['near_dup']} test injections are near-duplicates (≥ 0.9) of a train injection", "",
                "| attacks remembered | recall (strong) | recall (any) | false positives (strong) | false positives (any) |",
                "|---|---|---|---|---|"]
        for x in r["rows"]:
            out.append(f"| {x['remembered']} | {100 * x['recall_strong']:.1f}% | {100 * x['recall_any']:.1f}% | "
                       f"{100 * x['fpr_strong']:.2f}% ({x['fp_strong']}) | {100 * x['fpr_any']:.2f}% ({x['fp_any']}) |")
        out.append("")
    out += ["## Latency of one match (G2, ~600 characters)", "", "| attacks in memory | index build | median | p95 |",
            "|---|---|---|---|"]
    for x in lat:
        out.append(f"| {x['size']} | {x['load_s']:.2f} s | {x['p50_ms']:.2f} ms | {x['p95_ms']:.2f} ms |")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", action="append", choices=sorted(DATASETS), help="default: all")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "results" / "memory-pi.md"))
    a = ap.parse_args(argv)
    results = [bench(name) for name in (a.dataset or sorted(DATASETS))]
    md = markdown(results, latency())
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(md, encoding="utf-8")
    print(md)
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
