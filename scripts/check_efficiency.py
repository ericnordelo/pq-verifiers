#!/usr/bin/env python3
"""Efficiency ratchet: fail if any tracked cost regresses; only ever lower the baseline.

`efficiency_baseline.json` pins the paired-subtraction cost (L2 gas and Cairo steps) of
every tracked benchmark pair. This script re-measures them (same method as
`run_bench.py`: sierra-gas run for L2 gas, cairo-steps run for steps) and compares:

  - any measurement ABOVE its baseline  -> regression, exit 1;
  - any measurement below its baseline  -> improvement, reported (run --update to lock);
  - equal                               -> ok.

Numbers are deterministic for a given source tree + toolchain (pinned in
`.tool-versions`), so the comparison is strict: no tolerance. `--update` rewrites
improved (lower) entries only — the baseline is a one-way ratchet. Raising an entry is
a deliberate human decision: edit the JSON in the same commit that justifies it.

Usage:
  python3 scripts/check_efficiency.py            # gate (CI runs this)
  python3 scripts/check_efficiency.py --update   # ratchet improved entries down
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BASELINE = os.path.join(ROOT, "efficiency_baseline.json")

sys.path.insert(0, HERE)
from run_bench import parse, run_snforge  # noqa: E402

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def measure(entries):
    print("Measuring (snforge sierra-gas mode) ...")
    sierra = parse(run_snforge([]))
    print("Measuring (snforge cairo-steps mode) ...")
    steps = parse(run_snforge(["--tracked-resource", "cairo-steps"]))

    measured = {}
    for name, e in entries.items():
        vs, bs = sierra.get(e["test"]), sierra.get(e["baseline"])
        vt, bt = steps.get(e["test"]), steps.get(e["baseline"])
        if not (vs and bs and vt and bt):
            print(f"{RED}missing measurements for '{name}' "
                  f"({e['test']} / {e['baseline']}){RESET}")
            sys.exit(2)
        measured[name] = {
            "l2_gas": vs["sierra_gas"] - bs["sierra_gas"],
            "steps": vt["steps"] - bt["steps"],
        }
    return measured


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update", action="store_true",
        help="lower baseline entries to improved measurements (never raises)",
    )
    args = parser.parse_args()

    data = json.load(open(BASELINE))
    entries = data["entries"]
    measured = measure(entries)

    regressions, improvements = [], []
    width = max(len(n) for n in entries)
    print(f"\n{'entry':<{width}}  {'metric':<7} {'baseline':>12} {'measured':>12}")
    for name, e in entries.items():
        for metric in ("l2_gas", "steps"):
            base, got = e[metric], measured[name][metric]
            if got > base:
                mark, color = "REGRESSION", RED
                regressions.append((name, metric, base, got))
            elif got < base:
                mark, color = "improved", GREEN
                improvements.append((name, metric, base, got))
            else:
                mark, color = "ok", ""
            print(f"{name:<{width}}  {metric:<7} {base:>12,} {got:>12,} "
                  f"{color}{mark}{RESET}")

    if regressions:
        print(f"\n{RED}{len(regressions)} regression(s). Efficiency is a one-way "
              f"ratchet: make the change at least cost-neutral, or justify raising "
              f"the baseline explicitly in this commit.{RESET}")
        sys.exit(1)

    if improvements:
        if args.update:
            for name, metric, _, got in improvements:
                entries[name][metric] = got
            with open(BASELINE, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            print(f"\n{GREEN}baseline ratcheted down "
                  f"({len(improvements)} entr{'y' if len(improvements) == 1 else 'ies'}) "
                  f"-> commit {os.path.relpath(BASELINE, ROOT)}{RESET}")
        else:
            print(f"\n{YELLOW}{len(improvements)} improvement(s) not locked in — "
                  f"run `make ratchet` and commit the baseline.{RESET}")
    else:
        print(f"\n{GREEN}all entries at baseline{RESET}")


if __name__ == "__main__":
    main()
