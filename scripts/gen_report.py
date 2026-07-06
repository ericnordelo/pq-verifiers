#!/usr/bin/env python3
"""Generate a self-contained HTML report (and summary.md) from results/results.json.

No external/network dependencies: inline CSS, HTML-div bar charts, and a tiny inline
sort script. Open results/report.html in any browser or share the single file.
"""
import argparse
import html
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS_DIR = os.path.join(ROOT, "results")

CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  margin: 0; padding: 2rem; line-height: 1.6; color: #1a1a1a; background: #fafafa; }
.wrap { max-width: 1040px; margin: 0 auto; }
h1 { font-size: 24px; font-weight: 600; margin: 0 0 4px; }
h2 { font-size: 18px; font-weight: 600; margin: 2.25rem 0 .75rem; }
.sub { color: #666; font-size: 14px; margin: 0 0 1.5rem; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px,1fr)); gap: 12px; margin: 1.25rem 0; }
.card { background: #fff; border: 1px solid #e6e6e6; border-radius: 10px; padding: .85rem 1rem; }
.card .l { font-size: 12px; color: #777; text-transform: uppercase; letter-spacing: .03em; }
.card .v { font-size: 22px; font-weight: 600; margin-top: 2px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; background: #fff;
  border: 1px solid #e6e6e6; border-radius: 10px; overflow: hidden; }
th, td { text-align: right; padding: 9px 12px; border-bottom: 1px solid #f0f0f0; }
th:first-child, td:first-child { text-align: left; }
th { background: #f6f6f6; font-weight: 600; cursor: pointer; user-select: none; white-space: nowrap; }
th:hover { background: #efefef; }
tr:last-child td { border-bottom: none; }
.mono { font-variant-numeric: tabular-nums; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.badge { display: inline-block; font-size: 12px; padding: 2px 8px; border-radius: 6px; font-weight: 500; }
.ok { background: #e6f4ea; color: #1d6f3f; }
.no { background: #fdecea; color: #a3281f; }
.pending { background: #fff4e0; color: #8a5a0b; }
.barrow { display: grid; grid-template-columns: 200px 1fr 150px; align-items: center; gap: 12px; margin: 6px 0; }
.barlabel { font-size: 13px; color: #333; }
.track { background: #f0f0f0; border-radius: 5px; height: 18px; overflow: hidden; }
.fill { height: 100%; border-radius: 5px; }
.barval { font-size: 13px; color: #555; text-align: right; }
.note { color: #666; font-size: 13px; }
details { margin: .5rem 0; } summary { cursor: pointer; font-size: 14px; color: #444; }
footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid #e6e6e6; color: #777; font-size: 13px; }
code { background: #f0f0f0; padding: 1px 5px; border-radius: 4px; font-size: 13px; }
"""

SORT_JS = """
function sortTable(t, col, numeric) {
  var tbody = t.tBodies[0], rows = Array.prototype.slice.call(tbody.rows);
  var dir = t.getAttribute('data-dir-' + col) === 'asc' ? -1 : 1;
  t.setAttribute('data-dir-' + col, dir === 1 ? 'asc' : 'desc');
  rows.sort(function(a, b) {
    var x = a.cells[col].getAttribute('data-v'), y = b.cells[col].getAttribute('data-v');
    if (numeric) return (parseFloat(x) - parseFloat(y)) * dir;
    return x.localeCompare(y) * dir;
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
}
"""


def esc(x):
    return html.escape(str(x))


def fmt(n):
    return f"{n:,}"


def bar_row(label, value, maxv, color, value_text):
    pct = 0 if maxv <= 0 else max(1.0, round(100 * value / maxv, 2))
    return (
        f'<div class="barrow"><div class="barlabel">{esc(label)}</div>'
        f'<div class="track"><div class="fill" style="width:{pct}%;background:{color}"></div></div>'
        f'<div class="barval mono">{esc(value_text)}</div></div>'
    )


def build_html(data):
    meta = data["metadata"]
    schemes = data["schemes"]
    measured = [s for s in schemes if s.get("measured")]
    pending = [s for s in schemes if not s.get("measured")]
    caps = meta["caps"]

    max_gas = max([s["verify_l2_gas"] for s in measured], default=1)
    max_steps = max([s["verify_steps"] for s in measured], default=1)
    max_foot = max([s["sig_felts"] + s["pubkey_felts"] for s in schemes], default=1)

    parts = []
    parts.append(f"<style>{CSS}</style>")
    parts.append('<div class="wrap">')
    parts.append("<h1>Post-quantum signature verifiers &mdash; Starknet benchmark</h1>")
    parts.append(
        f'<p class="sub">Generated {esc(meta["generated"])} &middot; '
        f'scarb {esc(meta["toolchain"]["scarb"])}, snforge {esc(meta["toolchain"]["snforge"])} '
        f'&middot; cost of verifying one signature inside an account validation.</p>'
    )

    # Metric cards
    parts.append('<div class="cards">')
    parts.append(f'<div class="card"><div class="l">Measured</div><div class="v">{len(measured)}</div></div>')
    parts.append(f'<div class="card"><div class="l">Pending</div><div class="v">{len(pending)}</div></div>')
    parts.append(f'<div class="card"><div class="l">Validate gas cap</div><div class="v">{caps["validate_max_l2_gas"]//1_000_000}M</div></div>')
    parts.append(f'<div class="card"><div class="l">Validate step cap</div><div class="v">{caps["validate_max_steps"]//1000}k</div></div>')
    parts.append("</div>")

    # Measured table
    parts.append("<h2>Measured verifiers</h2>")
    if measured:
        parts.append('<table id="t"><thead><tr>'
                     '<th onclick="sortTable(t,0,false)">Scheme</th>'
                     '<th onclick="sortTable(t,1,false)">Family</th>'
                     '<th onclick="sortTable(t,2,true)">L2 gas</th>'
                     '<th onclick="sortTable(t,3,true)">% gas cap</th>'
                     '<th onclick="sortTable(t,4,true)">Steps</th>'
                     '<th onclick="sortTable(t,5,true)">% step cap</th>'
                     '<th onclick="sortTable(t,6,true)">Sig (felts)</th>'
                     '<th onclick="sortTable(t,7,true)">PubKey (felts)</th>'
                     '<th onclick="sortTable(t,8,true)">Calldata L2 gas</th>'
                     '<th onclick="sortTable(t,9,false)">Fits caps</th>'
                     "</tr></thead><tbody>")
        for s in measured:
            fits = s["fits_gas_cap"] and s["fits_step_cap"]
            badge = '<span class="badge ok">yes</span>' if fits else '<span class="badge no">no</span>'
            parts.append(
                "<tr>"
                f'<td data-v="{esc(s["label"])}">{esc(s["label"])}</td>'
                f'<td data-v="{esc(s["family"])}">{esc(s["family"])}</td>'
                f'<td class="mono" data-v="{s["verify_l2_gas"]}">{fmt(s["verify_l2_gas"])}</td>'
                f'<td class="mono" data-v="{s["pct_of_gas_cap"]}">{s["pct_of_gas_cap"]}%</td>'
                f'<td class="mono" data-v="{s["verify_steps"]}">{fmt(s["verify_steps"])}</td>'
                f'<td class="mono" data-v="{s["pct_of_step_cap"]}">{s["pct_of_step_cap"]}%</td>'
                f'<td class="mono" data-v="{s["sig_felts"]}">{s["sig_felts"]}</td>'
                f'<td class="mono" data-v="{s["pubkey_felts"]}">{s["pubkey_felts"]}</td>'
                f'<td class="mono" data-v="{s["calldata_l2_gas"]}">{fmt(s["calldata_l2_gas"])}</td>'
                f'<td data-v="{fits}">{badge}</td>'
                "</tr>"
            )
        parts.append("</tbody></table>")

        # Charts
        parts.append("<h2>Verification L2 gas (relative)</h2>")
        for s in measured:
            parts.append(bar_row(s["label"], s["verify_l2_gas"], max_gas, "#185FA5",
                                  f'{fmt(s["verify_l2_gas"])}  ({s["pct_of_gas_cap"]}% cap)'))
        parts.append("<h2>Verification steps (relative)</h2>")
        for s in measured:
            parts.append(bar_row(s["label"], s["verify_steps"], max_steps, "#0F6E56",
                                  f'{fmt(s["verify_steps"])}  ({s["pct_of_step_cap"]}% cap)'))

        # Builtin breakdown + per-function step attribution (cairo-profiler)
        parts.append("<h2>Where the cost goes</h2>")
        for s in measured:
            b = s.get("verify_builtins", {})
            inner = ", ".join(f"{k}: {v}" for k, v in sorted(b.items())) if b else "none"
            parts.append(f'<p class="note"><b>{esc(s["label"])}</b> &mdash; builtins: {esc(inner)}</p>')
            prof = [f for f in s.get("verify_profile", []) if not f.get("harness")]
            if prof:
                parts.append('<details><summary>step attribution (top functions inside verify)</summary>'
                             '<table><thead><tr><th>Function</th><th>Steps (flat)</th><th>% of test</th>'
                             "</tr></thead><tbody>")
                for fn in prof[:8]:
                    parts.append(
                        f'<tr><td style="text-align:left" class="mono">{esc(fn["function"])}</td>'
                        f'<td class="mono">{fmt(fn["flat_steps"])}</td>'
                        f'<td class="mono">{fn["flat_pct"]}%</td></tr>'
                    )
                parts.append("</tbody></table></details>")
    else:
        parts.append('<p class="note">No measured verifiers yet.</p>')

    # Realistic validation cost (in-__validate__) + class size
    val = [s for s in measured if "validate_l2_gas" in s]
    if val:
        parts.append("<h2>Realistic cost in __validate__ (deploy + call, baseline-subtracted)</h2>")
        parts.append('<p class="note">Adds call dispatch, tx-info read (signature deserialization) '
                     "and storage read on top of bare verification &mdash; the cost an account "
                     "actually pays during validation.</p>")
        parts.append('<table><thead><tr><th>Scheme</th><th>__validate__ L2 gas</th>'
                     '<th>% gas cap</th><th>Steps</th><th>% step cap</th>'
                     '<th>Bare verify L2 gas</th><th>Class (bytes)</th><th>Fits caps</th>'
                     "</tr></thead><tbody>")
        for s in val:
            fits = ('<span class="badge ok">yes</span>' if s.get("validate_fits")
                    else '<span class="badge no">no</span>')
            cb = f'{s["class_bytes"]:,}' if "class_bytes" in s else "&mdash;"
            parts.append(
                "<tr>"
                f'<td>{esc(s["label"])}</td>'
                f'<td class="mono">{fmt(s["validate_l2_gas"])}</td>'
                f'<td class="mono">{s["validate_pct_of_gas_cap"]}%</td>'
                f'<td class="mono">{fmt(s["validate_steps"])}</td>'
                f'<td class="mono">{s["validate_pct_of_step_cap"]}%</td>'
                f'<td class="mono">{fmt(s["verify_l2_gas"])}</td>'
                f'<td class="mono">{cb}</td>'
                f"<td>{fits}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    # Footprint chart (all schemes, including pending — sizes are known from the encoding)
    parts.append("<h2>On-chain footprint (signature + public key, felts)</h2>")
    for s in schemes:
        foot = s["sig_felts"] + s["pubkey_felts"]
        parts.append(bar_row(s["label"], foot, max_foot, "#D85A30",
                              f'{foot} felts ({s["sig_felts"]}+{s["pubkey_felts"]})'))

    # Pending
    parts.append("<h2>Pending implementation</h2>")
    parts.append('<table><thead><tr><th>Scheme</th><th>Family</th><th>NIST cat</th>'
                 '<th>Standardized</th><th>On-chain hash</th><th>Status</th></tr></thead><tbody>')
    for s in pending:
        parts.append(
            "<tr>"
            f'<td>{esc(s["label"])}</td><td>{esc(s["family"])}</td>'
            f'<td class="mono">{esc(s["nist_category"])}</td>'
            f'<td>{esc(s["standardized"])}</td><td>{esc(s["on_chain_hash"])}</td>'
            f'<td><span class="badge pending">stub</span></td>'
            "</tr>"
        )
    parts.append("</tbody></table>")
    for s in pending:
        parts.append(f'<p class="note"><b>{esc(s["label"])}</b> &mdash; {esc(s["notes"])}</p>')

    # Footer
    gt = meta["gas_table_l2"]
    gt_str = ", ".join(f"{k}={v}" for k, v in gt.items())
    parts.append("<footer>")
    parts.append(f'<p><b>Method.</b> {esc(meta["method"])}.</p>')
    parts.append(f'<p><b>Caps.</b> validate: {fmt(caps["validate_max_steps"])} steps / '
                 f'{fmt(caps["validate_max_l2_gas"])} L2 gas. Calldata: '
                 f'{meta["l2_gas_per_calldata_felt"]:,} L2 gas/felt.</p>')
    parts.append(f'<p><b>L2 gas table.</b> <span class="mono">{esc(gt_str)}</span></p>')
    parts.append("</footer></div>")
    parts.append(f"<script>{SORT_JS}</script>")
    return "\n".join(parts)


def build_md(data):
    schemes = data["schemes"]
    measured = [s for s in schemes if s.get("measured")]
    lines = ["# PQ verifier benchmark summary", "",
             f"_Generated {data['metadata']['generated']}._", ""]
    if measured:
        lines += ["| Scheme | L2 gas | % gas cap | Steps | % step cap | Sig+PK felts | Fits caps |",
                  "|---|--:|--:|--:|--:|--:|:--:|"]
        for s in measured:
            fits = "yes" if (s["fits_gas_cap"] and s["fits_step_cap"]) else "no"
            lines.append(
                f'| {s["label"]} | {s["verify_l2_gas"]:,} | {s["pct_of_gas_cap"]}% | '
                f'{s["verify_steps"]:,} | {s["pct_of_step_cap"]}% | '
                f'{s["sig_felts"] + s["pubkey_felts"]} | {fits} |'
            )
    lines += ["", "## Pending implementation", ""]
    for s in schemes:
        if not s.get("measured"):
            lines.append(f'- **{s["label"]}** ({s["family"]}) — {s["notes"]}')
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Generate the benchmark HTML report.")
    parser.add_argument("--results", default=os.path.join(RESULTS_DIR, "results.json"))
    args = parser.parse_args()

    data = json.load(open(args.results))
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(os.path.join(RESULTS_DIR, "report.html"), "w") as f:
        f.write("<!doctype html><meta charset=utf-8>\n" + build_html(data))
    with open(os.path.join(RESULTS_DIR, "summary.md"), "w") as f:
        f.write(build_md(data))
    print(f"Wrote {os.path.join(RESULTS_DIR, 'report.html')}")
    print(f"Wrote {os.path.join(RESULTS_DIR, 'summary.md')}")


if __name__ == "__main__":
    main()
