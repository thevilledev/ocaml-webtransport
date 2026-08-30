#!/usr/bin/env python3
"""Generates the QPACK static table and HPACK Huffman table as OCaml source.

Usage: gen_tables.py <rfc7541.txt> <rfc9204.txt> <outdir>

Run manually when regenerating; outputs are committed. Fetch inputs from
https://www.rfc-editor.org/rfc/rfc7541.txt and .../rfc9204.txt.
"""
import re
import sys

rfc7541, rfc9204, outdir = sys.argv[1], sys.argv[2], sys.argv[3]

# --- RFC 7541 Appendix B: Huffman code (257 symbols incl. EOS) ---
huff = {}
line_re = re.compile(r"\(\s*(\d+)\)\s+[|01]+\s+([0-9a-f]+)\s+\[\s*(\d+)\]\s*$")
for line in open(rfc7541):
    m = line_re.search(line)
    if m:
        sym, code, ln = int(m.group(1)), int(m.group(2), 16), int(m.group(3))
        huff[sym] = (code, ln)
assert len(huff) == 257, f"expected 257 huffman symbols, got {len(huff)}"
assert huff[256] == (0x3FFFFFFF, 30), "EOS mismatch"

with open(f"{outdir}/huffman_table.ml", "w") as f:
    f.write("(* Generated from RFC 7541 Appendix B by gen/gen_tables.py."
            " Do not edit. *)\n\n")
    f.write("let codes =\n  [|\n")
    for i in range(257):
        f.write(f"    0x{huff[i][0]:x};\n")
    f.write("  |]\n\nlet lengths =\n  [|\n")
    for i in range(257):
        f.write(f"    {huff[i][1]};\n")
    f.write("  |]\n")

# --- RFC 9204 Appendix A: static table (indices 0..98) ---
lines = open(rfc9204).read().splitlines()
start = next(i for i, l in enumerate(lines)
             if l.startswith("Appendix A.") and "Static Table" in l)
end = next(i for i, l in enumerate(lines)
           if i > start and l.startswith("Appendix B."))
rows = []
row_re = re.compile(r"^\s*\|(.*)\|(.*)\|(.*)\|\s*$")
for line in lines[start:end]:
    m = row_re.match(line)
    if not m:
        continue
    idx, name, value = (c.strip() for c in m.groups())
    if idx == "Index" or (idx and set(idx) <= set("=-+")):
        continue
    if idx.isdigit():
        assert int(idx) == len(rows), f"index gap at {idx}"
        rows.append([name, value])
    elif idx == "" and (name or value):
        # wrapped row: continuation of the previous entry's cells
        if name:
            rows[-1][0] += " " + name
        if value:
            rows[-1][1] += " " + value
assert len(rows) == 99, f"expected 99 static entries, got {len(rows)}"
assert rows[0] == [":authority", ""]
assert rows[85][1] == "script-src 'none'; object-src 'none'; base-uri 'none'"


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


with open(f"{outdir}/static_table_data.ml", "w") as f:
    f.write("(* Generated from RFC 9204 Appendix A by gen/gen_tables.py."
            " Do not edit. *)\n\n")
    f.write("let entries =\n  [|\n")
    for name, value in rows:
        f.write(f'    ("{esc(name)}", "{esc(value)}");\n')
    f.write("  |]\n")

print(f"wrote {outdir}/huffman_table.ml ({len(huff)} symbols) and "
      f"{outdir}/static_table_data.ml ({len(rows)} entries)")
