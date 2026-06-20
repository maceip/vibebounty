"""Quick structural inspection of the bug-bounty corpus parquet.

Run with uv so we don't depend on the project venv's interpreter:
    uv run --with pandas --with pyarrow python data/inspect_parquet.py
"""
import json
import sys
from pathlib import Path

import pandas as pd

PARQUET = Path(__file__).resolve().parent / "corpus" / "bugbounty_reports.parquet"


def main() -> None:
    df = pd.read_parquet(PARQUET)
    print("=" * 70)
    print(f"file: {PARQUET}")
    print(f"rows: {len(df):,}   cols: {len(df.columns)}")
    print("=" * 70)
    print("\n--- columns / dtypes ---")
    for c in df.columns:
        nn = df[c].notna().sum()
        print(f"  {c:<28} {str(df[c].dtype):<12} non-null={nn:,}")

    # Categorical-ish columns: show value counts.
    print("\n--- value counts (low-cardinality cols) ---")
    for c in df.columns:
        try:
            nun = df[c].nunique(dropna=True)
        except TypeError:
            continue
        if 1 <= nun <= 40:
            print(f"\n[{c}] ({nun} unique)")
            print(df[c].value_counts(dropna=False).head(40).to_string())

    # Text length stats for big text columns.
    print("\n--- text length (chars) for object cols ---")
    for c in df.columns:
        if df[c].dtype == object:
            lens = df[c].dropna().astype(str).str.len()
            if len(lens):
                print(f"  {c:<28} min={lens.min():>6}  med={int(lens.median()):>7}  "
                      f"max={lens.max():>8}  mean={int(lens.mean()):>7}")

    print("\n--- 3 sample rows (truncated) ---")
    for i, (_, row) in enumerate(df.head(3).iterrows()):
        print(f"\n========== row {i} ==========")
        for c in df.columns:
            v = row[c]
            s = "" if v is None else str(v)
            if len(s) > 600:
                s = s[:600] + f" ...[+{len(s) - 600} chars]"
            print(f"  {c}: {s}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        raise
