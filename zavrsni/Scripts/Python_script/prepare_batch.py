from __future__ import annotations

import os
import sys
import argparse
import importlib
from pathlib import Path

try:
    import prepare_single
except ModuleNotFoundError:
    sys.exit(
        "[ERROR] Cannot find 'prepare_single.py' in PYTHONPATH — make sure "
        "prepare_batch.py sits next to prepare_single.py or that the "
        "latter is importable."
    )


def iter_json_files(base_dir: Path):
    for p in base_dir.iterdir():
        if (
            p.is_file()
            and p.suffix.lower() == ".json"
            and not p.name.endswith("_placeholder.json")
        ):
            yield p


def process_file(src_path: Path, out_dir: Path) -> None:
    out_path = out_dir / f"{src_path.stem}_placeholder.json"

    events = prepare_single.load_events(src_path)
    processed = prepare_single.process(events)
    prepare_single.write_output(processed, out_path)

    print(f"[OK] {src_path.name} → {out_path.relative_to(out_dir.parent)}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Batch‑convert every JSON log inside a directory using prepare_single.py"
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=Path.cwd(),
        type=Path,
        help="Directory that contains .json logs (default: current working directory)",
    )

    ns = parser.parse_args(argv)
    base_dir: Path = ns.directory.resolve()

    if not base_dir.is_dir():
        sys.exit(f"[ERROR] Not a directory: {base_dir}")

    out_dir = base_dir / "out"
    out_dir.mkdir(exist_ok=True)

    files = list(iter_json_files(base_dir))
    if not files:
        print("[INFO] No .json files found to process — exiting.")
        return

    for fp in files:
        process_file(fp, out_dir)

    print(f"\nFinished: {len(files)} file(s) converted → {out_dir}\n")


if __name__ == "__main__":
    main()
