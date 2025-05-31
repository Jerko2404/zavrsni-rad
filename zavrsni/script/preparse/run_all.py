from __future__ import annotations

import subprocess
import sys
import pathlib


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("Usage: python run_all.py <folder_with_logs>")

    logs_dir = pathlib.Path(sys.argv[1]).resolve()
    preparer = pathlib.Path(__file__).with_name("parse_logs.py")

    if not preparer.exists():
        sys.exit("parse_logs.py not found in the same directory!")

    out_dir = logs_dir / "out"
    out_dir.mkdir(exist_ok=True)

    # Pick any extensions you need here
    log_files = sorted(list(logs_dir.glob("*.txt")) + list(logs_dir.glob("*.log")))
    if not log_files:
        sys.exit(f"No .txt or .log files found in {logs_dir}")

    for log_path in log_files:
        out_path = out_dir / f"{log_path.stem}.jsonl"
        cmd = [
            sys.executable,
            str(preparer),
            "-i",
            str(log_path),
            "-o",
            str(out_path),
        ]
        print(f"→ {log_path.name:<40} → out/{out_path.name}")
        subprocess.run(cmd, check=True)

    print(f"\n✓ Processed {len(log_files)} file(s). Outputs in: {out_dir}")


if __name__ == "__main__":
    main()
