import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

from core.loop import run_audit_agent


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Autonomous AI Agent for DevOps Repository Auditing"
    )
    parser.add_argument(
        "--repo",
        "-repo",
        required=True,
        dest="repo",
        help="Public GitHub repository URL to inspect",
    )
    parser.add_argument(
        "--output",
        "-output",
        required=True,
        dest="output",
        help="Output file path for the machine-readable JSON report (e.g., report.json)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=15,
        help="Maximum reasoning/tool-call cycles before synthesizing report (default: 15)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    load_dotenv()

    try:
        args = parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1

    repo_url = args.repo.strip()
    output_path = Path(args.output).resolve()

    if not repo_url:
        print("Fatal Error: --repo argument cannot be empty.", file=sys.stderr)
        return 1

    try:
        report = run_audit_agent(repo_url=repo_url, max_iterations=args.max_iterations)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        json_payload = report.model_dump_json(indent=2)
        output_path.write_text(json_payload + "\n", encoding="utf-8")

        print(
            f"[Agent] Audit succeeded. Wrote {len(report.violations)} violation(s) to {output_path}",
            file=sys.stderr,
        )
        return 0

    except Exception as exc:
        print(f"Fatal Error during repository audit: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
