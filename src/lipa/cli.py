"""
CLI Entry Point — LIPA (Local Ingress Pre-flight Auditor)

Provides the unified command-line interface for the LIPA audit pipeline:

  lipa <file> [file …]  [--json] [--baseline FILE] [--target-version X.Y …]
                         [--telemetry PATH] [--workspace DIR] [--strict]

Blueprint Reference: Lines 752-850 (Local Ingress Pre-flight.md §8)
"""

from __future__ import annotations

import argparse
import json
import sys

# Reconfigure stdout to UTF-8 so Unicode box-drawing characters in
# IssueReporter render correctly regardless of the Windows codepage.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from pathlib import Path

from .audit import AuditStatus, IssueReporter
from .core import LocalIngressAuditor


def _build_parser() -> argparse.ArgumentParser:
    """Construct and return the CLI argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="lipa",
        description=(
            "LIPA — Local Ingress Pre-flight Auditor\n"
            "Zero-execution AST auditor for Python ingress safety."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="Python source file(s) to audit.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        dest="json_output",
        help="Emit strict JSON payload to stdout instead of the human report.",
    )
    parser.add_argument(
        "--baseline",
        metavar="BASELINE_FILE",
        default=None,
        help=(
            "Path to the previous version of the file used as the contract "
            "baseline for API diff detection.  Only valid for single-file audits."
        ),
    )
    parser.add_argument(
        "--target-version",
        metavar="X.Y",
        action="append",
        dest="target_versions",
        default=None,
        help=(
            "Python version the code must remain compatible with.  "
            "Repeat the flag to specify multiple targets.  "
            "Defaults to 3.11 through 3.15."
        ),
    )
    parser.add_argument(
        "--workspace",
        metavar="DIR",
        default=".",
        help=(
            "Root directory that defines the internal module namespace.  "
            "Defaults to the current working directory."
        ),
    )
    parser.add_argument(
        "--telemetry",
        metavar="PATH",
        default=None,
        help=(
            "Optional path for the JSONL telemetry log that records per-run "
            "verdict snapshots.  Disabled when omitted."
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help=(
            "Exit with code 2 for WARN verdicts in addition to code 1 for "
            "BLOCKED.  Default behaviour exits 0 on WARN."
        ),
    )
    return parser


def _parse_target_versions(raw: list[str] | None) -> set[tuple[int, int]]:
    """Parse ``X.Y`` version strings into a set of (major, minor) tuples.

    Args:
        raw: List of strings like ``["3.11", "3.12"]``, or ``None`` to use
             the default set (3.11 through 3.15 inclusive).

    Returns:
        Set of (major, minor) integer tuples.

    Raises:
        SystemExit: When a version string cannot be parsed.
    """
    if raw is None:
        return {(3, 11), (3, 12), (3, 13), (3, 14), (3, 15)}

    parsed: set[tuple[int, int]] = set()
    for ver_str in raw:
        parts = ver_str.strip().split(".")
        if len(parts) != 2:
            print(
                f"lipa: error: invalid --target-version '{ver_str}' — "
                f"expected format X.Y (e.g. 3.11)",
                file=sys.stderr,
            )
            sys.exit(2)
        try:
            parsed.add((int(parts[0]), int(parts[1])))
        except ValueError:
            print(
                f"lipa: error: invalid --target-version '{ver_str}' — "
                f"major and minor must be integers",
                file=sys.stderr,
            )
            sys.exit(2)
    return parsed


def main() -> None:
    """CLI entry point — parses arguments and runs the audit pipeline.

    Exit codes:
        0  All files PASS (or WARN without --strict).
        1  One or more files BLOCKED.
        2  One or more files WARN when --strict is set; or argument error.

    Raises:
        SystemExit: Always — on both success and failure.
    """
    parser = _build_parser()
    args = parser.parse_args()

    target_versions = _parse_target_versions(args.target_versions)
    workspace = Path(args.workspace).resolve()
    telemetry_path = Path(args.telemetry) if args.telemetry else None

    try:
        auditor = LocalIngressAuditor(
            workspace_root=workspace,
            target_versions=target_versions,
            telemetry_path=telemetry_path,
        )
    except ValueError as exc:
        print(f"lipa: error: {exc}", file=sys.stderr)
        sys.exit(2)

    # Load baseline source for single-file contract diffing
    baseline_source: str | None = None
    if args.baseline is not None:
        baseline_path = Path(args.baseline)
        if not baseline_path.is_file():
            print(
                f"lipa: error: baseline file not found: {args.baseline}",
                file=sys.stderr,
            )
            sys.exit(2)
        with open(baseline_path, "r", encoding="utf-8") as bfh:
            baseline_source = bfh.read()
        if len(args.files) > 1:
            print(
                "lipa: warning: --baseline is only meaningful for single-file "
                "audits; the baseline will be applied to every target file.",
                file=sys.stderr,
            )

    reporter = IssueReporter()
    overall_blocked = False
    overall_warned  = False

    for file_str in args.files:
        file_path = Path(file_str).resolve()
        if not file_path.is_file():
            print(f"lipa: error: file not found: {file_str}", file=sys.stderr)
            overall_blocked = True
            continue

        verdict = auditor.audit_ingress_file(
            file_path,
            baseline_source=baseline_source,
        )

        if args.json_output:
            print(reporter.generate_json_payload(verdict))
        else:
            print(reporter.generate_human_report(verdict))

        if verdict.status is AuditStatus.BLOCKED:
            overall_blocked = True
        elif verdict.status is AuditStatus.WARN:
            overall_warned = True

    if overall_blocked:
        sys.exit(1)
    if args.strict and overall_warned:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
