"""
LIPA MCP Server — Model Context Protocol interface for the LIPA audit pipeline.

Exposes three tools via the FastMCP stdio transport so any MCP-compatible AI
assistant (Claude Desktop, Cursor, Windsurf, Gemini Code Assist, etc.) can
call LIPA's AST auditor as a native tool call without any subprocess juggling.

Tools registered:
  • audit_file       — Full pipeline audit on a single .py file
  • audit_workspace  — Batch audit across all .py files in a directory
  • get_lipa_info    — Server capabilities and supported Python target versions

Transport: stdio (default) — compatible with all MCP clients out of the box.

Usage:
    python -m lipa.mcp_server          # run with stdio (standard MCP client setup)
    fastmcp dev src/lipa/mcp_server.py # interactive dev inspector
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# FastMCP is the only non-stdlib dependency in this entire project.
# It must be installed in the same environment as LIPA:
#   pip install fastmcp
try:
    from fastmcp import FastMCP
except ImportError as _err:
    sys.exit(
        "ERROR: fastmcp is not installed.\n"
        "Run: pip install fastmcp\n"
        f"Original error: {_err}"
    )

from .audit import AuditStatus, IssueReporter
from .core import LocalIngressAuditor

# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------

mcp: FastMCP = FastMCP(
    name="LIPA",
    instructions=(
        "LIPA (Local Ingress Pre-flight Auditor) audits Python source files at "
        "the AST level before they are executed or merged. It runs a 4-stage "
        "pipeline: import topology scanning, API contract diffing, "
        "PEP-gated syntax checking, and FSM verdict collapse. "
        "Use audit_file to check a single .py file, audit_workspace for a "
        "whole directory, and get_lipa_info for server metadata."
    ),
)

# ---------------------------------------------------------------------------
# Tool: audit_file
# ---------------------------------------------------------------------------

@mcp.tool()
def audit_file(
    path: str,
    target_version: str = "3.12",
    baseline_path: Optional[str] = None,
    strict: bool = False,
) -> dict:
    """Audit a single Python source file through the full LIPA pipeline.

    Runs all four stages (ImportBoundaryScanner → SignatureExtractor →
    SyntaxVersionAuditor → FSM Verdict Collapse) and returns a structured
    verdict with all findings.

    Args:
        path:           Absolute or relative path to the .py file to audit.
        target_version: Python version compatibility target, e.g. "3.11",
                        "3.12", or "3.13". Controls which PEP 594 removals
                        and PEP-gated syntax checks are active. Default "3.12".
        baseline_path:  Optional path to a previously audited .py file to use
                        as the contract baseline. When provided, Stage 2
                        (ContractDiffer) activates and detects breaking API
                        changes such as symbol removal, TypeVar bound mutation,
                        or dataclass field reordering.
        strict:         When True, WARN-level findings escalate the verdict to
                        BLOCKED. Default False.

    Returns:
        A dict with keys:
          verdict        — "PASS", "WARN", or "BLOCKED"
          file           — audited file path (resolved absolute)
          finding_count  — total number of findings
          blocked_count  — number of FATAL/BLOCKED findings
          warn_count     — number of WARNING/WARN findings
          duration_ms    — wall-clock duration in milliseconds
          findings       — list of finding dicts, each with:
                             stage, code, severity, line, column, message,
                             remediation_hint
    """
    file_path = Path(path).resolve()
    if not file_path.exists():
        return {
            "verdict": "ERROR",
            "file": str(file_path),
            "error": f"File not found: {file_path}",
        }
    if not file_path.suffix == ".py":
        return {
            "verdict": "ERROR",
            "file": str(file_path),
            "error": "Only .py files are supported.",
        }

    major, minor = _parse_version(target_version)
    workspace_root = file_path.parent
    auditor = LocalIngressAuditor(
        workspace_root=workspace_root,
        target_versions={(major, minor)},
    )

    baseline_source: Optional[str] = None
    if baseline_path:
        bp = Path(baseline_path).resolve()
        if bp.exists():
            baseline_source = bp.read_text(encoding="utf-8")

    verdict = auditor.audit_ingress_file(file_path, baseline_source=baseline_source)

    # Apply strict escalation at the MCP layer (mirrors CLI --strict logic).
    effective_status = verdict.status
    if strict and effective_status == AuditStatus.WARN:
        effective_status = AuditStatus.BLOCKED

    findings = [
        {
            "stage": issue.stage,
            "code": issue.code,
            "severity": issue.severity.value,
            "line": issue.line,
            "column": issue.column,
            "symbol": issue.symbol,
            "message": issue.message,
            "remediation_hint": issue.remediation_hint,
        }
        for issue in verdict.issues
    ]

    blocked = sum(1 for f in findings if f["severity"] == "FATAL")
    warned = sum(1 for f in findings if f["severity"] == "WARNING")

    return {
        "verdict": effective_status.value,
        "file": str(file_path),
        "target_version": target_version,
        "strict": strict,
        "finding_count": len(findings),
        "blocked_count": blocked,
        "warn_count": warned,
        "duration_ms": round(verdict.execution_time_ms, 2),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Tool: audit_workspace
# ---------------------------------------------------------------------------

@mcp.tool()
def audit_workspace(
    workspace_dir: str,
    target_version: str = "3.12",
    strict: bool = False,
    max_files: int = 50,
) -> dict:
    """Batch-audit all Python files in a directory through the LIPA pipeline.

    Recursively discovers all *.py files under workspace_dir and runs the
    full 4-stage pipeline on each. Circular import detection (Stage 1)
    operates across the entire workspace graph, making cross-file cycle
    detection possible.

    Args:
        workspace_dir:  Absolute or relative path to the root directory to scan.
        target_version: Python version compatibility target (e.g. "3.12").
        strict:         When True, WARN findings escalate to BLOCKED. Default False.
        max_files:      Safety cap on the number of files audited in a single
                        call. Default 50. Raise if you need to scan larger trees.

    Returns:
        A dict with keys:
          overall_verdict — "PASS", "WARN", or "BLOCKED" (worst across all files)
          workspace       — resolved absolute path of the scanned directory
          target_version  — the Python version audited against
          files_audited   — number of files processed
          total_findings  — sum of all findings across all files
          blocked_count   — total FATAL findings
          warn_count      — total WARNING findings
          duration_ms     — total wall-clock time in milliseconds
          file_results    — list of per-file result dicts (same schema as audit_file)
    """
    import time as _time

    workspace = Path(workspace_dir).resolve()
    if not workspace.exists() or not workspace.is_dir():
        return {
            "overall_verdict": "ERROR",
            "workspace": str(workspace),
            "error": f"Directory not found or not a directory: {workspace}",
        }

    py_files = sorted(workspace.rglob("*.py"))
    # Exclude venv and cache directories deterministically.
    py_files = [
        p for p in py_files
        if not any(
            part in {".venv", ".venv-linux", "venv", "__pycache__", ".pytest_cache"}
            for part in p.parts
        )
    ]

    if len(py_files) > max_files:
        py_files = py_files[:max_files]

    major, minor = _parse_version(target_version)
    auditor = LocalIngressAuditor(
        workspace_root=workspace,
        target_versions={(major, minor)},
    )

    t_start = _time.perf_counter()
    file_results: list[dict] = []
    overall_blocked = False
    overall_warned = False
    total_findings = 0
    total_blocked = 0
    total_warned = 0

    for fp in py_files:
        verdict = auditor.audit_ingress_file(fp)

        effective_status = verdict.status
        if strict and effective_status == AuditStatus.WARN:
            effective_status = AuditStatus.BLOCKED

        if effective_status == AuditStatus.BLOCKED:
            overall_blocked = True
        elif effective_status == AuditStatus.WARN:
            overall_warned = True

        findings = [
            {
                "stage": issue.stage,
                "code": issue.code,
                "severity": issue.severity.value,
                "line": issue.line,
                "column": issue.column,
                "symbol": issue.symbol,
                "message": issue.message,
                "remediation_hint": issue.remediation_hint,
            }
            for issue in verdict.issues
        ]
        b = sum(1 for f in findings if f["severity"] == "FATAL")
        w = sum(1 for f in findings if f["severity"] == "WARNING")
        total_findings += len(findings)
        total_blocked += b
        total_warned += w

        file_results.append({
            "verdict": effective_status.value,
            "file": str(fp),
            "finding_count": len(findings),
            "blocked_count": b,
            "warn_count": w,
            "duration_ms": round(verdict.execution_time_ms, 2),
            "findings": findings,
        })

    duration_ms = round((_time.perf_counter() - t_start) * 1000, 2)

    if overall_blocked:
        overall_verdict = "BLOCKED"
    elif overall_warned:
        overall_verdict = "WARN"
    else:
        overall_verdict = "PASS"

    return {
        "overall_verdict": overall_verdict,
        "workspace": str(workspace),
        "target_version": target_version,
        "strict": strict,
        "files_audited": len(file_results),
        "total_findings": total_findings,
        "blocked_count": total_blocked,
        "warn_count": total_warned,
        "duration_ms": duration_ms,
        "file_results": file_results,
    }


# ---------------------------------------------------------------------------
# Tool: get_lipa_info
# ---------------------------------------------------------------------------

@mcp.tool()
def get_lipa_info() -> dict:
    """Return LIPA server metadata, supported features, and usage hints.

    Use this tool first to understand what LIPA can audit and how to
    interpret its verdicts before calling audit_file or audit_workspace.

    Returns:
        A dict with keys:
          name             — "LIPA"
          version          — package version string
          description      — one-line description
          tools            — list of available tool names
          supported_python — list of supported target version strings
          verdicts         — description of each possible verdict
          pipeline_stages  — names and descriptions of the 4 audit stages
    """
    return {
        "name": "LIPA",
        "version": "1.0.0",
        "description": (
            "Zero-Execution AST Safety Gate for Python Ingress Code. "
            "Audits .py files at the AST level before any execution occurs."
        ),
        "tools": ["audit_file", "audit_workspace", "get_lipa_info"],
        "supported_python_targets": [
            "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"
        ],
        "verdicts": {
            "PASS":    "All stages cleared — file is safe to merge (exit 0).",
            "WARN":    "Soft issues detected — advisory only, safe by default (exit 0). "
                       "Escalates to BLOCKED when strict=True.",
            "BLOCKED": "Hard violation detected — do NOT merge (exit 1).",
        },
        "pipeline_stages": {
            "1_ImportBoundaryScanner": (
                "Builds a directed import graph and runs Tarjan SCC to detect "
                "circular import chains. Also checks stdlib boundary violations, "
                "wildcard imports, and builtin shadowing."
            ),
            "2_ContractDiffer": (
                "Activated when baseline_path is supplied. Compares the public API "
                "surface (symbols, TypeVar bounds, dataclass fields, @final classes) "
                "against the baseline to detect breaking changes."
            ),
            "3_SyntaxVersionAuditor": (
                "AST-walks every node to enforce 17+ PEP-gated rules including "
                "security violations (eval/exec/pickle/subprocess), mutable defaults, "
                "implicit encoding, async blocking calls, PEP 594 removals, and more."
            ),
            "4_FSMVerdictCollapse": (
                "Aggregates all findings into a deterministic PASS/WARN/BLOCKED "
                "verdict with standard exit codes and optional JSON output."
            ),
        },
    }


# ---------------------------------------------------------------------------
# Version parsing helper
# ---------------------------------------------------------------------------

def _parse_version(version_str: str) -> tuple[int, int]:
    """Parse a 'major.minor' string into a (major, minor) int tuple.

    Args:
        version_str: Version string such as "3.12" or "3.13".

    Returns:
        Tuple of (major, minor) integers.

    Raises:
        ValueError: If the string is not in 'major.minor' format.
    """
    parts = version_str.split(".")
    if len(parts) < 2:
        raise ValueError(
            f"target_version must be 'major.minor' (e.g. '3.12'), got: {version_str!r}"
        )
    return int(parts[0]), int(parts[1])


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # stdio transport — MCP clients connect via stdin/stdout.
    mcp.run()
