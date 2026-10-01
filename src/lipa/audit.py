"""
Stage 4: Deterministic Audit Reconciliation & State Machine

Provides the core data structures for LIPA's audit pipeline:
  - AuditStatus / IssueSeverity enums (canonical verdict vocabulary)
  - AuditIssue  — typed issue record with stage, code, location, and remediation hint
  - AuditVerdict — final verdict aggregating all stage results
  - IssueReporter — Unicode box-drawing human report + strict JSON machine payload

Blueprint Reference: Lines 600-750 (Local Ingress Pre-flight.md §5)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Verdict vocabulary
# ---------------------------------------------------------------------------

class AuditStatus(Enum):
    """Terminal state of the FSM after all three audit stages complete."""

    PASS    = "PASS"
    WARN    = "WARN"
    BLOCKED = "BLOCKED"


class IssueSeverity(Enum):
    """Severity classification aligned with the FSM transition rules.

    FATAL  → drives state to BLOCKED
    WARNING → drives state to WARN (unless already BLOCKED)
    INFO   → informational only; never changes verdict
    """

    INFO    = "INFO"
    WARNING = "WARNING"
    FATAL   = "FATAL"


# ---------------------------------------------------------------------------
# Issue record
# ---------------------------------------------------------------------------

@dataclass
class AuditIssue:
    """Typed issue record produced by any audit stage.

    Args:
        stage:            Originating stage label (e.g. ``"Topology"``,
                          ``"ContractDiffer"``, ``"SyntaxCheck"``).
        code:             Machine-readable error code (e.g.
                          ``"INGRESS_SECURITY_VIOLATION"``).
        severity:         IssueSeverity controlling verdict escalation.
        filepath:         Absolute path of the scanned source file.
        line:             1-indexed source line where the issue was detected.
        column:           0-indexed column offset.
        symbol:           Optional symbol name (function / class / module) at
                          the issue site.  ``None`` when not applicable.
        message:          Human-readable description of the issue.
        remediation_hint: Actionable suggestion for the developer.

    Raises:
        TypeError: Raised implicitly if callers supply wrong types (dataclass
                   does not coerce types at construction time).
    """

    stage: str
    code: str
    severity: IssueSeverity
    filepath: str
    line: int
    column: int
    symbol: Optional[str]
    message: str
    remediation_hint: str

    def to_dict(self) -> dict[str, object]:
        """Serialise the issue to a plain dict suitable for JSON output.

        Returns:
            dict with all fields; ``severity`` is the enum *value* string.
        """
        return {
            "stage":            self.stage,
            "code":             self.code,
            "severity":         self.severity.value,
            "filepath":         self.filepath,
            "line":             self.line,
            "column":           self.column,
            "symbol":           self.symbol,
            "message":          self.message,
            "remediation_hint": self.remediation_hint,
        }


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

@dataclass
class AuditVerdict:
    """Aggregated result of the full three-stage LIPA audit pipeline.

    Args:
        status:               Terminal FSM state (PASS / WARN / BLOCKED).
        execution_time_ms:    Wall-clock time for the entire audit in milliseconds.
        scanned_files_count:  Number of source files analysed in this run.
        issues:               All AuditIssue records collected across all stages.
        contract_diff_summary: Dict with ``symbols_added`` and ``symbols_removed``
                               lists populated during the contract-diffing stage.
                               Empty dict when no baseline was provided.
    """

    status: AuditStatus
    execution_time_ms: float
    scanned_files_count: int
    issues: list[AuditIssue] = field(default_factory=list)
    contract_diff_summary: dict[str, list[str]] = field(default_factory=dict)

    # Convenience filters --------------------------------------------------

    def fatal_issues(self) -> list[AuditIssue]:
        """Return only FATAL-severity issues from this verdict.

        Returns:
            Filtered list; may be empty.
        """
        return [i for i in self.issues if i.severity is IssueSeverity.FATAL]

    def warning_issues(self) -> list[AuditIssue]:
        """Return only WARNING-severity issues from this verdict.

        Returns:
            Filtered list; may be empty.
        """
        return [i for i in self.issues if i.severity is IssueSeverity.WARNING]

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dict for JSON reporting.

        Returns:
            dict with ``status`` as a string value and ``issues`` as a list
            of serialised issue dicts.
        """
        return {
            "status":                self.status.value,
            "execution_time_ms":     round(self.execution_time_ms, 3),
            "scanned_files_count":   self.scanned_files_count,
            "issues_count":          len(self.issues),
            "fatal_count":           len(self.fatal_issues()),
            "warning_count":         len(self.warning_issues()),
            "contract_diff_summary": self.contract_diff_summary,
            "issues":                [i.to_dict() for i in self.issues],
        }


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

class IssueReporter:
    """Produces human-readable Unicode-box reports and strict JSON payloads.

    Keeps formatting logic completely separate from verdict generation so that
    the core engine remains output-format agnostic.
    """

    # Severity → prefix symbols for the human report
    _SEVERITY_ICON: dict[IssueSeverity, str] = {
        IssueSeverity.FATAL:   "✖ FATAL  ",
        IssueSeverity.WARNING: "⚠ WARN   ",
        IssueSeverity.INFO:    "ℹ INFO   ",
    }

    # Status → header colour indicator (using ASCII box chars; works in all
    # terminals without ANSI escape code requirements)
    _STATUS_HEADER: dict[AuditStatus, str] = {
        AuditStatus.PASS:    "╔══════════════════════════════════════╗\n"
                             "║  ✔  LIPA VERDICT: PASS               ║\n"
                             "╚══════════════════════════════════════╝",
        AuditStatus.WARN:    "╔══════════════════════════════════════╗\n"
                             "║  ⚠  LIPA VERDICT: WARN               ║\n"
                             "╚══════════════════════════════════════╝",
        AuditStatus.BLOCKED: "╔══════════════════════════════════════╗\n"
                             "║  ✖  LIPA VERDICT: BLOCKED            ║\n"
                             "╚══════════════════════════════════════╝",
    }

    def generate_human_report(self, verdict: AuditVerdict) -> str:
        """Render a structured Unicode-box audit report for terminal output.

        Args:
            verdict: The AuditVerdict to render.

        Returns:
            Multi-line string suitable for ``print()`` or log capture.
        """
        lines: list[str] = []
        lines.append(self._STATUS_HEADER[verdict.status])
        lines.append("")
        lines.append(
            f"  Files scanned : {verdict.scanned_files_count}"
        )
        lines.append(
            f"  Execution time: {verdict.execution_time_ms:.2f} ms"
        )
        lines.append(
            f"  Issues found  : {len(verdict.issues)} "
            f"(✖ {len(verdict.fatal_issues())} fatal, "
            f"⚠ {len(verdict.warning_issues())} warnings)"
        )

        if verdict.contract_diff_summary:
            added   = verdict.contract_diff_summary.get("symbols_added", [])
            removed = verdict.contract_diff_summary.get("symbols_removed", [])
            lines.append(
                f"  Contract diff : +{len(added)} added, -{len(removed)} removed"
            )

        if verdict.issues:
            lines.append("")
            lines.append("  ┌─ Issues ─────────────────────────────────────────────────")
            for issue in verdict.issues:
                icon = self._SEVERITY_ICON.get(issue.severity, "? ")
                sym_label = f" [{issue.symbol}]" if issue.symbol else ""
                lines.append(
                    f"  │  {icon}{sym_label}  {issue.code}"
                )
                lines.append(
                    f"  │    Location  : {issue.filepath}:{issue.line}:{issue.column}"
                )
                lines.append(
                    f"  │    Message   : {issue.message}"
                )
                lines.append(
                    f"  │    Hint      : {issue.remediation_hint}"
                )
                lines.append("  │")
            lines.append(
                "  └──────────────────────────────────────────────────────────"
            )

        return "\n".join(lines)

    def generate_json_payload(self, verdict: AuditVerdict) -> str:
        """Serialise the verdict to a deterministic JSON string.

        Uses ``sort_keys=True`` and ``ensure_ascii=False`` so that the output
        is stable across runs and preserves Unicode characters in messages.

        Args:
            verdict: The AuditVerdict to serialise.

        Returns:
            Compact JSON string (no trailing newline).
        """
        return json.dumps(
            verdict.to_dict(),
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
