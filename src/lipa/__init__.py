"""
Local Ingress Pre-flight Auditor (LIPA)

Zero-dependency, zero-execution AST-based security and compatibility auditor
for Python ingress code.  Requires Python 3.11+.

Subsystems:
  topology  Stage 1 — Import graph, Tarjan SCC, builtin shadowing
  contract  Stage 2 — Public API signature diffing, @final, TypeVar bounds
  syntax    Stage 3 — Version gating, security shield, PEP compliance
  audit     Stage 4 — Data types: AuditIssue, AuditVerdict, IssueReporter
  core      Unified Driver — LocalIngressAuditor, IncrementalASTCache
  cli       CLI entry point

Usage:
    from lipa.core import LocalIngressAuditor
    from pathlib import Path

    auditor = LocalIngressAuditor(
        workspace_root=Path("."),
        target_versions={(3, 11), (3, 12), (3, 13)},
    )
    verdict = auditor.audit_ingress_file(Path("my_module.py"))
    print(verdict.status.value)
"""

from __future__ import annotations

from .audit import AuditIssue, AuditStatus, AuditVerdict, IssueSeverity, IssueReporter
from .core import IncrementalASTCache, LocalIngressAuditor, RemediationSynthesizer

__version__: str = "1.0.0"
__all__: list[str] = [
    # Core audit data types
    "AuditIssue",
    "AuditStatus",
    "AuditVerdict",
    "IssueSeverity",
    "IssueReporter",
    # Unified driver + extensions
    "LocalIngressAuditor",
    "IncrementalASTCache",
    "RemediationSynthesizer",
]
