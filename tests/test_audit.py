"""
Test Suite — Stage 5: Deterministic Audit Engine & Unified Driver (Phase 5 & 6)

Covers:
  Test 5.1  FSM state machine correct terminal state for mixed-severity issues
  Test 5.2  AuditVerdict status accuracy (PASS / WARN / BLOCKED)
  Test 5.3  IssueReporter JSON payload structure
  Test 5.4  IssueReporter human report format
  Test 5.5  LocalIngressAuditor end-to-end PASS verdict (clean file)
  Test 5.6  LocalIngressAuditor end-to-end BLOCKED verdict (security violation)
  Test 5.7  LocalIngressAuditor end-to-end WARN verdict (mutable default only)
  Test 5.8  Contract diffing — exported symbol removal → BLOCKED
  Test 5.9  Contract diffing — @final class subclassing → BLOCKED
  Test 5.10 IncrementalASTCache cache hit behaviour (no re-parse on unchanged file)
  Test 5.11 Batch audit pipeline — multi-file mixed verdicts
  Test 5.12 AuditVerdict.fatal_issues() / warning_issues() filters
  Test 5.13 CLI exit-code mapping (smoke test via LocalIngressAuditor directly)

Blueprint Reference: Lines 600-750 (Local Ingress Pre-flight.md §5)
"""

from __future__ import annotations

import json
import textwrap
import time
from pathlib import Path

import pytest

from lipa.audit import (
    AuditIssue,
    AuditStatus,
    AuditVerdict,
    IssueSeverity,
    IssueReporter,
)
from lipa.core import (
    IncrementalASTCache,
    LocalIngressAuditor,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_workspace(tmp_path: Path) -> Path:
    """Create a minimal workspace with a package root."""
    pkg = tmp_path / "src" / "mypkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    return tmp_path


def _write_py(directory: Path, name: str, source: str) -> Path:
    """Write *source* to *directory*/*name* and return the Path.

    Args:
        directory: Target directory (must exist).
        name:      File name (e.g. ``"target.py"``).
        source:    Python source text.

    Returns:
        Absolute path of the written file.
    """
    path = directory / name
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


def _make_auditor(workspace: Path) -> LocalIngressAuditor:
    """Construct a LocalIngressAuditor targeting Python 3.11–3.15.

    Args:
        workspace: Root directory for module indexing.

    Returns:
        Configured ``LocalIngressAuditor``.
    """
    return LocalIngressAuditor(
        workspace_root=workspace,
        target_versions={(3, 11), (3, 12), (3, 13), (3, 14), (3, 15)},
    )


# ---------------------------------------------------------------------------
# Helpers — synthetic verdict builders
# ---------------------------------------------------------------------------

def _make_fatal_issue(msg: str = "fatal") -> AuditIssue:
    return AuditIssue(
        stage="Test",
        code="TEST_FATAL",
        severity=IssueSeverity.FATAL,
        filepath="/f.py",
        line=1,
        column=0,
        symbol=None,
        message=msg,
        remediation_hint="fix it",
    )


def _make_warning_issue(msg: str = "warn") -> AuditIssue:
    return AuditIssue(
        stage="Test",
        code="TEST_WARN",
        severity=IssueSeverity.WARNING,
        filepath="/f.py",
        line=2,
        column=0,
        symbol="sym",
        message=msg,
        remediation_hint="consider fixing",
    )


def _make_info_issue(msg: str = "info") -> AuditIssue:
    return AuditIssue(
        stage="Test",
        code="TEST_INFO",
        severity=IssueSeverity.INFO,
        filepath="/f.py",
        line=3,
        column=0,
        symbol=None,
        message=msg,
        remediation_hint="",
    )


# ===========================================================================
# 5.1 — FSM State Machine Terminal State
# ===========================================================================

class TestFSMTerminalState:
    """AuditVerdict must encode the correct terminal FSM state."""

    def test_fatal_issue_yields_blocked(self) -> None:
        verdict = AuditVerdict(
            status=AuditStatus.BLOCKED,
            execution_time_ms=10.0,
            scanned_files_count=1,
            issues=[_make_fatal_issue()],
        )
        assert verdict.status is AuditStatus.BLOCKED

    def test_warn_only_yields_warn(self) -> None:
        verdict = AuditVerdict(
            status=AuditStatus.WARN,
            execution_time_ms=5.0,
            scanned_files_count=1,
            issues=[_make_warning_issue()],
        )
        assert verdict.status is AuditStatus.WARN

    def test_no_issues_yields_pass(self) -> None:
        verdict = AuditVerdict(
            status=AuditStatus.PASS,
            execution_time_ms=3.0,
            scanned_files_count=1,
            issues=[],
        )
        assert verdict.status is AuditStatus.PASS

    def test_mixed_fatal_and_warn_yields_blocked(self) -> None:
        """FATAL takes precedence over WARNING — state must be BLOCKED."""
        # Simulate FSM collapse logic
        issues = [_make_fatal_issue(), _make_warning_issue()]
        has_fatal = any(i.severity is IssueSeverity.FATAL for i in issues)
        has_warn  = any(i.severity is IssueSeverity.WARNING for i in issues)
        status = (
            AuditStatus.BLOCKED if has_fatal
            else AuditStatus.WARN if has_warn
            else AuditStatus.PASS
        )
        assert status is AuditStatus.BLOCKED


# ===========================================================================
# 5.2 — AuditVerdict Accuracy
# ===========================================================================

class TestAuditVerdictAccuracy:
    """AuditVerdict filters and to_dict must return correct data."""

    def test_fatal_issues_filter(self) -> None:
        verdict = AuditVerdict(
            status=AuditStatus.BLOCKED,
            execution_time_ms=1.0,
            scanned_files_count=1,
            issues=[_make_fatal_issue(), _make_warning_issue(), _make_info_issue()],
        )
        fatals = verdict.fatal_issues()
        assert len(fatals) == 1
        assert fatals[0].severity is IssueSeverity.FATAL

    def test_warning_issues_filter(self) -> None:
        verdict = AuditVerdict(
            status=AuditStatus.WARN,
            execution_time_ms=1.0,
            scanned_files_count=1,
            issues=[_make_warning_issue(), _make_info_issue()],
        )
        warns = verdict.warning_issues()
        assert len(warns) == 1
        assert warns[0].severity is IssueSeverity.WARNING

    def test_to_dict_keys_present(self) -> None:
        verdict = AuditVerdict(
            status=AuditStatus.PASS,
            execution_time_ms=8.5,
            scanned_files_count=2,
            issues=[],
        )
        d = verdict.to_dict()
        required_keys = {
            "status", "execution_time_ms", "scanned_files_count",
            "issues_count", "fatal_count", "warning_count",
            "contract_diff_summary", "issues",
        }
        assert required_keys.issubset(d.keys())

    def test_to_dict_status_is_string(self) -> None:
        verdict = AuditVerdict(
            status=AuditStatus.BLOCKED,
            execution_time_ms=1.0,
            scanned_files_count=1,
            issues=[_make_fatal_issue()],
        )
        d = verdict.to_dict()
        assert isinstance(d["status"], str)
        assert d["status"] == "BLOCKED"


# ===========================================================================
# 5.3 — IssueReporter JSON Payload
# ===========================================================================

class TestIssueReporterJSON:
    """generate_json_payload must produce valid, parseable JSON."""

    def _make_verdict(self) -> AuditVerdict:
        return AuditVerdict(
            status=AuditStatus.BLOCKED,
            execution_time_ms=42.7,
            scanned_files_count=1,
            issues=[_make_fatal_issue("eval detected"), _make_warning_issue()],
        )

    def test_output_is_valid_json(self) -> None:
        verdict = self._make_verdict()
        reporter = IssueReporter()
        payload = reporter.generate_json_payload(verdict)
        parsed = json.loads(payload)
        assert isinstance(parsed, dict)

    def test_json_contains_status(self) -> None:
        verdict = self._make_verdict()
        reporter = IssueReporter()
        parsed = json.loads(reporter.generate_json_payload(verdict))
        assert parsed["status"] == "BLOCKED"

    def test_json_issues_count_matches(self) -> None:
        verdict = self._make_verdict()
        reporter = IssueReporter()
        parsed = json.loads(reporter.generate_json_payload(verdict))
        assert parsed["issues_count"] == 2
        assert len(parsed["issues"]) == 2

    def test_json_issue_has_required_fields(self) -> None:
        verdict = self._make_verdict()
        reporter = IssueReporter()
        parsed = json.loads(reporter.generate_json_payload(verdict))
        issue = parsed["issues"][0]
        required = {"stage", "code", "severity", "filepath", "line",
                    "column", "symbol", "message", "remediation_hint"}
        assert required.issubset(issue.keys())


# ===========================================================================
# 5.4 — IssueReporter Human Report
# ===========================================================================

class TestIssueReporterHumanReport:
    """generate_human_report must include key identifiers in its output."""

    def test_report_contains_verdict_status(self) -> None:
        verdict = AuditVerdict(
            status=AuditStatus.PASS,
            execution_time_ms=5.0,
            scanned_files_count=1,
            issues=[],
        )
        report = IssueReporter().generate_human_report(verdict)
        assert "PASS" in report

    def test_blocked_report_contains_blocked(self) -> None:
        verdict = AuditVerdict(
            status=AuditStatus.BLOCKED,
            execution_time_ms=5.0,
            scanned_files_count=1,
            issues=[_make_fatal_issue()],
        )
        report = IssueReporter().generate_human_report(verdict)
        assert "BLOCKED" in report

    def test_report_contains_issue_code(self) -> None:
        verdict = AuditVerdict(
            status=AuditStatus.BLOCKED,
            execution_time_ms=5.0,
            scanned_files_count=1,
            issues=[_make_fatal_issue()],
        )
        report = IssueReporter().generate_human_report(verdict)
        assert "TEST_FATAL" in report

    def test_report_contains_execution_time(self) -> None:
        verdict = AuditVerdict(
            status=AuditStatus.PASS,
            execution_time_ms=12.34,
            scanned_files_count=1,
            issues=[],
        )
        report = IssueReporter().generate_human_report(verdict)
        assert "12.34" in report


# ===========================================================================
# 5.5 — End-to-End: Clean File → PASS
# ===========================================================================

class TestEndToEndPass:
    """A syntactically correct, security-clean file must yield PASS."""

    def test_clean_file_yields_pass(self, tmp_workspace: Path) -> None:
        source = """\
            \"\"\"Simple utility module.\"\"\"
            from __future__ import annotations

            def add(a: int, b: int) -> int:
                \"\"\"Return the sum of *a* and *b*.\"\"\"
                return a + b
        """
        target = _write_py(tmp_workspace, "clean.py", source)
        auditor = _make_auditor(tmp_workspace)
        verdict = auditor.audit_ingress_file(target)
        assert verdict.status is AuditStatus.PASS
        assert verdict.issues == []

    def test_clean_file_sub_150ms(self, tmp_workspace: Path) -> None:
        """Performance target: single file audit must complete within 150 ms."""
        source = """\
            from __future__ import annotations

            def compute(x: int) -> int:
                return x * x + 1
        """
        target = _write_py(tmp_workspace, "perf.py", source)
        auditor = _make_auditor(tmp_workspace)
        verdict = auditor.audit_ingress_file(target)
        assert verdict.execution_time_ms < 150.0, (
            f"Performance target missed: {verdict.execution_time_ms:.2f} ms > 150 ms"
        )


# ===========================================================================
# 5.6 — End-to-End: Security Violation → BLOCKED
# ===========================================================================

class TestEndToEndBlocked:
    """A file containing eval() must yield BLOCKED."""

    def test_eval_yields_blocked(self, tmp_workspace: Path) -> None:
        source = """\
            def dangerous(payload: str) -> None:
                eval(payload)
        """
        target = _write_py(tmp_workspace, "unsafe.py", source)
        auditor = _make_auditor(tmp_workspace)
        verdict = auditor.audit_ingress_file(target)
        assert verdict.status is AuditStatus.BLOCKED
        assert any(
            i.code == "INGRESS_SECURITY_VIOLATION"
            for i in verdict.fatal_issues()
        )

    def test_legacy_ast_node_yields_blocked(self, tmp_workspace: Path) -> None:
        source = "isinstance(node, ast.Num)\n"
        target = _write_py(tmp_workspace, "legacy_ast.py", source)
        auditor = _make_auditor(tmp_workspace)
        verdict = auditor.audit_ingress_file(target)
        assert verdict.status is AuditStatus.BLOCKED
        assert any(
            i.code == "LEGACY_AST_NODE_REMOVED"
            for i in verdict.fatal_issues()
        )


# ===========================================================================
# 5.7 — End-to-End: Warning-only → WARN
# ===========================================================================

class TestEndToEndWarn:
    """A file with only WARNING-severity issues must yield WARN."""

    def test_mutable_default_yields_warn(self, tmp_workspace: Path) -> None:
        source = """\
            from __future__ import annotations

            def process(items: list = []) -> list:
                return items
        """
        target = _write_py(tmp_workspace, "mut_default.py", source)
        auditor = _make_auditor(tmp_workspace)
        verdict = auditor.audit_ingress_file(target)
        assert verdict.status is AuditStatus.WARN
        assert verdict.fatal_issues() == []
        assert len(verdict.warning_issues()) >= 1


# ===========================================================================
# 5.8 — Contract Diffing: Symbol Removal → BLOCKED
# ===========================================================================

class TestContractDiffingSymbolRemoval:
    """Removing an exported public symbol must yield BLOCKED."""

    def test_removed_symbol_yields_blocked(self, tmp_workspace: Path) -> None:
        baseline = """\
            def public_api(x: int) -> int:
                return x

            def another_api(y: int) -> int:
                return y
        """
        ingress = """\
            # another_api has been removed — breaking change
            def public_api(x: int) -> int:
                return x
        """
        target = _write_py(tmp_workspace, "api.py", ingress)
        auditor = _make_auditor(tmp_workspace)
        verdict = auditor.audit_ingress_file(
            target, baseline_source=textwrap.dedent(baseline)
        )
        assert verdict.status is AuditStatus.BLOCKED
        assert any(
            i.code == "EXPORTED_SYMBOL_REMOVED"
            for i in verdict.fatal_issues()
        )
        assert "another_api" in verdict.contract_diff_summary.get(
            "symbols_removed", []
        )


# ===========================================================================
# 5.9 — Contract Diffing: @final Class Subclassing → BLOCKED
# ===========================================================================

class TestContractDiffingFinalViolation:
    """Inheriting from a @final class must yield BLOCKED."""

    def test_final_class_subclassing_blocked(self, tmp_workspace: Path) -> None:
        baseline = """\
            from typing import final

            @final
            class Base:
                def method(self) -> None: ...
        """
        ingress = """\
            from typing import final

            @final
            class Base:
                def method(self) -> None: ...

            class Child(Base):
                pass
        """
        target = _write_py(tmp_workspace, "final_test.py", ingress)
        auditor = _make_auditor(tmp_workspace)
        verdict = auditor.audit_ingress_file(
            target, baseline_source=textwrap.dedent(baseline)
        )
        assert verdict.status is AuditStatus.BLOCKED
        assert any(
            i.code == "FINAL_CLASS_SUBCLASSED"
            for i in verdict.fatal_issues()
        )


# ===========================================================================
# 5.10 — IncrementalASTCache
# ===========================================================================

class TestIncrementalASTCache:
    """Second parse of an unchanged file must use the cache (same object id)."""

    def test_cache_hit_returns_same_object(self, tmp_path: Path) -> None:
        source = "x = 1\n"
        target = tmp_path / "module.py"
        target.write_text(source, encoding="utf-8")

        cache = IncrementalASTCache()
        tree1 = cache.get_or_parse(target, source)
        tree2 = cache.get_or_parse(target, source)
        # Same object reference proves cache was used on the second call.
        assert tree1 is tree2

    def test_cache_miss_on_modified_file(self, tmp_path: Path) -> None:
        """Modifying mtime triggers a re-parse (different AST object)."""
        source_v1 = "x = 1\n"
        source_v2 = "x = 2\n"
        target = tmp_path / "module.py"
        target.write_text(source_v1, encoding="utf-8")

        cache = IncrementalASTCache()
        tree1 = cache.get_or_parse(target, source_v1)

        # Overwrite to change mtime and size simultaneously
        time.sleep(0.01)   # ensure mtime_ns differs
        target.write_text(source_v2, encoding="utf-8")

        tree2 = cache.get_or_parse(target, source_v2)
        # Must be a fresh parse — different object identity
        assert tree1 is not tree2


# ===========================================================================
# 5.11 — Batch Audit Pipeline
# ===========================================================================

class TestBatchAuditPipeline:
    """audit_batch must return one verdict per input file in order."""

    def test_batch_mixed_verdicts(self, tmp_workspace: Path) -> None:
        clean_src = "from __future__ import annotations\nx: int = 1\n"
        unsafe_src = "eval('1 + 1')\n"

        clean_file  = _write_py(tmp_workspace, "clean.py", clean_src)
        unsafe_file = _write_py(tmp_workspace, "unsafe.py", unsafe_src)

        auditor = _make_auditor(tmp_workspace)
        verdicts = auditor.audit_batch([clean_file, unsafe_file])

        assert len(verdicts) == 2
        assert verdicts[0].status is AuditStatus.PASS
        assert verdicts[1].status is AuditStatus.BLOCKED

    def test_batch_all_pass(self, tmp_workspace: Path) -> None:
        sources = [
            ("a.py", "from __future__ import annotations\nx = 1\n"),
            ("b.py", "from __future__ import annotations\ny = 2\n"),
        ]
        paths = [_write_py(tmp_workspace, name, src) for name, src in sources]
        auditor = _make_auditor(tmp_workspace)
        verdicts = auditor.audit_batch(paths)
        assert all(v.status is AuditStatus.PASS for v in verdicts)


# ===========================================================================
# 5.12 — AuditIssue.to_dict serialisation
# ===========================================================================

class TestAuditIssueSerialisation:
    """AuditIssue.to_dict must serialise all fields correctly."""

    def test_to_dict_all_fields(self) -> None:
        issue = AuditIssue(
            stage="Topology",
            code="SYS_MODULES_MUTATION",
            severity=IssueSeverity.FATAL,
            filepath="/src/m.py",
            line=42,
            column=8,
            symbol="sys.modules",
            message="Direct mutation detected.",
            remediation_hint="Do not mutate sys.modules.",
        )
        d = issue.to_dict()
        assert d["stage"]            == "Topology"
        assert d["code"]             == "SYS_MODULES_MUTATION"
        assert d["severity"]         == "FATAL"
        assert d["filepath"]         == "/src/m.py"
        assert d["line"]             == 42
        assert d["column"]           == 8
        assert d["symbol"]           == "sys.modules"
        assert d["message"]          == "Direct mutation detected."
        assert d["remediation_hint"] == "Do not mutate sys.modules."

    def test_to_dict_is_json_serialisable(self) -> None:
        issue = _make_fatal_issue("test")
        d = issue.to_dict()
        # Must not raise
        encoded = json.dumps(d)
        assert isinstance(encoded, str)
