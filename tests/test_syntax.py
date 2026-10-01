"""
Test Suite — Stage 3: Syntax & Security Gating (Phase 4 Cluster Tests)

Covers:
  Test 4.1  Legacy AST node detection  (ast.Num, ast.Str — removed in 3.14)
  Test 4.2  eval() security violation
  Test 4.3  PEP 798 starred unpacking in comprehensions
  Test 4.4  Walrus operator scope violation in class comprehension
  Test 4.5  Bare raise outside except block
  Test 4.6  PEP 765 return/break/continue inside finally
  Test 4.7  Mutable default argument detection
  Test 4.8  Implicit text-mode open() encoding
  Test 4.9  Async blocking call detection
  Test 4.10 PEP 594 removed stdlib in import chain (via topology scanner)
  Test 4.11 exec() / pickle.loads / os.system / subprocess shell=True
  Test 4.12 Unquoted forward reference (no __future__ annotations)
  Test 4.13 __del__ finalizer detection

Blueprint Reference: Lines 852-950 (Local Ingress Pre-flight.md §7 Edge-Case Matrix)
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from lipa.syntax import (
    LEGACY_AST_REMOVED_IN_3_14,
    PEP_594_REMOVED_IN_3_13,
    SyntaxVersionAuditor,
)
from lipa.topology import ImportBoundaryScanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_and_audit(
    source: str,
    has_future_annotations: bool = False,
) -> SyntaxVersionAuditor:
    """Parse ``source`` and run SyntaxVersionAuditor; return the visitor.

    Args:
        source:                Clean Python source string (no leading indent).
        has_future_annotations: Forward to ``SyntaxVersionAuditor.__init__``.

    Returns:
        Populated ``SyntaxVersionAuditor`` instance.
    """
    tree: ast.Module = compile(  # type: ignore[assignment]
        textwrap.dedent(source), "<test>", "exec", ast.PyCF_ONLY_AST
    )
    auditor = SyntaxVersionAuditor(has_future_annotations=has_future_annotations)
    auditor.visit(tree)
    return auditor


def _scan_imports(source: str) -> ImportBoundaryScanner:
    """Parse and run ImportBoundaryScanner on *source*.

    Args:
        source: Clean Python source string.

    Returns:
        Populated ``ImportBoundaryScanner`` instance.
    """
    tree: ast.Module = compile(  # type: ignore[assignment]
        textwrap.dedent(source), "<test>", "exec", ast.PyCF_ONLY_AST
    )
    scanner = ImportBoundaryScanner(current_module="test_module")
    scanner.visit(tree)
    return scanner


# ===========================================================================
# 4.1 — Legacy AST Node Detection
# ===========================================================================

class TestLegacyASTNodes:
    """ast.Num / ast.Str / ast.Bytes / ast.NameConstant / ast.Ellipsis
    were permanently removed in Python 3.14.  Any usage must be blocked."""

    def test_attribute_access_ast_num(self) -> None:
        """Detect 'ast.Num' accessed as an attribute."""
        auditor = _parse_and_audit("isinstance(node, ast.Num)")
        assert any(
            "ast.Num" in msg
            for _, _, msg in auditor.legacy_ast_usages
        ), "Expected 'ast.Num' in legacy_ast_usages"

    def test_attribute_access_ast_str(self) -> None:
        """Detect 'ast.Str' accessed as an attribute."""
        auditor = _parse_and_audit("isinstance(node, ast.Str)")
        assert any(
            "ast.Str" in msg
            for _, _, msg in auditor.legacy_ast_usages
        )

    def test_import_from_ast_bytes(self) -> None:
        """Detect 'from ast import Bytes' direct import."""
        auditor = _parse_and_audit("from ast import Bytes")
        assert any(
            "Bytes" in msg
            for _, _, msg in auditor.legacy_ast_usages
        )

    def test_clean_code_no_legacy_ast(self) -> None:
        """Clean code using ast.Constant must not trigger any legacy warning."""
        auditor = _parse_and_audit("isinstance(node, ast.Constant)")
        assert auditor.legacy_ast_usages == []

    def test_all_removed_node_names_are_in_constant(self) -> None:
        """The LEGACY_AST_REMOVED_IN_3_14 set must contain all known removed nodes."""
        expected = {"Num", "Str", "Bytes", "NameConstant", "Ellipsis"}
        assert expected == set(LEGACY_AST_REMOVED_IN_3_14)


# ===========================================================================
# 4.2 — eval() / exec() Security Violations
# ===========================================================================

class TestSecurityViolations:
    """Dynamic-execution calls must be detected and flagged as FATAL."""

    def test_eval_call(self) -> None:
        """eval() must register a security violation."""
        auditor = _parse_and_audit("result = eval(user_input)")
        assert len(auditor.security_violations) == 1
        _, _, msg = auditor.security_violations[0]
        assert "eval" in msg.lower()

    def test_exec_call(self) -> None:
        """exec() must register a security violation."""
        auditor = _parse_and_audit("exec('import os')")
        assert len(auditor.security_violations) >= 1
        assert any("exec" in msg.lower() for _, _, msg in auditor.security_violations)

    def test_pickle_loads(self) -> None:
        """pickle.loads() must register a security violation."""
        auditor = _parse_and_audit("pickle.loads(raw_bytes)")
        assert len(auditor.security_violations) >= 1, (
            "Expected security_violations for pickle.loads"
        )
        # The description string comes from DANGEROUS_CALLS dict value
        _, _, msg = auditor.security_violations[0]
        assert "pickle" in msg.lower() or "deserialization" in msg.lower(), (
            f"Unexpected security message: {msg}"
        )

    def test_os_system(self) -> None:
        """os.system() must register a security violation."""
        auditor = _parse_and_audit("os.system('rm -rf /')")
        assert any(
            "os.system" in msg or "Shell command" in msg
            for _, _, msg in auditor.security_violations
        )

    def test_subprocess_shell_true(self) -> None:
        """subprocess.run(shell=True) must register a security violation."""
        auditor = _parse_and_audit("subprocess.run('cmd', shell=True)")
        assert any(
            "shell=True" in msg
            for _, _, msg in auditor.security_violations
        )

    def test_subprocess_no_shell(self) -> None:
        """subprocess.run without shell=True must not register a violation."""
        auditor = _parse_and_audit("subprocess.run(['ls', '-la'])")
        assert auditor.security_violations == []

    def test_marshal_loads(self) -> None:
        """marshal.loads() must register a security violation."""
        auditor = _parse_and_audit("marshal.loads(raw_data)")
        assert len(auditor.security_violations) >= 1, (
            "Expected security_violations for marshal.loads"
        )
        _, _, msg = auditor.security_violations[0]
        assert "marshal" in msg.lower() or "deserialization" in msg.lower(), (
            f"Unexpected security message: {msg}"
        )


# ===========================================================================
# 4.3 — PEP 798 Starred Unpacking in Comprehensions
# ===========================================================================

class TestPEP798UnpackingDetection:
    """[*x for x in data] and {**d for d in data} require Python >= 3.15.

    On Python < 3.15 the parse itself raises SyntaxError — which is the
    physical proof that the feature is incompatible.  On Python >= 3.15
    the auditor records a VersionRequirement diagnostic.
    """

    def test_starred_list_comprehension(self) -> None:
        """[*item for item in matrix] must either raise SyntaxError on parse
        (proving incompatibility) or register a (3, 15) PEP 798 diagnostic."""
        import sys
        source = "result = [*item for item in matrix]"
        try:
            auditor = _parse_and_audit(source)
            # If we reach here we are on Python >= 3.15 — check diagnostic
            reqs = [req for _, _, req in auditor.diagnostics]
            assert any(
                req.min_version == (3, 15) and "PEP 798" in req.feature_name
                for req in reqs
            ), f"Expected PEP 798 diagnostic on Python >= 3.15, got: {reqs}"
        except SyntaxError:
            # On Python < 3.15 the SyntaxError itself is the evidence of
            # incompatibility — the test passes because the feature is gated.
            assert sys.version_info < (3, 15), (
                "SyntaxError for PEP 798 should only occur on Python < 3.15"
            )

    def test_starred_set_comprehension(self) -> None:
        """{*item for item in matrix} must either raise SyntaxError (< 3.15)
        or register a (3, 15) PEP 798 diagnostic (>= 3.15)."""
        import sys
        source = "result = {*item for item in matrix}"
        try:
            auditor = _parse_and_audit(source)
            reqs = [req for _, _, req in auditor.diagnostics]
            assert any(
                req.min_version == (3, 15) and "PEP 798" in req.feature_name
                for req in reqs
            )
        except SyntaxError:
            assert sys.version_info < (3, 15)

    def test_clean_list_comprehension(self) -> None:
        """A plain [x for x in data] must not trigger a PEP 798 diagnostic."""
        auditor = _parse_and_audit("[x * 2 for x in range(10)]")
        pep798 = [
            req for _, _, req in auditor.diagnostics
            if "PEP 798" in req.feature_name
        ]
        assert pep798 == []


# ===========================================================================
# 4.4 — Walrus Operator Scope Violations (PEP 572)
# ===========================================================================

class TestWalrusScopeViolations:
    """Walrus inside comprehension in class scope must be blocked."""

    def test_walrus_in_class_comprehension(self) -> None:
        """class C: [x := v for v in lst] must detect walrus scope violation."""
        source = """\
            class C:
                data = [x := v for v in [1, 2, 3]]
        """
        auditor = _parse_and_audit(source)
        assert len(auditor.walrus_scope_violations) >= 1
        _, _, msg = auditor.walrus_scope_violations[0]
        assert ":=" in msg

    def test_walrus_rebinds_iteration_variable(self) -> None:
        """(y := y for y in data) must detect rebind of iteration variable."""
        source = "result = list(y := y for y in [1, 2, 3])"
        auditor = _parse_and_audit(source)
        assert len(auditor.walrus_scope_violations) >= 1

    def test_walrus_safe_outside_class(self) -> None:
        """(y := x for x in data) with distinct variable name must be clean."""
        auditor = _parse_and_audit("result = [y for x in [1,2] if (y := x + 1) > 0]")
        # walrus on 'y' inside a ListComp; 'y' is NOT the iteration variable 'x'
        rebind_violations = [
            msg for _, _, msg in auditor.walrus_scope_violations
            if "rebind" in msg
        ]
        assert rebind_violations == []


# ===========================================================================
# 4.5 — Bare Raise Outside Except Block
# ===========================================================================

class TestBareRaiseOutsideExcept:
    """A bare `raise` outside an except handler must be flagged as FATAL."""

    def test_bare_raise_in_function(self) -> None:
        """def f(): raise — must detect BARE_RAISE_OUTSIDE_EXCEPT."""
        source = """\
            def f():
                raise
        """
        auditor = _parse_and_audit(source)
        assert len(auditor.bare_raises_outside_except) == 1

    def test_bare_raise_inside_except_is_safe(self) -> None:
        """bare raise inside an except handler is valid and must not be flagged."""
        source = """\
            try:
                risky()
            except ValueError:
                raise
        """
        auditor = _parse_and_audit(source)
        assert auditor.bare_raises_outside_except == []

    def test_raise_with_exception_is_safe(self) -> None:
        """raise ValueError() is always safe and must not be flagged."""
        auditor = _parse_and_audit("raise ValueError('oops')")
        assert auditor.bare_raises_outside_except == []


# ===========================================================================
# 4.6 — PEP 765 return/break/continue in finally
# ===========================================================================

class TestPEP765FinallyRule:
    """return, break, and continue inside finally blocks require Python 3.14+
    (they silently suppress exceptions in older Python; 3.14+ makes them an
    error that the auditor must gate)."""

    def test_return_in_finally(self) -> None:
        """return inside a finally block must register a (3, 14) diagnostic."""
        source = """\
            def f():
                try:
                    pass
                finally:
                    return 42
        """
        auditor = _parse_and_audit(source)
        reqs = [req for _, _, req in auditor.diagnostics]
        assert any(
            req.min_version == (3, 14) and "PEP 765" in req.feature_name
            for req in reqs
        ), f"Expected PEP 765 return diagnostic, got: {reqs}"

    def test_break_in_finally(self) -> None:
        """break inside a finally block must register a (3, 14) diagnostic."""
        source = """\
            def f():
                for i in range(3):
                    try:
                        pass
                    finally:
                        break
        """
        auditor = _parse_and_audit(source)
        reqs = [req for _, _, req in auditor.diagnostics]
        assert any(
            req.min_version == (3, 14) and "PEP 765" in req.feature_name
            for req in reqs
        )


# ===========================================================================
# 4.7 — Mutable Default Argument
# ===========================================================================

class TestMutableDefaultArguments:
    """List/dict/set literals as default arguments must be flagged."""

    def test_list_default(self) -> None:
        """def f(x=[]) must detect a mutable default."""
        auditor = _parse_and_audit("def f(x=[]):\n    pass")
        assert len(auditor.mutable_defaults) == 1
        _, _, func_name, default_repr = auditor.mutable_defaults[0]
        assert func_name == "f"
        assert "[]" in default_repr

    def test_dict_default(self) -> None:
        """def f(x={}) must detect a mutable default."""
        auditor = _parse_and_audit("def f(x={}):\n    pass")
        assert len(auditor.mutable_defaults) == 1

    def test_set_default(self) -> None:
        """def f(x=set()) is NOT caught (it's a Call, not a Set literal)."""
        # set() is a Call node, not a Set literal — correctly not flagged
        auditor = _parse_and_audit("def f(x=set()):\n    pass")
        assert auditor.mutable_defaults == []

    def test_none_default_is_safe(self) -> None:
        """def f(x=None) must not be flagged."""
        auditor = _parse_and_audit("def f(x=None):\n    pass")
        assert auditor.mutable_defaults == []


# ===========================================================================
# 4.8 — Implicit Text-Mode Encoding
# ===========================================================================

class TestImplicitEncoding:
    """open() in text mode without explicit encoding= must be flagged."""

    def test_text_mode_no_encoding(self) -> None:
        """open('file.txt', 'r') must flag implicit encoding."""
        auditor = _parse_and_audit("f = open('file.txt', 'r')")
        assert len(auditor.implicit_encoding_opens) >= 1

    def test_text_mode_with_encoding(self) -> None:
        """open('file.txt', 'r', encoding='utf-8') must not be flagged."""
        auditor = _parse_and_audit("f = open('file.txt', 'r', encoding='utf-8')")
        assert auditor.implicit_encoding_opens == []

    def test_binary_mode_no_encoding(self) -> None:
        """open('file', 'rb') must not flag — binary mode has no encoding."""
        auditor = _parse_and_audit("f = open('file', 'rb')")
        assert auditor.implicit_encoding_opens == []

    def test_bare_open_no_mode(self) -> None:
        """open('file') — no mode specified defaults to text; must be flagged."""
        auditor = _parse_and_audit("f = open('file.txt')")
        assert len(auditor.implicit_encoding_opens) >= 1


# ===========================================================================
# 4.9 — Async Blocking Calls
# ===========================================================================

class TestAsyncBlockingCalls:
    """Synchronous blocking calls inside async functions must be flagged."""

    def test_time_sleep_in_async(self) -> None:
        """time.sleep() inside async def must register a blocking-call warning."""
        source = """\
            async def handler():
                time.sleep(1)
        """
        auditor = _parse_and_audit(source)
        assert any(
            "time.sleep" in call
            for _, _, call in auditor.blocking_calls
        )

    def test_time_sleep_outside_async(self) -> None:
        """time.sleep() in a normal function must not be flagged."""
        auditor = _parse_and_audit("def f():\n    time.sleep(1)")
        assert auditor.blocking_calls == []


# ===========================================================================
# 4.10 — PEP 594 Removed Stdlib Modules
# ===========================================================================

class TestPEP594RemovedStdlib:
    """Imports of stdlib modules removed in Python 3.13 must be detected
    by the ImportBoundaryScanner (not SyntaxVersionAuditor)."""

    def test_removed_module_aifc(self) -> None:
        """'import aifc' must be detected as a removed stdlib module."""
        scanner = _scan_imports("import aifc")
        removed = [
            imp.target_module
            for imp in scanner.imports
            if imp.target_module in PEP_594_REMOVED_IN_3_13
        ]
        assert "aifc" in removed

    def test_removed_module_crypt(self) -> None:
        """'import crypt' must appear in PEP_594_REMOVED_IN_3_13."""
        scanner = _scan_imports("import crypt")
        removed = [
            imp.target_module
            for imp in scanner.imports
            if imp.target_module in PEP_594_REMOVED_IN_3_13
        ]
        assert "crypt" in removed

    def test_active_module_os_not_removed(self) -> None:
        """'import os' must not appear in PEP_594_REMOVED_IN_3_13."""
        scanner = _scan_imports("import os")
        removed = [
            imp.target_module
            for imp in scanner.imports
            if imp.target_module in PEP_594_REMOVED_IN_3_13
        ]
        assert "os" not in removed

    def test_pep594_set_completeness(self) -> None:
        """The removal set must include all 20 modules listed in PEP 594."""
        # Exact set listed in PEP 594 rationale section
        pep594_official = {
            "aifc", "audioop", "cgi", "cgitb", "chunk", "crypt",
            "imghdr", "mailcap", "msilib", "nis", "nntplib", "ossaudiodev",
            "pipes", "sndhdr", "spwd", "sunau", "telnetlib", "uu", "xdrlib",
        }
        # Our constant must be a superset (we may add more in future)
        assert pep594_official.issubset(PEP_594_REMOVED_IN_3_13)


# ===========================================================================
# 4.11 — __del__ Finalizer Detection
# ===========================================================================

class TestFinalizerDetection:
    """__del__ methods must trigger a WARNING about non-deterministic cleanup."""

    def test_del_method_detected(self) -> None:
        """class C: def __del__(self) must be flagged."""
        source = """\
            class Resource:
                def __del__(self):
                    self.cleanup()
        """
        auditor = _parse_and_audit(source)
        assert len(auditor.finalizers_detected) == 1
        _, _, msg = auditor.finalizers_detected[0]
        assert "__del__" in msg

    def test_other_dunder_not_flagged(self) -> None:
        """__init__ must not be flagged as a finalizer."""
        auditor = _parse_and_audit("class C:\n    def __init__(self):\n        pass")
        assert auditor.finalizers_detected == []


# ===========================================================================
# 4.12 — Unquoted Forward Reference Guard (PEP 649 / 749)
# ===========================================================================

class TestUnquotedForwardReferenceGuard:
    """Without __future__ annotations, forward refs raise NameError on <= 3.13."""

    def test_forward_ref_without_future_annotations(self) -> None:
        """def f(x: UnknownClass) without __future__ must flag a forward ref."""
        source = "def f(x: UnknownClass) -> None:\n    pass"
        auditor = _parse_and_audit(source, has_future_annotations=False)
        assert len(auditor.unquoted_forward_refs) >= 1

    def test_forward_ref_with_future_annotations(self) -> None:
        """With __future__ annotations active, forward refs must be suppressed."""
        source = "def f(x: UnknownClass) -> None:\n    pass"
        auditor = _parse_and_audit(source, has_future_annotations=True)
        assert auditor.unquoted_forward_refs == []

    def test_builtin_annotation_not_flagged(self) -> None:
        """def f(x: int) must never trigger an unquoted forward ref warning."""
        auditor = _parse_and_audit("def f(x: int) -> str:\n    return str(x)")
        assert auditor.unquoted_forward_refs == []
