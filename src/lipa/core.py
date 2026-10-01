"""
Unified Driver — LocalIngressAuditor

Orchestrates the full three-stage LIPA audit pipeline:

  Stage 1  Topology   ImportBoundaryScanner + TarjanSCC + PEP-594 stdlib check
  Stage 2  Contract   SignatureExtractor + contract diffing (when baseline provided)
  Stage 3  Syntax     SyntaxVersionAuditor (security, PEP-765, PEP-798, walrus …)
  Stage 4  Verdict    FSM state collapse → AuditStatus via AuditVerdict

Extended subsystems from blueprint §6:
  - IncrementalASTCache  — BLAKE2b fingerprint-based parse cache (> 80 % hit ratio)
  - HourlyTelemetryLogger — append-only JSONL time-series of verdict snapshots
  - RemediationSynthesizer — PEP 702 deprecation stub generator

Blueprint Reference: Lines 752-850 (Local Ingress Pre-flight.md §8)
Performance Target: < 150 ms per file, < 2 s for 10-file batch
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

from .audit import (
    AuditIssue,
    AuditStatus,
    AuditVerdict,
    IssueSeverity,
)
from .contract import SignatureExtractor
from .syntax import (
    PEP_594_REMOVED_IN_3_13,
    SyntaxVersionAuditor,
)
from .topology import ImportBoundaryScanner, detect_cycles_tarjan


# ---------------------------------------------------------------------------
# §6.1 — Incremental AST cache
# ---------------------------------------------------------------------------

class IncrementalASTCache:
    """BLAKE2b-fingerprinted parse cache keyed on (mtime_ns, size).

    Avoids redundant ``compile(PyCF_ONLY_AST)`` calls when a file has not
    changed between audit runs — critical for batch performance targets.

    The fingerprint deliberately uses *only* filesystem metadata (mtime_ns and
    st_size) rather than file content so that ``get_fingerprint`` never reads
    the file, keeping cache-miss latency under a microsecond.
    """

    def __init__(self) -> None:
        # Maps str(path) → (fingerprint_hex, parsed_ast_module)
        self._cache: dict[str, tuple[str, ast.Module]] = {}

    def get_fingerprint(self, path: Path) -> str:
        """Compute a 16-byte BLAKE2b digest from filesystem stat metadata.

        Args:
            path: Absolute path to the source file.

        Returns:
            Hex string of the 16-byte BLAKE2b digest.
        """
        stat = path.stat()
        hasher = hashlib.blake2b(digest_size=16)
        hasher.update(f"{stat.st_mtime_ns}:{stat.st_size}".encode())
        return hasher.hexdigest()

    def get_or_parse(self, path: Path, source: str) -> ast.Module:
        """Return cached AST or parse ``source`` and store the result.

        Args:
            path:   Absolute path (used as cache key and for fingerprinting).
            source: UTF-8 file content already read by the caller.

        Returns:
            Parsed ``ast.Module`` (never bytecode-compiled; PyCF_ONLY_AST).

        Raises:
            SyntaxError: Propagated from ``compile`` when the source is
                         syntactically invalid.
        """
        fp = self.get_fingerprint(path)
        cached = self._cache.get(str(path))
        if cached is not None and cached[0] == fp:
            return cached[1]

        tree = compile(source, str(path), "exec", ast.PyCF_ONLY_AST)  # type: ignore[arg-type]
        self._cache[str(path)] = (fp, tree)
        return tree  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# §6.2 — Hourly telemetry logger
# ---------------------------------------------------------------------------

class HourlyTelemetryLogger:
    """Append-only JSONL logger for audit verdict time-series snapshots.

    Each snapshot records the UTC timestamp, verdict status, execution time,
    and symbol-delta counts — useful for tracking API surface evolution over
    time without requiring an external database.

    Args:
        log_path: Absolute path of the target ``.jsonl`` file.  Parent
                  directories are created on first write if absent.
    """

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path

    def record_snapshot(
        self,
        verdict: AuditVerdict,
        diff_summary: dict[str, list[str]],
    ) -> None:
        """Append one snapshot line to the telemetry log.

        Args:
            verdict:      The AuditVerdict to snapshot.
            diff_summary: Contract diff dict (``symbols_added`` /
                          ``symbols_removed``).
        """
        entry = {
            "timestamp":             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status":                verdict.status.value,
            "execution_ms":          round(verdict.execution_time_ms, 3),
            "symbols_added_count":   len(diff_summary.get("symbols_added", [])),
            "symbols_removed_count": len(diff_summary.get("symbols_removed", [])),
            "issues_count":          len(verdict.issues),
        }
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")


# ---------------------------------------------------------------------------
# §6.3 — Auto-remediation stub synthesizer
# ---------------------------------------------------------------------------

class RemediationSynthesizer:
    """Generates backwards-compatible deprecation shims for removed symbols.

    When a public symbol is deleted from the ingress module, the synthesizer
    produces a PEP 702-style wrapper that issues a ``DeprecationWarning``
    rather than an ``ImportError``, buying downstream consumers time to
    migrate.
    """

    @staticmethod
    def generate_deprecation_stub(old_name: str, new_name: str) -> str:
        """Return source text for a deprecation compatibility shim.

        Args:
            old_name: The deleted symbol name to emulate.
            new_name: The replacement symbol that callers should migrate to.

        Returns:
            Python source string containing the shim function definition.
        """
        return (
            f"\n# Auto-generated compatibility stub (PEP 702)\n"
            f"import warnings\n"
            f"def {old_name}(*args, **kwargs):\n"
            f"    warnings.warn(\n"
            f"        '{old_name} is deprecated; use {new_name}',\n"
            f"        DeprecationWarning,\n"
            f"        stacklevel=2,\n"
            f"    )\n"
            f"    return {new_name}(*args, **kwargs)\n"
        )


# ---------------------------------------------------------------------------
# Unified Driver
# ---------------------------------------------------------------------------

class LocalIngressAuditor:
    """Zero-execution AST auditor orchestrating all four pipeline stages.

    Builds and caches a workspace module index on construction so that
    relative-import resolution is O(1) during per-file audits.

    Args:
        workspace_root:   Root directory whose ``*.py`` tree defines the
                          internal module namespace.
        target_versions:  Set of ``(major, minor)`` Python version tuples the
                          ingress code must be compatible with.
                          E.g. ``{(3, 11), (3, 12), (3, 13)}``.
        telemetry_path:   Optional path for the JSONL telemetry log.  When
                          ``None``, telemetry recording is disabled.

    Raises:
        ValueError: If ``workspace_root`` does not exist or is not a directory.
    """

    def __init__(
        self,
        workspace_root: Path,
        target_versions: set[tuple[int, int]],
        telemetry_path: Optional[Path] = None,
    ) -> None:
        resolved = workspace_root.resolve()
        if not resolved.is_dir():
            raise ValueError(
                f"workspace_root must be an existing directory: {workspace_root}"
            )
        self.workspace_root: Path = resolved
        self.target_versions: set[tuple[int, int]] = target_versions
        self._cache: IncrementalASTCache = IncrementalASTCache()
        self._workspace_modules: set[str] = self._index_workspace()
        self._telemetry: Optional[HourlyTelemetryLogger] = (
            HourlyTelemetryLogger(telemetry_path) if telemetry_path else None
        )

    # ------------------------------------------------------------------
    # Workspace indexing
    # ------------------------------------------------------------------

    def _index_workspace(self) -> set[str]:
        """Build a set of canonical dotted module paths from the workspace tree.

        An ``__init__.py`` file maps to its *package* canonical name (without
        the ``__init__`` suffix); all other ``*.py`` files drop the ``.py``
        extension and use dot-joined path components.

        Returns:
            Set of canonical module names (e.g. ``{"lipa", "lipa.topology"}``).
        """
        modules: set[str] = set()
        for root, _, files in os.walk(self.workspace_root):
            for filename in files:
                if not filename.endswith(".py"):
                    continue
                full_path = Path(root) / filename
                rel = full_path.relative_to(self.workspace_root)
                parts = list(rel.parts)
                if parts[-1] == "__init__.py":
                    parts = parts[:-1]
                else:
                    parts[-1] = parts[-1][:-3]   # strip .py
                if parts:
                    modules.add(".".join(parts))
        return modules

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def audit_ingress_file(
        self,
        file_path: Path,
        baseline_source: Optional[str] = None,
    ) -> AuditVerdict:
        """Run the complete LIPA pipeline on a single ingress file.

        Executes all four stages in sequence and collapses the FSM to a
        terminal AuditStatus according to the blueprint §5 transition table:

          INIT → RESOLVING_TOPOLOGY → EVALUATING_CONTRACTS
               → VALIDATING_SYNTAX → PASS | WARN | BLOCKED

        Args:
            file_path:       Absolute path to the Python file to audit.
            baseline_source: Optional UTF-8 source string of the *previous*
                             version of the module.  When supplied, the
                             contract-diffing stage (Stage 2) is activated.

        Returns:
            AuditVerdict with terminal status and accumulated issues.

        Raises:
            FileNotFoundError: If ``file_path`` does not exist.
            PermissionError:   If the file cannot be read.
        """
        start_time = time.perf_counter()
        issues: list[AuditIssue] = []

        # --- Read source --------------------------------------------------
        with open(file_path, "r", encoding="utf-8") as fh:
            source = fh.read()

        # --- Parse (PyCF_ONLY_AST = zero bytecode overhead) --------------
        try:
            tree: ast.Module = self._cache.get_or_parse(file_path, source)  # type: ignore[assignment]
        except SyntaxError as exc:
            issues.append(AuditIssue(
                stage="SyntaxCheck",
                code="SYNTAX_ERROR",
                severity=IssueSeverity.FATAL,
                filepath=str(file_path),
                line=exc.lineno or 0,
                column=exc.offset or 0,
                symbol=None,
                message=str(exc.msg),
                remediation_hint="Fix the syntax error before attempting ingress.",
            ))
            return AuditVerdict(
                status=AuditStatus.BLOCKED,
                execution_time_ms=(time.perf_counter() - start_time) * 1000,
                scanned_files_count=1,
                issues=issues,
                contract_diff_summary={},
            )

        # =================================================================
        # Stage 1 — Topology: imports, isolation guard, builtin shadowing
        # =================================================================
        scanner = ImportBoundaryScanner(current_module=file_path.stem)
        scanner.visit(tree)
        scanner.check_module_purity(tree)

        for line, col, msg in scanner.isolation_violations:
            issues.append(AuditIssue(
                stage="Topology",
                code="SYS_MODULES_MUTATION",
                severity=IssueSeverity.FATAL,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol="sys.modules",
                message=f"Direct mutation of global module state: {msg}",
                remediation_hint=(
                    "Never mutate sys.modules or __builtins__ directly "
                    "in ingress code."
                ),
            ))

        for line, col, b_name in scanner.builtin_shadowing:
            issues.append(AuditIssue(
                stage="Topology",
                code="BUILTIN_SHADOWED_AT_MODULE_LEVEL",
                severity=IssueSeverity.WARNING,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol=b_name,
                message=(
                    f"Module-level name '{b_name}' shadows a Python built-in; "
                    f"consumers using 'import *' will receive the overridden binding."
                ),
                remediation_hint="Rename the variable to avoid shadowing a built-in.",
            ))

        # PEP 594 — removed stdlib modules
        for imp in scanner.imports:
            if imp.target_module in PEP_594_REMOVED_IN_3_13:
                issues.append(AuditIssue(
                    stage="Topology",
                    code="PEP594_REMOVED_STDLIB",
                    severity=IssueSeverity.FATAL,
                    filepath=str(file_path),
                    line=imp.lineno,
                    column=imp.col_offset,
                    symbol=imp.target_module,
                    message=(
                        f"Module '{imp.target_module}' was removed from the "
                        f"standard library in Python 3.13 (PEP 594)."
                    ),
                    remediation_hint=(
                        "Switch to a third-party replacement or a modern "
                        "stdlib equivalent."
                    ),
                ))

        for line, col, func_name in scanner.top_level_side_effects:
            issues.append(AuditIssue(
                stage="Topology",
                code="TOP_LEVEL_SIDE_EFFECT",
                severity=IssueSeverity.WARNING,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol=func_name,
                message=(
                    f"Top-level call '{func_name}()' executes a side effect "
                    f"at import time."
                ),
                remediation_hint=(
                    "Guard with 'if __name__ == \"__main__\":' or "
                    "move into an initialiser function."
                ),
            ))

        # Circular import detection via Tarjan's SCC
        adj: dict[str, set[str]] = {}
        for imp in scanner.imports:
            if imp.target_module and not imp.level:
                adj.setdefault(imp.source_module, set()).add(imp.target_module)
        cycles = detect_cycles_tarjan(adj)
        for cycle in cycles:
            cycle_str = " → ".join(cycle) + f" → {cycle[0]}"
            issues.append(AuditIssue(
                stage="Topology",
                code="CIRCULAR_IMPORT_DETECTED",
                severity=IssueSeverity.FATAL,
                filepath=str(file_path),
                line=1,
                column=0,
                symbol=cycle[0],
                message=f"Circular import cycle detected: {cycle_str}",
                remediation_hint=(
                    "Break the cycle by extracting shared code into a "
                    "dependency-free utility module."
                ),
            ))

        # =================================================================
        # Stage 2 — Contract diffing (activated only when baseline provided)
        # =================================================================
        diff_summary: dict[str, list[str]] = {
            "symbols_added": [],
            "symbols_removed": [],
        }

        if baseline_source is not None:
            base_tree: ast.Module = compile(  # type: ignore[assignment]
                baseline_source, "baseline", "exec", ast.PyCF_ONLY_AST
            )
            base_ext = SignatureExtractor(module_name=file_path.stem)
            base_ext.visit(base_tree)
            base_contract = base_ext.finalize()

            ing_ext = SignatureExtractor(module_name=file_path.stem)
            ing_ext.visit(tree)
            ing_contract = ing_ext.finalize()

            removed = base_contract.exported_symbols - ing_contract.exported_symbols
            added   = ing_contract.exported_symbols - base_contract.exported_symbols
            diff_summary["symbols_removed"] = sorted(removed)
            diff_summary["symbols_added"]   = sorted(added)

            # Removed public symbols
            for sym in removed:
                issues.append(AuditIssue(
                    stage="ContractDiffer",
                    code="EXPORTED_SYMBOL_REMOVED",
                    severity=IssueSeverity.FATAL,
                    filepath=str(file_path),
                    line=1,
                    column=0,
                    symbol=sym,
                    message=(
                        f"Public symbol '{sym}' was removed or renamed "
                        f"(breaking change)."
                    ),
                    remediation_hint=(
                        "Preserve the original symbol or provide a "
                        "RemediationSynthesizer deprecation stub."
                    ),
                ))

            # @final class subclassing violations (PEP 591)
            for cls_name, ing_cls in ing_contract.classes.items():
                for base_name in ing_cls.bases:
                    if (
                        base_name in base_contract.classes
                        and base_contract.classes[base_name].is_final
                    ):
                        issues.append(AuditIssue(
                            stage="ContractDiffer",
                            code="FINAL_CLASS_SUBCLASSED",
                            severity=IssueSeverity.FATAL,
                            filepath=str(file_path),
                            line=1,
                            column=0,
                            symbol=cls_name,
                            message=(
                                f"Class '{cls_name}' inherits from @final class "
                                f"'{base_name}' (PEP 591 violation)."
                            ),
                            remediation_hint=(
                                "Remove the inheritance or use composition instead "
                                "of subclassing."
                            ),
                        ))

            # TypeVar bound narrowing (PEP 695)
            for tv_name, base_tvb in base_contract.typevar_bounds.items():
                if tv_name in ing_contract.typevar_bounds:
                    ing_tvb = ing_contract.typevar_bounds[tv_name]
                    base_bound = getattr(base_tvb, "bound", None)
                    ing_bound  = getattr(ing_tvb, "bound", None)
                    if (
                        base_bound is not None
                        and ing_bound is not None
                        and base_bound != ing_bound
                    ):
                        issues.append(AuditIssue(
                            stage="ContractDiffer",
                            code="TYPEVAR_BOUND_MUTATION_BREAK",
                            severity=IssueSeverity.FATAL,
                            filepath=str(file_path),
                            line=1,
                            column=0,
                            symbol=tv_name,
                            message=(
                                f"TypeVar '{tv_name}' bound changed from "
                                f"'{base_bound}' to '{ing_bound}' — "
                                f"breaks generic call sites."
                            ),
                            remediation_hint=(
                                "Preserve the original TypeVar bound to maintain "
                                "generic compatibility."
                            ),
                        ))

            # Dataclass field kw_only mutation
            for cls_name, base_cls in base_contract.classes.items():
                if not base_cls.is_dataclass:
                    continue
                if cls_name not in ing_contract.classes:
                    continue
                ing_cls = ing_contract.classes[cls_name]
                base_fields = {f.name: f for f in base_cls.dataclass_fields}
                for f in ing_cls.dataclass_fields:
                    if f.name not in base_fields:
                        continue
                    base_f = base_fields[f.name]
                    if not base_f.is_kw_only and f.is_kw_only:
                        issues.append(AuditIssue(
                            stage="ContractDiffer",
                            code="DATACLASS_FIELD_KW_ONLY_MUTATION",
                            severity=IssueSeverity.FATAL,
                            filepath=str(file_path),
                            line=1,
                            column=0,
                            symbol=f"{cls_name}.{f.name}",
                            message=(
                                f"Dataclass field '{f.name}' in '{cls_name}' "
                                f"changed to kw_only, breaking positional callers."
                            ),
                            remediation_hint=(
                                "Preserve the positional parameter contract or "
                                "deprecate positional usage first."
                            ),
                        ))

        # =================================================================
        # Stage 3 — Syntax & security gating
        # =================================================================
        version_auditor = SyntaxVersionAuditor(
            has_future_annotations=scanner.has_future_annotations
        )
        version_auditor.visit(tree)

        # Security violations — FATAL
        for line, col, sec_msg in version_auditor.security_violations:
            issues.append(AuditIssue(
                stage="SyntaxCheck",
                code="INGRESS_SECURITY_VIOLATION",
                severity=IssueSeverity.FATAL,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol="security",
                message=f"Unsafe call detected: {sec_msg}",
                remediation_hint=(
                    "Remove all eval/exec/pickle/marshal/os.system calls "
                    "from ingress code unconditionally."
                ),
            ))

        # Legacy AST nodes — FATAL (crash on Python >= 3.14)
        for line, col, ast_err in version_auditor.legacy_ast_usages:
            issues.append(AuditIssue(
                stage="SyntaxCheck",
                code="LEGACY_AST_NODE_REMOVED",
                severity=IssueSeverity.FATAL,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol="ast",
                message=ast_err,
                remediation_hint=(
                    "Replace the removed AST node with 'ast.Constant' "
                    "(Python >= 3.8 compatible)."
                ),
            ))

        # Walrus scope violations — FATAL
        for line, col, walrus_err in version_auditor.walrus_scope_violations:
            issues.append(AuditIssue(
                stage="SyntaxCheck",
                code="WALRUS_COMPREHENSION_SCOPE_VIOLATION",
                severity=IssueSeverity.FATAL,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol=":=",
                message=walrus_err,
                remediation_hint=(
                    "Avoid walrus operator inside comprehensions within class "
                    "scope, or avoid reusing loop-variable names with :=."
                ),
            ))

        # Bare raise outside except — FATAL
        for line, col in version_auditor.bare_raises_outside_except:
            issues.append(AuditIssue(
                stage="SyntaxCheck",
                code="BARE_RAISE_OUTSIDE_EXCEPT",
                severity=IssueSeverity.FATAL,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol="raise",
                message=(
                    "Bare 'raise' outside an except block will raise "
                    "RuntimeError: No active exception to re-raise."
                ),
                remediation_hint=(
                    "Supply an exception instance: 'raise ValueError(...)' "
                    "or move inside an except handler."
                ),
            ))

        # Version-gate diagnostics — FATAL when target < min_version
        for line, col, req in version_auditor.diagnostics:
            for target_ver in self.target_versions:
                if target_ver < req.min_version:
                    issues.append(AuditIssue(
                        stage="SyntaxCheck",
                        code="INCOMPATIBLE_VERSION_SYNTAX",
                        severity=IssueSeverity.FATAL,
                        filepath=str(file_path),
                        line=line,
                        column=col,
                        symbol=req.feature_name,
                        message=(
                            f"'{req.feature_name}' requires Python "
                            f">={req.min_version[0]}.{req.min_version[1]} "
                            f"but target {target_ver[0]}.{target_ver[1]} "
                            f"was declared."
                        ),
                        remediation_hint=(
                            f"Remove or conditionally guard use of "
                            f"'{req.feature_name}', or raise the minimum "
                            f"Python version requirement."
                        ),
                    ))

        # Unquoted forward refs — WARNING when any target <= 3.13
        if any(ver <= (3, 13) for ver in self.target_versions):
            for line, col, fwd_msg in version_auditor.unquoted_forward_refs:
                issues.append(AuditIssue(
                    stage="SyntaxCheck",
                    code="UNQUOTED_FORWARD_REF_RUNTIME_HAZARD",
                    severity=IssueSeverity.WARNING,
                    filepath=str(file_path),
                    line=line,
                    column=col,
                    symbol="annotation",
                    message=fwd_msg,
                    remediation_hint=(
                        "Add 'from __future__ import annotations' at the top of "
                        "the file or wrap the type name in a string literal."
                    ),
                ))

        # __del__ finalizer — WARNING
        for line, col, del_msg in version_auditor.finalizers_detected:
            issues.append(AuditIssue(
                stage="SyntaxCheck",
                code="FINALIZER_DEL_METHOD_DETECTED",
                severity=IssueSeverity.WARNING,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol="__del__",
                message=del_msg,
                remediation_hint=(
                    "Replace __del__ with a Context Manager (with-statement) "
                    "for deterministic lifecycle management."
                ),
            ))

        # Implicit encoding — WARNING
        for line, col, enc_msg in version_auditor.implicit_encoding_opens:
            issues.append(AuditIssue(
                stage="SyntaxCheck",
                code="IMPLICIT_FILE_ENCODING_TARGET_MISMATCH",
                severity=IssueSeverity.WARNING,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol="open",
                message=enc_msg,
                remediation_hint=(
                    "Specify encoding='utf-8' explicitly in all open() "
                    "text-mode calls."
                ),
            ))

        # Mutable default arguments — WARNING
        for line, col, func_n, def_val in version_auditor.mutable_defaults:
            issues.append(AuditIssue(
                stage="SyntaxCheck",
                code="MUTABLE_DEFAULT_ARGUMENT",
                severity=IssueSeverity.WARNING,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol=func_n,
                message=(
                    f"Function '{func_n}' has a mutable default argument: "
                    f"{def_val}"
                ),
                remediation_hint=(
                    "Use None as the default and create the mutable object "
                    "inside the function body."
                ),
            ))

        # Async blocking calls — WARNING
        for line, col, blk_call in version_auditor.blocking_calls:
            issues.append(AuditIssue(
                stage="SyntaxCheck",
                code="ASYNC_BLOCKING_CALL",
                severity=IssueSeverity.WARNING,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol=blk_call,
                message=(
                    f"Synchronous blocking call '{blk_call}' inside "
                    f"an async function stalls the event loop."
                ),
                remediation_hint=(
                    "Replace with the async equivalent (e.g. asyncio.sleep) "
                    "or offload via loop.run_in_executor."
                ),
            ))

        # Unmanaged resources — WARNING
        for line, col, leak_msg in version_auditor.unmanaged_resources:
            issues.append(AuditIssue(
                stage="SyntaxCheck",
                code="UNMANAGED_RESOURCE_LEAK",
                severity=IssueSeverity.WARNING,
                filepath=str(file_path),
                line=line,
                column=col,
                symbol="open",
                message=leak_msg,
                remediation_hint=(
                    "Use 'with open(...) as f:' to guarantee the file "
                    "descriptor is closed even on exception."
                ),
            ))

        # =================================================================
        # Stage 4 — FSM state collapse → terminal AuditStatus
        # =================================================================
        has_fatal = any(i.severity is IssueSeverity.FATAL for i in issues)
        has_warn  = any(i.severity is IssueSeverity.WARNING for i in issues)
        status = (
            AuditStatus.BLOCKED if has_fatal
            else AuditStatus.WARN if has_warn
            else AuditStatus.PASS
        )

        verdict = AuditVerdict(
            status=status,
            execution_time_ms=(time.perf_counter() - start_time) * 1000,
            scanned_files_count=1,
            issues=issues,
            contract_diff_summary=diff_summary,
        )

        if self._telemetry is not None:
            self._telemetry.record_snapshot(verdict, diff_summary)

        return verdict

    def audit_batch(
        self,
        file_paths: list[Path],
        baseline_sources: Optional[dict[str, str]] = None,
    ) -> list[AuditVerdict]:
        """Run the audit pipeline on multiple files sequentially.

        Args:
            file_paths:       Ordered list of absolute paths to audit.
            baseline_sources: Optional dict mapping ``str(path)`` to baseline
                              source strings for contract diffing.

        Returns:
            List of AuditVerdict in the same order as ``file_paths``.
        """
        results: list[AuditVerdict] = []
        for fp in file_paths:
            baseline = None
            if baseline_sources:
                baseline = baseline_sources.get(str(fp))
            results.append(self.audit_ingress_file(fp, baseline_source=baseline))
        return results
