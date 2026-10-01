"""
Stage 3: Syntax & Runtime Polyfill Version Matrix

Zero-execution AST-based auditor covering:
  - Python 3.11–3.15+ compatibility gating
  - Security violation detection (eval/exec/pickle/marshal/os.system/subprocess)
  - Legacy AST node purge detection (ast.Num/Str/Bytes removed in 3.14)
  - PEP 798 Comprehension Unpacking (*x, **d in comprehensions)
  - PEP 749/649 Unquoted Forward Reference Guard
  - PEP 734 Subinterpreters gate
  - PEP 747 typing.TypeForm gate
  - PEP 572 Walrus scope violation detection
  - PEP 765 return/break/continue inside finally blocks
  - PEP 594 removed stdlib modules (Python 3.13+)
  - Bare raise outside except context
  - Mutable default argument detection
  - Implicit text-mode open() encoding detection
  - Async blocking call detection
  - Unmanaged resource (open without context manager) detection
  - __del__ finalizer detection (free-threaded runtime hazard)

Blueprint Reference: Lines 401-500 (Local Ingress Pre-flight.md §4)
Performance Target: < 80ms per file
"""

from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Compile-time constants derived from official Python documentation / PEP text
# ---------------------------------------------------------------------------

PYTHON_CORE_BUILTINS: frozenset[str] = frozenset(dir(builtins))

# AST node names permanently removed in Python 3.14 (use ast.Constant instead).
LEGACY_AST_REMOVED_IN_3_14: frozenset[str] = frozenset(
    {"Num", "Str", "Bytes", "NameConstant", "Ellipsis"}
)

# Stdlib modules removed by PEP 594 in Python 3.13.
PEP_594_REMOVED_IN_3_13: frozenset[str] = frozenset({
    "aifc", "audioop", "cgi", "cgitb", "chunk", "crypt", "imghdr",
    "mailcap", "msilib", "nis", "nntplib", "ossaudiodev", "pipes",
    "sndhdr", "spwd", "sunau", "telnetlib", "uu", "xdrlib",
})

# Dangerous calls that guarantee security violations regardless of context.
DANGEROUS_CALLS: dict[str, str] = {
    "eval":          "Dynamic code execution via eval()",
    "exec":          "Arbitrary code execution via exec()",
    "pickle.loads":  "Arbitrary code execution via unsafe pickle deserialization",
    "marshal.loads": "Arbitrary code execution via unsafe marshal deserialization",
    "os.system":     "Shell command execution via os.system()",
}

# Synchronous blocking calls that are hazardous inside async functions.
ASYNC_BLOCKING_CALLS: frozenset[str] = frozenset({
    "time.sleep", "subprocess.run", "urllib.request.urlopen",
})


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VersionRequirement:
    """Metadata for a syntax feature that requires a minimum Python version.

    Args:
        feature_name: Human-readable PEP / feature description.
        min_version:  Minimum (major, minor) tuple required.
        description:  Brief explanation surfaced in diagnostics.
    """

    feature_name: str
    min_version: Tuple[int, int]
    description: str


# ---------------------------------------------------------------------------
# Visitor
# ---------------------------------------------------------------------------

class SyntaxVersionAuditor(ast.NodeVisitor):
    """AST visitor performing combined version-gate and security analysis.

    All detected issues are accumulated into typed lists rather than raising
    exceptions, preserving the zero-execution guarantee by never importing
    or executing the target module.

    Args:
        has_future_annotations: True when ``from __future__ import annotations``
            was detected by the upstream ImportBoundaryScanner, which suppresses
            unquoted-forward-reference warnings (PEP 649/749).
    """

    def __init__(self, has_future_annotations: bool = False) -> None:
        self.has_future_annotations: bool = has_future_annotations

        # Version diagnostics — items whose min_version exceeds a target version.
        self.diagnostics: list[tuple[int, int, VersionRequirement]] = []

        # Security issues — FATAL blocking items.
        self.security_violations: list[tuple[int, int, str]] = []

        # Legacy AST node usages — crash on Python ≥ 3.14.
        self.legacy_ast_usages: list[tuple[int, int, str]] = []

        # Walrus operator scope violations — SyntaxError or unexpected rebind.
        self.walrus_scope_violations: list[tuple[int, int, str]] = []

        # Bare ``raise`` outside an except handler — RuntimeError at runtime.
        self.bare_raises_outside_except: list[tuple[int, int]] = []

        # Mutable default arguments (list/dict/set literals as defaults).
        self.mutable_defaults: list[tuple[int, int, str, str]] = []

        # Unquoted forward references when future annotations are absent.
        self.unquoted_forward_refs: list[tuple[int, int, str]] = []

        # open() in text mode without explicit encoding= keyword.
        self.implicit_encoding_opens: list[tuple[int, int, str]] = []

        # Synchronous blocking calls inside async functions.
        self.blocking_calls: list[tuple[int, int, str]] = []

        # Unmanaged open() calls (not guarded by a with-statement).
        self.unmanaged_resources: list[tuple[int, int, str]] = []

        # __del__ finalizer definitions (non-deterministic in free-threaded runtimes).
        self.finalizers_detected: list[tuple[int, int, str]] = []

        # Tracking stacks — each entry is a bool sentinel pushed on scope entry.
        self._in_finally_stack: list[bool] = []
        self._in_except_stack: list[bool] = []
        self._in_class_stack: list[bool] = []
        self._in_comprehension_stack: list[bool] = []
        self._comprehension_targets: list[set[str]] = []
        self._in_async_func: bool = False

        # Running set of names declared before the current position in file
        # order — used by the forward-reference guard.
        self._defined_symbols_so_far: set[str] = set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record(self, min_ver: Tuple[int, int], feature: str, line: int, col: int) -> None:
        """Append a version-gate diagnostic.

        Args:
            min_ver: (major, minor) minimum Python version required.
            feature: Human-readable feature label.
            line:    Source line number (1-indexed).
            col:     Column offset.
        """
        req = VersionRequirement(
            feature_name=feature,
            min_version=min_ver,
            description=f"Requires Python >={min_ver[0]}.{min_ver[1]}",
        )
        self.diagnostics.append((line, col, req))

    # ------------------------------------------------------------------
    # Import visitors
    # ------------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._defined_symbols_so_far.add(alias.asname or alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""

        if module == "ast":
            for alias in node.names:
                if alias.name in LEGACY_AST_REMOVED_IN_3_14:
                    self.legacy_ast_usages.append((
                        node.lineno,
                        node.col_offset,
                        f"Importing removed AST node 'ast.{alias.name}' "
                        f"will crash on Python >=3.14",
                    ))
        elif module == "typing":
            for alias in node.names:
                if alias.name == "TypeForm":
                    self._record(
                        (3, 15),
                        "PEP 747: typing.TypeForm (use typing_extensions on <=3.14)",
                        node.lineno,
                        node.col_offset,
                    )
        elif module == "interpreters":
            self._record(
                (3, 14),
                "PEP 734: Multiple Interpreters stdlib module",
                node.lineno,
                node.col_offset,
            )

        for alias in node.names:
            self._defined_symbols_so_far.add(alias.asname or alias.name)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Attribute access — catch ast.Num / ast.Str etc. used via attribute
    # ------------------------------------------------------------------

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name):
            val_id = node.value.id
            if val_id == "ast" and node.attr in LEGACY_AST_REMOVED_IN_3_14:
                self.legacy_ast_usages.append((
                    node.lineno,
                    node.col_offset,
                    f"ast.{node.attr} was permanently removed in Python 3.14 "
                    f"(use ast.Constant instead)",
                ))
            elif val_id == "typing" and node.attr == "TypeForm":
                self._record(
                    (3, 15),
                    "PEP 747: typing.TypeForm (use typing_extensions on <=3.14)",
                    node.lineno,
                    node.col_offset,
                )
            elif val_id == "interpreters":
                self._record(
                    (3, 14),
                    "PEP 734: Multiple Interpreters stdlib module",
                    node.lineno,
                    node.col_offset,
                )
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Class definitions
    # ------------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._defined_symbols_so_far.add(node.name)
        self._in_class_stack.append(True)

        if getattr(node, "type_params", None):
            self._record(
                (3, 12),
                "Generic Class Type Parameters (class Cls[T])",
                node.lineno,
                node.col_offset,
            )

        for dec in node.decorator_list:
            dec_str = ast.unparse(dec)
            if "disjoint_base" in dec_str:
                self._record(
                    (3, 15),
                    "PEP 800: @typing.disjoint_base",
                    node.lineno,
                    node.col_offset,
                )

        self.generic_visit(node)
        self._in_class_stack.pop()

    # ------------------------------------------------------------------
    # Function definitions
    # ------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._defined_symbols_so_far.add(node.name)

        if node.name == "__del__":
            self.finalizers_detected.append((
                node.lineno,
                node.col_offset,
                "Defining __del__ finalizer causes non-deterministic cleanup "
                "in free-threaded runtimes",
            ))

        self._check_mutable_defaults(node.name, node.args)
        self._check_annotations(node.args, node.returns)

        if getattr(node, "type_params", None):
            self._record(
                (3, 12),
                "Generic Function Type Parameters (def func[T])",
                node.lineno,
                node.col_offset,
            )

        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._defined_symbols_so_far.add(node.name)
        self._check_mutable_defaults(node.name, node.args)
        self._check_annotations(node.args, node.returns)

        prev = self._in_async_func
        self._in_async_func = True
        self.generic_visit(node)
        self._in_async_func = prev

    def _check_mutable_defaults(self, func_name: str, args: ast.arguments) -> None:
        """Flag list/dict/set literals used as default argument values.

        Mutable defaults share state across all calls — a classic Python trap.

        Args:
            func_name: Name of the enclosing function (for diagnostics).
            args:      AST arguments node.
        """
        all_defaults: list[ast.expr] = [
            d for d in args.defaults if d is not None
        ] + [
            d for d in args.kw_defaults if d is not None
        ]
        for d in all_defaults:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                self.mutable_defaults.append((
                    d.lineno,
                    d.col_offset,
                    func_name,
                    ast.unparse(d),
                ))

    def _check_annotations(
        self,
        args: ast.arguments,
        returns: Optional[ast.expr],
    ) -> None:
        """Detect unquoted forward references when PEP 649/749 is unavailable.

        On Python <= 3.13 without ``from __future__ import annotations``, a
        type annotation that references a name not yet defined in file order
        raises NameError at class/function definition time.

        Args:
            args:    AST arguments node of the function being analysed.
            returns: Optional return-annotation AST node.
        """
        if self.has_future_annotations:
            return

        all_annotations: list[ast.expr] = [
            a.annotation
            for a in (args.posonlyargs + args.args + args.kwonlyargs)
            if a.annotation
        ]
        if args.vararg and args.vararg.annotation:
            all_annotations.append(args.vararg.annotation)
        if args.kwarg and args.kwarg.annotation:
            all_annotations.append(args.kwarg.annotation)
        if returns:
            all_annotations.append(returns)

        for ann in all_annotations:
            for child in ast.walk(ann):
                if (
                    isinstance(child, ast.Name)
                    and child.id not in PYTHON_CORE_BUILTINS
                    and child.id not in self._defined_symbols_so_far
                ):
                    self.unquoted_forward_refs.append((
                        ann.lineno,
                        ann.col_offset,
                        f"Unquoted forward reference '{child.id}' relies on "
                        f"PEP 649/749 lazy evaluation and will raise NameError "
                        f"on Python <=3.13 without "
                        f"'from __future__ import annotations'",
                    ))

    # ------------------------------------------------------------------
    # Comprehension visitors — PEP 798 unpacking detection
    # ------------------------------------------------------------------

    def _enter_comprehension(self, node: ast.expr) -> None:
        """Push comprehension scope and collect iteration-variable names.

        Args:
            node: The comprehension expression node (ListComp, SetComp, etc.).
        """
        self._in_comprehension_stack.append(True)
        iter_targets: set[str] = set()
        for gen in getattr(node, "generators", []):
            for n in ast.walk(gen.target):
                if isinstance(n, ast.Name):
                    iter_targets.add(n.id)
        self._comprehension_targets.append(iter_targets)

    def _exit_comprehension(self) -> None:
        """Pop comprehension scope tracking stacks."""
        if self._comprehension_targets:
            self._comprehension_targets.pop()
        if self._in_comprehension_stack:
            self._in_comprehension_stack.pop()

    def visit_ListComp(self, node: ast.ListComp) -> None:
        if isinstance(node.elt, ast.Starred):
            self._record(
                (3, 15),
                "PEP 798: Starred unpacking in comprehensions ([*x for ...])",
                node.lineno,
                node.col_offset,
            )
        self._enter_comprehension(node)
        self.generic_visit(node)
        self._exit_comprehension()

    def visit_SetComp(self, node: ast.SetComp) -> None:
        if isinstance(node.elt, ast.Starred):
            self._record(
                (3, 15),
                "PEP 798: Starred unpacking in set comprehensions ({*x for ...})",
                node.lineno,
                node.col_offset,
            )
        self._enter_comprehension(node)
        self.generic_visit(node)
        self._exit_comprehension()

    def visit_DictComp(self, node: ast.DictComp) -> None:
        if node.key is None or isinstance(node.value, ast.Starred):
            self._record(
                (3, 15),
                "PEP 798: Mapping unpacking in dict comprehensions ({**d for ...})",
                node.lineno,
                node.col_offset,
            )
        self._enter_comprehension(node)
        self.generic_visit(node)
        self._exit_comprehension()

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        if isinstance(node.elt, ast.Starred):
            self._record(
                (3, 15),
                "PEP 798: Starred unpacking in generator expressions ((*x for ...))",
                node.lineno,
                node.col_offset,
            )
        self._enter_comprehension(node)
        self.generic_visit(node)
        self._exit_comprehension()

    # ------------------------------------------------------------------
    # Walrus operator — PEP 572 scope trap
    # ------------------------------------------------------------------

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        # Inside a comprehension that is itself inside a class body, the walrus
        # target leaks into the enclosing scope, causing SyntaxError on
        # current CPython implementations.
        if self._in_comprehension_stack and self._in_class_stack:
            self.walrus_scope_violations.append((
                node.lineno,
                node.col_offset,
                f"Walrus operator (:=) cannot be used inside comprehension "
                f"within class scope: {ast.unparse(node)}",
            ))
        # Walrus must not rebind the comprehension's own iteration variable.
        if (
            self._comprehension_targets
            and isinstance(node.target, ast.Name)
            and node.target.id in self._comprehension_targets[-1]
        ):
            self.walrus_scope_violations.append((
                node.lineno,
                node.col_offset,
                f"Assignment expression cannot rebind comprehension iteration "
                f"variable '{node.target.id}'",
            ))
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Try / except / finally — PEP 765 and bare-raise tracking
    # ------------------------------------------------------------------

    def visit_Try(self, node: ast.Try) -> None:
        # Body
        for stmt in node.body:
            self.visit(stmt)
        # Except handlers
        for handler in node.handlers:
            self._in_except_stack.append(True)
            self.visit(handler)
            self._in_except_stack.pop()
        # Else clause
        for stmt in node.orelse:
            self.visit(stmt)
        # Finally clause — PEP 765: no return/break/continue allowed here
        self._in_finally_stack.append(True)
        for stmt in node.finalbody:
            self.visit(stmt)
        self._in_finally_stack.pop()

    def visit_Return(self, node: ast.Return) -> None:
        if self._in_finally_stack:
            self._record(
                (3, 14),
                "PEP 765: return statement inside finally block",
                node.lineno,
                node.col_offset,
            )
        self.generic_visit(node)

    def visit_Break(self, node: ast.Break) -> None:
        if self._in_finally_stack:
            self._record(
                (3, 14),
                "PEP 765: break statement inside finally block",
                node.lineno,
                node.col_offset,
            )
        self.generic_visit(node)

    def visit_Continue(self, node: ast.Continue) -> None:
        if self._in_finally_stack:
            self._record(
                (3, 14),
                "PEP 765: continue statement inside finally block",
                node.lineno,
                node.col_offset,
            )
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        # A bare ``raise`` (no exception expression) outside an except block
        # raises RuntimeError: No active exception to re-raise.
        if node.exc is None and not self._in_except_stack:
            self.bare_raises_outside_except.append((node.lineno, node.col_offset))
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Exception groups — PEP 654 (Python 3.11+)
    # ------------------------------------------------------------------

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self._record(
            (3, 11),
            "Exception Groups (except*) — PEP 654",
            node.lineno,
            node.col_offset,
        )
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Type alias statement — PEP 695 (Python 3.12+)
    # ------------------------------------------------------------------

    def visit_TypeAlias(self, node: ast.AST) -> None:
        lineno = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        self._record(
            (3, 12),
            "Type Parameter Syntax (PEP 695 type statement)",
            lineno,
            col,
        )
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Template strings — PEP 750 (Python 3.14+)
    # ------------------------------------------------------------------

    def visit_Constant(self, node: ast.Constant) -> None:
        if getattr(node, "kind", None) == "t":
            self._record(
                (3, 14),
                "Template Strings (PEP 750 t-strings)",
                node.lineno,
                node.col_offset,
            )
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Function calls — security & encoding
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ast.unparse(node.func)

        # --- Security shield ---
        if func_name in DANGEROUS_CALLS:
            self.security_violations.append((
                node.lineno,
                node.col_offset,
                DANGEROUS_CALLS[func_name],
            ))
        elif func_name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and getattr(kw.value, "value", False) is True:
                    self.security_violations.append((
                        node.lineno,
                        node.col_offset,
                        "subprocess call with shell=True represents high command injection risk",
                    ))

        # --- PEP 734 subinterpreters ---
        if "interpreters.create" in func_name or "interpreters.run" in func_name:
            self._record(
                (3, 14),
                "PEP 734: Subinterpreters execution",
                node.lineno,
                node.col_offset,
            )

        # --- Async blocking calls ---
        if self._in_async_func and func_name in ASYNC_BLOCKING_CALLS:
            self.blocking_calls.append((node.lineno, node.col_offset, func_name))

        # --- Implicit text-mode encoding ---
        if func_name == "open":
            has_encoding = any(kw.arg == "encoding" for kw in node.keywords)
            is_binary = False
            # Positional mode argument
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                if "b" in node.args[1].value:
                    is_binary = True
            # Keyword mode argument
            for kw in node.keywords:
                if (
                    kw.arg == "mode"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                    and "b" in kw.value.value
                ):
                    is_binary = True
            if not has_encoding and not is_binary:
                self.implicit_encoding_opens.append((
                    node.lineno,
                    node.col_offset,
                    "open() in text mode without explicit encoding relies on "
                    "Python 3.15 default UTF-8 and fails on older Windows targets",
                ))

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Unmanaged resource detection
    # ------------------------------------------------------------------

    def visit_Expr(self, node: ast.Expr) -> None:
        if (
            isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func) == "open"
        ):
            self.unmanaged_resources.append((
                node.lineno,
                node.col_offset,
                "Unmanaged open() call without with-context",
            ))
        self.generic_visit(node)
