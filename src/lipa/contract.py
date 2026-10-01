"""
Contract Module - Type-Safe Symbol Definition & Validation

Implements type-safe contract definitions for audit symbols using
Python's typing system with AST analysis and PEP compliance.

Blueprint Reference: Lines 236-400 (Local Ingress Pre-flight.md)
Performance Target: < 50ms per file
"""

from __future__ import annotations

import ast
import dataclasses
import sys
import warnings
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TypeVar, Generic, Optional, List, Dict, Any


if sys.version_info >= (3, 11):
    from typing import final
else:
    def final(cls: type) -> type:
        """Decorator to mark class as not intended for subclassing."""
        cls.__final__ = True
        return cls


class ParameterKind(Enum):
    """Parameter position kinds per PEP 3107 (type hints)."""
    POSITIONAL_ONLY = auto()      # Before /
    POSITION_OR_KEYWORD = auto()  # Default
    KEYWORD_ONLY = auto()         # After *


class SymbolKind(Enum):
    """Symbol classification for module contract."""
    CLASS = auto()
    FUNCTION = auto()
    VARIABLE = auto()
    MODULE = auto()
    ASYNC_GENERATOR = auto()    # async def with yield


@dataclass(frozen=True)
class ParameterContract:
    """Complete parameter contract with position, annotation, and default."""

    name: str
    kind: ParameterKind
    annotation: Optional[str] = None
    has_default: bool = False
    is_var_positional: bool = False   # *args
    is_var_keyword: bool = False      # **kwargs

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ParameterContract):
            return NotImplemented
        return (
            self.name == other.name
            and self.kind == other.kind
            and self.annotation == other.annotation
            and self.has_default == other.has_default
            and self.is_var_positional == other.is_var_positional
            and self.is_var_keyword == other.is_var_keyword
        )


@dataclass(frozen=True)
class CallableSignature:
    """Complete function signature with all parameters."""

    name: str
    params: List[ParameterContract] = field(default_factory=list)
    return_annotation: Optional[str] = None
    is_async: bool = False
    has_yield: bool = False           # Generator detection
    is_final: bool = False            # PEP 591 @final method
    is_generator: bool = False        # Has yield
    is_deprecated: bool = False       # @deprecated decorator or warnings.warn() in body
    deprecation_msg: Optional[str] = None
    kind: Optional["SymbolKind"] = None  # Fine-grained classification (ASYNC_GENERATOR etc.)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CallableSignature):
            return NotImplemented
        return (
            self.name == other.name
            and self.params == other.params
            and self.return_annotation == other.return_annotation
            and self.is_async == other.is_async
            and self.has_yield == other.has_yield
            and self.is_final == other.is_final
            and self.is_generator == other.is_generator
            and self.is_deprecated == other.is_deprecated
            and self.deprecation_msg == other.deprecation_msg
        )


@dataclass(frozen=True)
class DataclassFieldContract:
    """Dataclass field with metadata per PEP 557."""

    name: str
    annotation: Optional[str] = None
    has_default: bool = False
    default_value: Optional[Any] = None
    is_kw_only: bool = False          # kw_only=True in field()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DataclassFieldContract):
            return NotImplemented
        return (
            self.name == other.name
            and self.annotation == other.annotation
            and self.has_default == other.has_default
            and self.default_value == other.default_value
            and self.is_kw_only == other.is_kw_only
        )


@dataclass(frozen=True)
class ClassContract:
    """Complete class contract with methods, attributes, and decorators."""

    name: str
    bases: List[str] = field(default_factory=list)
    keywords: List[tuple[str, str]] = field(default_factory=list)
    methods: Dict[str, CallableSignature] = field(default_factory=dict)
    attributes: Dict[str, Any] = field(default_factory=dict)

    # Special flags
    is_final: bool = False            # PEP 591 @final class
    is_protocol: bool = False         # PEP 544 Protocol
    is_dataclass: bool = False        # PEP 557 @dataclass
    is_typed_dict: bool = False       # PEP 728 TypedDict
    is_closed_typed_dict: bool = True # total=True (default) vs total=False

    # Inheritance chain tracking
    inherits_from_final: bool = False

    # Dataclass fields extracted from class body
    dataclass_fields: List[DataclassFieldContract] = field(default_factory=list)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ClassContract):
            return NotImplemented
        return (
            self.name == other.name
            and self.bases == other.bases
            and self.keywords == other.keywords
            and self.methods == other.methods
            and self.attributes == other.attributes
            and self.is_final == other.is_final
            and self.is_protocol == other.is_protocol
            and self.is_dataclass == other.is_dataclass
            and self.is_typed_dict == other.is_typed_dict
            and self.is_closed_typed_dict == other.is_closed_typed_dict
            and self.dataclass_fields == other.dataclass_fields
        )


@dataclass(frozen=True)
class SymbolContractGroup:
    """Group of overloaded function variants (PEP 496)."""

    name: str
    variants: List[CallableSignature] = field(default_factory=list)
    is_overloaded: bool = False

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SymbolContractGroup):
            return NotImplemented
        return (
            self.name == other.name
            and self.variants == other.variants
            and self.is_overloaded == other.is_overloaded
        )


@dataclass(frozen=True)
class TypeVarBound:
    """TypeVar with bound information."""

    name: str
    bound: Optional[str] = None       # e.g., "BaseClass"
    constraints: List[str] = field(default_factory=list)  # e.g., ["str", "int"]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TypeVarBound):
            return NotImplemented
        return (
            self.name == other.name
            and self.bound == other.bound
            and self.constraints == other.constraints
        )

    def __contains__(self, item: str) -> bool:
        """Enable `"BaseClass" in bound` membership test against bound and constraints.

        Checks whether ``item`` is a substring of the bound annotation or any
        constraint string, matching the natural way tests read:
        ``assert "BaseClass" in bound``.
        """
        if self.bound is not None and item in self.bound:
            return True
        return any(item in c for c in self.constraints)


@dataclass(frozen=True)
class ModuleContract:
    """Complete module contract with exported symbols."""

    name: str = ""
    functions: Dict[str, CallableSignature] = field(default_factory=dict)
    classes: Dict[str, ClassContract] = field(default_factory=dict)
    variables: Dict[str, Any] = field(default_factory=dict)
    typevar_bounds: Dict[str, TypeVarBound] = field(default_factory=dict)
    symbol_groups: Dict[str, SymbolContractGroup] = field(default_factory=dict)

    # Exported symbols (from __all__ or public names)
    exported_symbols: set[str] = field(default_factory=set)

    # Callables — union of functions and class methods for easy access
    callables: Dict[str, SymbolContractGroup] = field(default_factory=dict)

    # Breaking change tracking
    removed_symbols: List[str] = field(default_factory=list)
    added_symbols: List[str] = field(default_factory=list)


class SignatureExtractor(ast.NodeVisitor):
    """AST visitor for extracting type-safe signatures from Python source."""

    def __init__(self, module_name: str) -> None:
        self.module_name = module_name
        self.functions: Dict[str, CallableSignature] = {}
        self.classes: Dict[str, ClassContract] = {}
        self.variables: Dict[str, Any] = {}
        self.typevar_bounds: Dict[str, TypeVarBound] = {}
        self.symbol_groups: Dict[str, SymbolContractGroup] = {}

        # Name of the class currently being visited, or None at module level
        self._current_class: Optional[str] = None
        # Staging: class_name -> mutable methods dict built during generic_visit.
        # Methods cannot be injected into a frozen ClassContract directly, so we
        # accumulate them here and rebuild the dataclass with dataclasses.replace().
        self._class_methods: Dict[str, Dict[str, CallableSignature]] = {}
        # Indirect TypedDict subclass registry — populated on each visit_ClassDef
        self._typeddict_registry: set[str] = {"TypedDict"}
        # Indirect Protocol subclass registry
        self._protocol_registry: set[str] = {"Protocol"}

    def visit(self, node: ast.AST) -> None:  # type: ignore[override]
        super().visit(node)

    # ------------------------------------------------------------------
    # Parameter extraction
    # ------------------------------------------------------------------

    def _extract_params(
        self,
        args: ast.arguments,
        is_async: bool = False,
    ) -> List[ParameterContract]:
        """Extract all parameter kinds per PEP 3107 with correct default alignment."""
        params: List[ParameterContract] = []

        # Positional-only (before /)
        for arg in args.posonlyargs:
            params.append(ParameterContract(
                name=arg.arg,
                kind=ParameterKind.POSITIONAL_ONLY,
                annotation=ast.unparse(arg.annotation) if arg.annotation else None,
                has_default=False,
            ))

        # Positional-or-keyword — defaults are right-aligned
        n_defaults = len(args.defaults)
        n_args = len(args.args)
        for i, arg in enumerate(args.args):
            has_default = i >= (n_args - n_defaults)
            params.append(ParameterContract(
                name=arg.arg,
                kind=ParameterKind.POSITION_OR_KEYWORD,
                annotation=ast.unparse(arg.annotation) if arg.annotation else None,
                has_default=has_default,
            ))

        # *args
        if args.vararg:
            params.append(ParameterContract(
                name=args.vararg.arg,
                kind=ParameterKind.POSITION_OR_KEYWORD,
                annotation=ast.unparse(args.vararg.annotation) if args.vararg.annotation else None,
                has_default=False,
                is_var_positional=True,
            ))

        # Keyword-only (after *)
        for i, arg in enumerate(args.kwonlyargs):
            has_default = (
                i < len(args.kw_defaults) and args.kw_defaults[i] is not None
            )
            params.append(ParameterContract(
                name=arg.arg,
                kind=ParameterKind.KEYWORD_ONLY,
                annotation=ast.unparse(arg.annotation) if arg.annotation else None,
                has_default=has_default,
            ))

        # **kwargs
        if args.kwarg:
            params.append(ParameterContract(
                name=args.kwarg.arg,
                kind=ParameterKind.KEYWORD_ONLY,
                annotation=ast.unparse(args.kwarg.annotation) if args.kwarg.annotation else None,
                has_default=False,
                is_var_keyword=True,
            ))

        return params

    # ------------------------------------------------------------------
    # Decorator analysis
    # ------------------------------------------------------------------

    def _check_decorators(
        self,
        node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> Dict[str, Any]:
        """Extract decorator flags: @final, @dataclass, @overload, @deprecated."""
        flags: Dict[str, Any] = {
            "is_final": False,
            "is_dataclass": False,
            "is_overloaded": False,
            "is_deprecated": False,
            "deprecation_msg": None,
        }

        for dec in node.decorator_list:
            dec_name: Optional[str] = None
            dec_args: list[ast.expr] = []
            dec_kwargs: list[ast.keyword] = []

            if isinstance(dec, ast.Name):
                dec_name = dec.id
            elif isinstance(dec, ast.Attribute):
                dec_name = dec.attr
            elif isinstance(dec, ast.Call):
                dec_args = dec.args
                dec_kwargs = dec.keywords
                if isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    dec_name = dec.func.attr

            if dec_name == "final":
                flags["is_final"] = True
            elif dec_name == "dataclass":
                flags["is_dataclass"] = True
            elif dec_name == "overload":
                flags["is_overloaded"] = True
            elif dec_name == "deprecated":
                flags["is_deprecated"] = True
                if dec_args:
                    flags["deprecation_msg"] = ast.unparse(dec_args[0])

        return flags

    def _extract_keywords(self, node: ast.ClassDef) -> List[tuple[str, str]]:
        """Extract base class keywords (e.g., total=False)."""
        return [
            (kw.arg or "", ast.unparse(kw.value) if kw.value else "None")
            for kw in node.keywords
        ]

    # ------------------------------------------------------------------
    # Helper predicates
    # ------------------------------------------------------------------

    def _has_yield(
        self, func_node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> bool:
        """Return True if the function body contains a yield expression."""
        return any(
            isinstance(child, (ast.Yield, ast.YieldFrom))
            for child in ast.walk(func_node)
        )

    def _is_typeddict_base(self, base_names: List[str]) -> bool:
        """True if any base is TypedDict or a known TypedDict subclass."""
        return any(
            b in self._typeddict_registry or "TypedDict" in b
            for b in base_names
        )

    def _is_protocol_base(self, base_names: List[str]) -> bool:
        """True if any base is Protocol or a known Protocol subclass."""
        return any(
            b in self._protocol_registry or "Protocol" in b
            for b in base_names
        )

    # ------------------------------------------------------------------
    # Dataclass field extraction
    # ------------------------------------------------------------------

    def _extract_dataclass_fields(
        self, class_node: ast.ClassDef
    ) -> List[DataclassFieldContract]:
        """Extract PEP 557 fields from annotated assignments in the class body."""
        fields: List[DataclassFieldContract] = []
        for item in class_node.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                name = item.target.id
                annotation = ast.unparse(item.annotation) if item.annotation else None
                # Detect kw_only=True inside field(kw_only=True)
                is_kw = False
                if (
                    item.value is not None
                    and isinstance(item.value, ast.Call)
                    and isinstance(item.value.func, ast.Name)
                    and item.value.func.id == "field"
                ):
                    for kw in item.value.keywords:
                        if kw.arg == "kw_only":
                            is_kw = (
                                isinstance(kw.value, ast.Constant)
                                and bool(kw.value.value)
                            )
                fields.append(DataclassFieldContract(
                    name=name,
                    annotation=annotation,
                    has_default=item.value is not None,
                    default_value=None,
                    is_kw_only=is_kw,
                ))
        return fields

    # ------------------------------------------------------------------
    # Function visitor (sync + async share the same processor)
    # ------------------------------------------------------------------

    def _process_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Shared handler for synchronous and async function/method definitions."""
        is_async = isinstance(node, ast.AsyncFunctionDef)
        dec_flags = self._check_decorators(node)
        params = self._extract_params(node.args, is_async=is_async)
        return_ann = ast.unparse(node.returns) if node.returns else None
        has_yield = self._has_yield(node)

        # Detect warnings.warn(..., DeprecationWarning) in the function body —
        # covers the common pre-PEP-702 deprecation pattern that @deprecated
        # does not handle.
        is_deprecated = dec_flags.get("is_deprecated", False)
        deprecation_msg = dec_flags.get("deprecation_msg")
        if not is_deprecated:
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                # Match warnings.warn(...) or warn(...)
                func = child.func
                func_name: Optional[str] = None
                if isinstance(func, ast.Attribute) and func.attr == "warn":
                    func_name = "warn"
                elif isinstance(func, ast.Name) and func.id == "warn":
                    func_name = "warn"
                if func_name != "warn":
                    continue
                # Check if any argument is DeprecationWarning or its subclasses
                all_args = list(child.args) + [kw.value for kw in child.keywords]
                for arg in all_args:
                    arg_src = ast.unparse(arg)
                    if "DeprecationWarning" in arg_src or "PendingDeprecationWarning" in arg_src:
                        is_deprecated = True
                        # First positional arg is the message string, if present
                        if child.args:
                            deprecation_msg = ast.unparse(child.args[0])
                        break
                if is_deprecated:
                    break

        # Classify fine-grained kind for async generators.
        kind: Optional[SymbolKind] = None
        if is_async and has_yield:
            kind = SymbolKind.ASYNC_GENERATOR

        sig = CallableSignature(
            name=node.name,
            params=params,
            return_annotation=return_ann,
            is_async=is_async,
            has_yield=has_yield,
            is_final=dec_flags.get("is_final", False),
            is_generator=has_yield,
            is_deprecated=is_deprecated,
            deprecation_msg=deprecation_msg,
            kind=kind,
        )

        if self._current_class:
            # Accumulate into the staging dict; merged after generic_visit finishes
            self._class_methods.setdefault(self._current_class, {})[node.name] = sig
        else:
            is_overloaded = dec_flags.get("is_overloaded", False)
            if node.name in self.symbol_groups:
                # Second+ @overload variant — mark the group
                existing = self.symbol_groups[node.name]
                self.symbol_groups[node.name] = SymbolContractGroup(
                    name=node.name,
                    variants=list(existing.variants) + [sig],
                    is_overloaded=True,
                )
            else:
                self.symbol_groups[node.name] = SymbolContractGroup(
                    name=node.name,
                    variants=[sig],
                    is_overloaded=is_overloaded,
                )
            if has_yield:
                self.variables[node.name] = "generator"
            else:
                self.functions[node.name] = sig

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit synchronous function definition."""
        self._process_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function or async-generator definition."""
        self._process_function(node)

    # ------------------------------------------------------------------
    # Class visitor
    # ------------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definition and extract the full ClassContract."""
        bases: List[str] = [ast.unparse(b) for b in node.bases if b is not None]
        keywords = self._extract_keywords(node)
        dec_flags = self._check_decorators(node)

        is_td = self._is_typeddict_base(bases)
        is_proto = self._is_protocol_base(bases)

        # Closed TypedDict: total=True (or absent) means closed
        is_closed_td = True
        for kw, val in keywords:
            if kw == "total":
                is_closed_td = val.strip() not in ("False", "'False'", '"False"')

        # Dataclass field extraction must happen before generic_visit so the AST
        # node is still in its original, unmodified form
        dc_fields: List[DataclassFieldContract] = (
            self._extract_dataclass_fields(node)
            if dec_flags.get("is_dataclass")
            else []
        )

        # Populate indirect-detection registries so later subclass visits work
        if is_td:
            self._typeddict_registry.add(node.name)
        if is_proto:
            self._protocol_registry.add(node.name)

        # Build initial contract with empty methods (filled after generic_visit)
        class_contract = ClassContract(
            name=node.name,
            bases=bases,
            keywords=keywords,
            methods={},
            attributes={},
            is_final=dec_flags.get("is_final", False),
            is_protocol=is_proto,
            is_dataclass=dec_flags.get("is_dataclass", False),
            is_typed_dict=is_td,
            is_closed_typed_dict=is_closed_td,
            dataclass_fields=dc_fields,
        )
        self.classes[node.name] = class_contract

        # Push context and visit children (visit_FunctionDef fills staging dict)
        old_ctx = self._current_class
        self._current_class = node.name
        self._class_methods.setdefault(node.name, {})
        self.generic_visit(node)
        self._current_class = old_ctx

        # Merge staged methods back — ClassContract is frozen so rebuild via replace()
        staged = self._class_methods.get(node.name, {})
        if staged:
            self.classes[node.name] = dataclasses.replace(
                class_contract, methods=staged
            )

    # ------------------------------------------------------------------
    # Variable visitors
    # ------------------------------------------------------------------

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Visit annotated assignment at module level (variable declaration)."""
        if not self._current_class and isinstance(node.target, ast.Name):
            name = node.target.id
            self.variables[name] = {
                "annotation": ast.unparse(node.annotation) if node.annotation else None,
                "value": ast.unparse(node.value) if node.value else None,
            }

    def visit_Assign(self, node: ast.Assign) -> None:
        """Extract TypeVar bound/constraint definitions at module level.

        Matches the pattern:  T = TypeVar("T", bound=BaseClass)
        """
        if self._current_class:
            return
        if not (len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)):
            return
        tv_name = node.targets[0].id
        if not (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "TypeVar"
        ):
            return
        bound: Optional[str] = None
        constraints: List[str] = (
            [ast.unparse(a) for a in node.value.args[1:]]
            if len(node.value.args) > 1
            else []
        )
        for kw in node.value.keywords:
            if kw.arg == "bound":
                bound = ast.unparse(kw.value)
        self.typevar_bounds[tv_name] = TypeVarBound(
            name=tv_name,
            bound=bound,
            constraints=constraints,
        )

    # ------------------------------------------------------------------
    # Finalization
    # ------------------------------------------------------------------

    def finalize(self) -> ModuleContract:
        """Finalize extraction and return the complete ModuleContract."""
        exported: set[str] = set()
        if "__all__" in self.variables:
            all_value = self.variables["__all__"]
            if isinstance(all_value, list):
                exported.update(str(i) for i in all_value if isinstance(i, str))
        exported.update(self.functions.keys())
        exported.update(self.classes.keys())
        exported.update(self.variables.keys())

        return ModuleContract(
            name=self.module_name,
            functions=dict(self.functions),
            classes=dict(self.classes),
            variables=dict(self.variables),
            typevar_bounds=dict(self.typevar_bounds),
            symbol_groups=dict(self.symbol_groups),
            callables=dict(self.symbol_groups),
            exported_symbols=exported,
        )


def extract_signature(source: str, module_name: str = "unknown") -> ModuleContract:
    """Convenience function to extract a ModuleContract from source code string."""
    tree = ast.parse(source)
    extractor = SignatureExtractor(module_name)
    extractor.visit(tree)
    return extractor.finalize()
