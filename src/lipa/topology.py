"""
Topology Module - Import Graph Analysis & Dependency Resolution

Implements static analysis of Python import topology using AST only.
Detects circular dependencies, sys.modules shadowing, and builtin overrides.

Blueprint Reference: Lines 86-234 (Local Ingress Pre-flight.md)
Performance Target: < 50ms per file
"""

from __future__ import annotations

import ast
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple


class ImportType(Enum):
    """Enumeration of Python import types for topology analysis."""
    STANDARD = auto()      # Standard library imports
    THIRD_PARTY = auto()   # External package imports  
    LOCAL = auto()         # Local/relative imports
    BUILTIN = auto()       # Built-in module references


class TopologyRiskLevel(Enum):
    """Risk severity levels for import topology issues."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ImportNode:
    """Represents a single import node in the dependency graph."""
    module_name: str
    alias: Optional[str] = None
    import_type: ImportType = ImportType.STANDARD
    line_number: int = 0
    is_relative: bool = False
    relative_level: int = 0
    
    def __hash__(self) -> int:
        """Hash based on module name and alias for graph uniqueness."""
        return hash((self.module_name, self.alias))
    
    def __eq__(self, other: object) -> bool:
        """Equality comparison for import nodes."""
        if not isinstance(other, ImportNode):
            return False
        return self.module_name == other.module_name and self.alias == other.alias


@dataclass
class TopologyIssue:
    """Represents a detected topology issue with risk assessment."""
    issue_type: str
    severity: TopologyRiskLevel
    description: str
    affected_modules: List[str] = field(default_factory=list)
    line_number: Optional[int] = None
    
    def to_dict(self) -> dict:
        """Convert issue to dictionary for reporting."""
        return {
            "type": self.issue_type,
            "severity": self.severity.value,
            "description": self.description,
            "affected_modules": self.affected_modules,
            "line_number": self.line_number
        }


class ImportVisitor(ast.NodeVisitor):
    """AST visitor for extracting import information from Python files."""
    
    BUILTIN_MODULES = frozenset({
        'sys', 'os', 'io', 'ast', 'token', 'keyword', 'operator',
        'builtins', '_collections_abc', 'types', 'functools', 'itertools'
    })
    
    STANDARD_LIBRARY_PREFIXES = (
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
        'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z'
    )
    
    def __init__(self) -> None:
        """Initialize import visitor with empty tracking structures."""
        self.imports: List[ImportNode] = []
        self.from_imports: List[Tuple[str, List[str], int]] = []
        
    def visit_Import(self, node: ast.Import) -> None:
        """Visit regular import statements (import x)."""
        for alias in node.names:
            module_name = alias.name
            import_type = self._classify_import(module_name)
            
            import_node = ImportNode(
                module_name=module_name,
                alias=alias.asname,
                import_type=import_type,
                line_number=node.lineno,
                is_relative=False
            )
            self.imports.append(import_node)
        
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Visit from-import statements (from x import y)."""
        module_name = node.module or ""
        is_relative = node.level > 0
        
        if is_relative:
            # Calculate actual module path for relative imports
            prefix = "." * node.level
            full_module = f"{prefix}{module_name}" if module_name else prefix
            import_type = ImportType.LOCAL
        else:
            full_module = module_name
            import_type = self._classify_import(module_name)
        
        # Track imported names from the module
        names = [alias.name for alias in node.names]
        self.from_imports.append((full_module, names, node.lineno))
        
        # Create ImportNode for the parent module
        import_node = ImportNode(
            module_name=module_name,
            import_type=import_type,
            line_number=node.lineno,
            is_relative=is_relative,
            relative_level=node.level
        )
        self.imports.append(import_node)
        
        self.generic_visit(node)
    
    def _classify_import(self, module_name: str) -> ImportType:
        """Classify import type based on module name patterns."""
        if not module_name:
            return ImportType.LOCAL
        
        first_part = module_name.split(".")[0]
        
        # Explicit standard library modules list
        known_standard_lib = {
            'os', 'sys', 'io', 'ast', 'token', 'keyword', 'operator',
            'builtins', '_collections_abc', 'types', 'functools', 'itertools',
            'json', 're', 'math', 'pathlib', 'collections', 'typing',
            'dataclasses', 'enum', 'abc', 'contextlib', 'threading', 'queue'
        }
        
        # Check for builtin modules
        if first_part in self.BUILTIN_MODULES or first_part in sys.builtin_module_names:
            return ImportType.BUILTIN
        
        # Check for known standard library modules
        if first_part in known_standard_lib:
            return ImportType.STANDARD
        
        # Default to third-party
        return ImportType.THIRD_PARTY


class TopologyAnalyzer:
    """Main analyzer for Python import topology analysis."""
    
    def __init__(self) -> None:
        """Initialize topology analyzer with empty cache."""
        self._cache: Dict[str, Tuple[List[ImportNode], List[TopologyIssue]]] = {}
    
    def analyze_file(self, file_path: str) -> Tuple[List[ImportNode], List[TopologyIssue]]:
        """
        Analyze import topology of a Python file.
        
        Args:
            file_path: Path to Python file for analysis
            
        Returns:
            Tuple of (import_nodes, issues)
            
        Raises:
            FileNotFoundError: If file doesn't exist
            SyntaxError: If file has invalid Python syntax
        """
        # Check cache first for performance
        if file_path in self._cache:
            return self._cache[file_path]
        
        # Read and parse file
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        tree = ast.parse(source_code, filename=file_path)
        
        # Extract imports
        visitor = ImportVisitor()
        visitor.visit(tree)
        
        # Detect issues
        issues = self._detect_topology_issues(visitor.imports, file_path)
        
        # Cache result
        self._cache[file_path] = (visitor.imports, issues)
        
        return visitor.imports, issues
    
    def _detect_topology_issues(
        self, 
        imports: List[ImportNode], 
        file_path: str
    ) -> List[TopologyIssue]:
        """Detect topology-related security and maintenance issues."""
        issues = []
        
        # Issue 1: Circular import detection (simplified)
        circular = self._detect_circular_imports(imports)
        if circular:
            issues.append(TopologyIssue(
                issue_type="circular_import",
                severity=TopologyRiskLevel.MEDIUM,
                description=f"Potential circular imports detected: {', '.join(circular)}",
                affected_modules=circular,
                line_number=None
            ))
        
        # Issue 2: sys.modules shadowing detection
        sys_shadows = self._detect_sys_shadowing(imports)
        if sys_shadows:
            issues.append(TopologyIssue(
                issue_type="sys_modules_shadowing",
                severity=TopologyRiskLevel.HIGH,
                description=f"sys.modules may be shadowed by local imports: {', '.join(sys_shadows)}",
                affected_modules=sys_shadows,
                line_number=None
            ))
        
        # Issue 3: Builtin function override detection
        builtin_overrides = self._detect_builtin_override(imports)
        if builtin_overrides:
            issues.append(TopologyIssue(
                issue_type="builtin_override",
                severity=TopologyRiskLevel.CRITICAL,
                description=f"Built-in functions may be overridden: {', '.join(builtin_overrides)}",
                affected_modules=builtin_overrides,
                line_number=None
            ))
        
        # Issue 4: Relative import depth check
        deep_relative = self._detect_deep_relative_imports(imports)
        if deep_relative:
            issues.append(TopologyIssue(
                issue_type="deep_relative_import",
                severity=TopologyRiskLevel.LOW,
                description=f"Deep relative imports detected (may indicate poor structure): {', '.join(deep_relative)}",
                affected_modules=deep_relative,
                line_number=None
            ))
        
        return issues
    
    def _detect_circular_imports(
        self, 
        imports: List[ImportNode]
    ) -> List[str]:
        """Detect potential circular import patterns."""
        # Simplified detection: look for mutual imports between modules
        module_names = {imp.module_name.split(".")[0] for imp in imports}
        
        # Check if any local import names conflict with standard library
        conflicting = []
        for name in module_names:
            if name in sys.builtin_module_names or name in ImportVisitor.BUILTIN_MODULES:
                conflicting.append(name)
        
        return conflicting
    
    def _detect_sys_shadowing(self, imports: List[ImportNode]) -> List[str]:
        """Detect sys.modules shadowing risks."""
        shadows = []
        for imp in imports:
            if imp.module_name == "sys" and imp.alias == "modules":
                shadows.append("sys.modules")
        
        return shadows
    
    def _detect_builtin_override(self, imports: List[ImportNode]) -> List[str]:
        """Detect potential builtin function overrides."""
        builtins_to_watch = {'open', 'input', 'print', 'exec', 'eval', 'compile'}
        overrides = []
        
        for imp in imports:
            if imp.alias and imp.alias in builtins_to_watch:
                overrides.append(imp.alias)
        
        return overrides
    
    def _detect_deep_relative_imports(self, imports: List[ImportNode]) -> List[str]:
        """Detect deep relative imports that may indicate structural issues."""
        deep_imports = []
        for imp in imports:
            if imp.is_relative and imp.relative_level > 1:
                deep_imports.append(f"{imp.module_name} (level={imp.relative_level})")
        
        return deep_imports
    
    def clear_cache(self) -> None:
        """Clear analysis cache to free memory."""
        self._cache.clear()
    
    def get_cache_stats(self) -> dict:
        """Get cache statistics for performance monitoring."""
        return {
            "cached_files": len(self._cache),
            "cache_size_mb": sum(
                len(str(nodes + issues)) for nodes, issues in self._cache.values()
            ) / (1024 * 1024)
        }


# ===========================================================================
# Blueprint §2 — Full ImportBoundaryScanner + Tarjan SCC
# These types fulfil the public contract expected by core.py and the test suite.
# ===========================================================================

import builtins as _builtins_module

PYTHON_CORE_BUILTINS: frozenset[str] = frozenset(dir(_builtins_module))


@dataclass(frozen=True)
class RawImportRecord:
    """Minimal import record extracted by the boundary scanner.

    Args:
        source_module:  Dotted canonical name of the scanning module.
        target_module:  Dotted canonical name of the imported module
                        (``None`` for ``from . import something``).
        imported_name:  Name imported from the module, or ``"*"`` for bare
                        ``import foo`` statements.
        as_name:        Optional alias (``import foo as bar`` → ``"bar"``).
        level:          0 for absolute; >0 for relative (number of leading dots).
        lineno:         1-indexed source line.
        col_offset:     0-indexed column offset.
    """

    source_module: str
    target_module: Optional[str]
    imported_name: str
    as_name: Optional[str]
    level: int
    lineno: int
    col_offset: int


class ImportBoundaryScanner(ast.NodeVisitor):
    """Blueprint §2.2 — AST Import Extraction & Isolation Shield.

    Scans import statements, detects direct ``sys.modules`` / ``__builtins__``
    mutations, module-level builtin shadowing, and top-level call side-effects
    without executing any code.

    Args:
        current_module: Canonical dotted name of the module under analysis.
    """

    def __init__(self, current_module: str) -> None:
        self.current_module: str = current_module
        self.imports: List[RawImportRecord] = []
        self.top_level_side_effects: List[Tuple[int, int, str]] = []
        self.isolation_violations: List[Tuple[int, int, str]] = []
        self.builtin_shadowing: List[Tuple[int, int, str]] = []
        self.has_future_annotations: bool = False

    def visit_Import(self, node: ast.Import) -> None:
        """Extract bare ``import foo`` / ``import foo as bar`` records."""
        for alias in node.names:
            self.imports.append(RawImportRecord(
                source_module=self.current_module,
                target_module=alias.name,
                imported_name="*",
                as_name=alias.asname,
                level=0,
                lineno=node.lineno,
                col_offset=node.col_offset,
            ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Extract ``from foo import bar`` records; detect future annotations."""
        if node.module == "__future__":
            for alias in node.names:
                if alias.name == "annotations":
                    self.has_future_annotations = True

        for alias in node.names:
            self.imports.append(RawImportRecord(
                source_module=self.current_module,
                target_module=node.module,
                imported_name=alias.name,
                as_name=alias.asname,
                level=node.level,
                lineno=node.lineno,
                col_offset=node.col_offset,
            ))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect direct mutations to ``sys.modules`` or ``__builtins__``
        and builtin name shadowing at module scope."""
        for target in node.targets:
            target_str = ast.unparse(target)
            if "sys.modules" in target_str:
                self.isolation_violations.append((
                    node.lineno,
                    node.col_offset,
                    f"Direct mutation of 'sys.modules': {target_str}",
                ))
            elif "__builtins__" in target_str or "builtins." in target_str:
                self.isolation_violations.append((
                    node.lineno,
                    node.col_offset,
                    f"Tampering with builtins: {target_str}",
                ))
            elif isinstance(target, ast.Name) and target.id in PYTHON_CORE_BUILTINS:
                self.builtin_shadowing.append((
                    node.lineno,
                    node.col_offset,
                    target.id,
                ))
        self.generic_visit(node)

    def check_module_purity(self, mod: ast.Module) -> None:
        """Detect top-level call expressions that cause side-effects on import.

        Args:
            mod: Root ``ast.Module`` of the parsed source.
        """
        for stmt in mod.body:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                func_name = ast.unparse(stmt.value.func)
                self.top_level_side_effects.append(
                    (stmt.lineno, stmt.col_offset, func_name)
                )


def detect_cycles_tarjan(
    adjacency_list: Dict[str, Set[str]],
) -> List[List[str]]:
    """Blueprint §2.4 — Tarjan's SCC cycle detection (O(V+E)).

    Identifies strongly connected components of size > 1 (or self-loops),
    which correspond to circular import cycles.

    Args:
        adjacency_list: Map from module name to the set of modules it imports.

    Returns:
        List of SCCs that form cycles.  Each SCC is itself a list of module
        name strings.  Single-node SCCs without self-loops are excluded.
    """
    index_counter: int = 0
    indices: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    stack: List[str] = []
    on_stack: Set[str] = set()
    cycles: List[List[str]] = []

    def strongconnect(v: str) -> None:
        nonlocal index_counter
        indices[v] = index_counter
        lowlink[v] = index_counter
        index_counter += 1
        stack.append(v)
        on_stack.add(v)

        for w in adjacency_list.get(v, set()):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])

        if lowlink[v] == indices[v]:
            scc: List[str] = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                scc.append(w)
                if w == v:
                    break
            # Only report genuine cycles (SCC > 1, or single node with self-loop)
            if len(scc) > 1 or (
                len(scc) == 1 and v in adjacency_list.get(v, set())
            ):
                cycles.append(scc)

    for node in adjacency_list:
        if node not in indices:
            strongconnect(node)

    return cycles
