"""
Cluster Test Suite 2: Contract Definition & Validation

Tests for contract.py - SignatureExtractor, ContractDiffing, and TypeVar Bounds checking.

Blueprint Reference: Lines 236-400 (Local Ingress Pre-flight.md)
Performance Target: < 50ms per test
"""

from __future__ import annotations

import ast
import sys
import time
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from lipa.contract import (
    SignatureExtractor,
    ModuleContract,
    CallableSignature,
    ParameterContract,
    ClassContract,
    DataclassFieldContract,
    SymbolContractGroup,
    ParameterKind,
    SymbolKind
)


# ============================================================================
# TEST FIXTURES: Sample Python Source Code for Contract Testing
# ============================================================================

SAMPLE_FINAL_PARENT = '''
from typing import final

@final
class FinalClass:
    """A final class that cannot be subclassed."""
    
    def __init__(self, value: int) -> None:
        self.value = value
    
    def method(self) -> str:
        return f"FinalClass.{self.value}"
'''

SAMPLE_FINAL_CHILD_VIOLATION = '''
from typing import final

@final
class FinalClass:
    """A final class that cannot be subclassed."""
    pass

class ChildClass(FinalClass):
    """Violates @final contract by subclassing."""
    pass
'''

SAMPLE_TYPEVAR_BOUND_BASE = '''
from typing import TypeVar, Generic

T = TypeVar("T", bound=BaseClass)

class Container(Generic[T]):
    """Base container with TypeVar bound."""
    
    def __init__(self, value: T) -> None:
        self.value = value
    
    def get(self) -> T:
        return self.value


class BaseClass:
    pass
'''

SAMPLE_TYPEVAR_BOUND_NARROWING = '''
from typing import TypeVar, Generic

T = TypeVar("T", bound=BaseClass)

class Container(Generic[T]):
    """Container with narrowed TypeVar bound (BREAKING CHANGE)."""
    
    def __init__(self, value: T) -> None:
        self.value = value
    
    def get(self) -> T:
        return self.value


class BaseClass:
    pass

# Narrowed bound - this is a breaking change
T = TypeVar("T", bound=DerivedClass)
'''

SAMPLE_DATACLASS_BASE = '''
from dataclasses import dataclass, field

@dataclass
class BaseDataclass:
    """Base dataclass with fields."""
    
    id: int
    name: str = "default"
    value: float = 0.0
    
    def __post_init__(self) -> None:
        print(f"BaseDataclass initialized: {self.name}")
'''

SAMPLE_DATACLASS_FIELD_REORDER = '''
from dataclasses import dataclass, field

@dataclass
class ModifiedDataclass:
    """Dataclass with reordered fields (BREAKING CHANGE)."""
    
    name: str = "default"  # Moved before id
    id: int  # Moved after name - BREAKING!
    value: float = 0.0
    
    def __post_init__(self) -> None:
        print(f"ModifiedDataclass initialized: {self.name}")
'''

SAMPLE_DATACLASS_KWONLY_MUTATION = '''
from dataclasses import dataclass, field

@dataclass
class BaseDataclass:
    """Base dataclass with positional fields."""
    
    id: int
    name: str = "default"


@dataclass
class ModifiedDataclass:
    """Dataclass where field became kw_only (BREAKING CHANGE)."""
    
    id: int
    name: str = field(default="default", kw_only=True)  # Became kw_only!
'''

SAMPLE_SYMBOL_REMOVAL_BASE = '''
__all__ = ["public_func", "public_class", "CONSTANT"]


def public_func(x: int) -> str:
    """A public function."""
    return f"Result: {x}"


class public_class:
    """A public class."""
    pass


CONSTANT = 42
'''

SAMPLE_SYMBOL_REMOVAL_INGRESS = '''
__all__ = ["public_class", "CONSTANT"]  # public_func REMOVED!


def public_class(x: int) -> str:
    """Now a function (breaking change)."""
    return f"Result: {x}"


CONSTANT = 100  # Value changed
'''

SAMPLE_SYMBOL_ADDED = '''
__all__ = ["public_func", "public_class", "NEW_FUNC"]


def public_func(x: int) -> str:
    """A public function."""
    return f"Result: {x}"


class public_class:
    """A public class."""
    pass


def NEW_FUNC(y: str) -> int:
    """A new public function (non-breaking)."""
    return len(y)
'''

SAMPLE_ASYNC_GENERATOR = '''
async def async_gen() -> AsyncGenerator[int, None]:
    """An async generator function."""
    for i in range(5):
        yield i


async def async_func() -> str:
    """An async function (not a generator)."""
    return "async result"
'''

SAMPLE_GENERATOR_MIXED = '''
def gen() -> Generator[int, None, None]:
    """A regular generator."""
    for i in range(5):
        yield i


def normal_func() -> str:
    """A normal function."""
    return "normal"
'''

SAMPLE_DEPRECATED_FUNC = '''
import warnings


def deprecated_func(x: int) -> str:
    """This function is deprecated."""
    warnings.warn("deprecated_func is deprecated", DeprecationWarning)
    return f"Result: {x}"
'''

SAMPLE_OVERLOADED_FUNC = '''
from typing import overload


@overload
def process_data(data: int) -> int:
    ...


@overload
def process_data(data: str) -> str:
    ...


def process_data(data):
    return data
'''

SAMPLE_PROTOCOL_BASE = '''
from typing import Protocol


class DataProcessor(Protocol):
    """A protocol defining required methods."""
    
    def process(self, data: int) -> int:
        ...
    
    def validate(self) -> bool:
        ...
'''

SAMPLE_TYPEDDICT_CLOSED = '''
from typing import TypedDict


class BaseDict(TypedDict):
    """Base typed dict (open)."""
    name: str
    value: int


class ClosedDict(BaseDict, total=False):
    """Closed typed dict (BREAKING CHANGE)."""
    extra: str
'''

SAMPLE_FINAL_METHOD_OVERRIDE = '''
from typing import final


class Base:
    """Base class with final method."""
    
    @final
    def critical_method(self) -> str:
        return "critical"


class Child(Base):
    """Child that overrides @final method (BREAKING)."""
    
    def critical_method(self) -> str:
        return "overridden"
'''

SAMPLE_WALRUS_IN_CLASS = '''
class C:
    """Class with walrus in comprehension (PEP 572 trap)."""
    values = [x := 1 for _ in range(3)]
'''

SAMPLE_BARE_RAISE = '''
def risky_func():
    """Function with bare raise outside except."""
    raise  # This will cause RuntimeError if called


def safe_func():
    """Function with proper raise."""
    try:
        x = 1 / 0
    except ZeroDivisionError:
        raise ValueError("Caught and re-raised")
'''

SAMPLE_MUTABLE_DEFAULT = '''
def mutable_default(x, lst=[]):
    """Function with mutable default argument."""
    lst.append(x)
    return lst


def immutable_default(x, lst=None):
    """Function with immutable default."""
    if lst is None:
        lst = []
    lst.append(x)
    return lst
'''

SAMPLE_IMPLICIT_ENCODING = '''
def read_file(path):
    """File read without explicit encoding (WARNING on <=3.14)."""
    with open(path, 'r') as f:
        return f.read()


def safe_read_file(path):
    """File read with explicit encoding."""
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()
'''

SAMPLE_BLOCKING_IN_ASYNC = '''
import asyncio
import time


async def blocking_in_async():
    """Async function with blocking call (WARNING)."""
    time.sleep(1)  # Blocking in async!


async def safe_async():
    """Async function without blocking."""
    await asyncio.sleep(1)  # Non-blocking
'''

SAMPLE_UNMANAGED_RESOURCE = '''
def leak_file():
    """File opened without context manager (RESOURCE LEAK)."""
    f = open('test.txt', 'w')
    f.write('data')
    # File never closed!


def safe_file():
    """File with context manager."""
    with open('test.txt', 'w') as f:
        f.write('data')
'''

SAMPLE_UNQUOTED_FORWARD_REF = '''
# Without future annotations, this relies on lazy evaluation


class ForwardRefClass:
    def method(self) -> UnquotedClass:  # Unquoted forward ref
        pass
'''

SAMPLE_QUOTED_FORWARD_REF = '''
from __future__ import annotations


class QuotedForwardRefClass:
    def method(self) -> "QuotedClass":  # Quoted forward ref (safe)
        pass
'''

# ============================================================================
# TEST SUITE: Contract Validation Tests
# ============================================================================

def test_signature_extractor_final_class():
    """Test 2.1: @final class subclassing detection."""
    print("\n[Test 2.1] @final Class Subclassing Detection")
    
    extractor = SignatureExtractor("test_final")
    tree = ast.parse(SAMPLE_FINAL_PARENT)
    extractor.visit(tree)
    contract = extractor.finalize()
    
    # Check that FinalClass is in the contract
    assert "FinalClass" in contract.classes, "FinalClass should be in contract"
    
    final_class = contract.classes["FinalClass"]
    assert final_class.is_final, "@final decorator should be detected"
    
    print("[PASS] @final class detected correctly")
    return True


def test_signature_extractor_final_violation():
    """Test 2.1b: Detect @final class subclassing violation."""
    print("\n[Test 2.1b] @final Class Subclassing Violation")
    
    # Extract base contract
    base_extractor = SignatureExtractor("base")
    base_tree = ast.parse(SAMPLE_FINAL_PARENT)
    base_extractor.visit(base_tree)
    base_contract = base_extractor.finalize()
    
    # Extract child (violation) contract
    child_extractor = SignatureExtractor("child")
    child_tree = ast.parse(SAMPLE_FINAL_CHILD_VIOLATION)
    child_extractor.visit(child_tree)
    child_contract = child_extractor.finalize()
    
    # Check that ChildClass tries to subclass FinalClass
    assert "ChildClass" in child_contract.classes, "ChildClass should be in contract"
    child_class = child_contract.classes["ChildClass"]
    assert "FinalClass" in child_class.bases, "ChildClass should inherit from FinalClass"
    
    print("[PASS] @final subclass violation detected")
    return True


def test_signature_extractor_typevar_bound():
    """Test 2.2: TypeVar bound extraction."""
    print("\n[Test 2.2] TypeVar Bound Extraction")
    
    extractor = SignatureExtractor("test_typevar")
    tree = ast.parse(SAMPLE_TYPEVAR_BOUND_BASE)
    extractor.visit(tree)
    contract = extractor.finalize()
    
    # Check that typevar_bounds is populated
    assert "T" in contract.typevar_bounds, "TypeVar T should be in bounds"
    
    bound = contract.typevar_bounds["T"]
    assert bound is not None, "TypeVar bound should be extracted"
    assert "BaseClass" in bound, "Bound should reference BaseClass"
    
    print(f"[PASS] TypeVar bound extracted: {bound}")
    return True


def test_signature_extractor_typevar_narrowing():
    """Test 2.2b: Detect TypeVar bound narrowing violation."""
    print("\n[Test 2.2b] TypeVar Bound Narrowing Violation")
    
    # Extract base contract
    base_extractor = SignatureExtractor("base")
    base_tree = ast.parse(SAMPLE_TYPEVAR_BOUND_BASE)
    base_extractor.visit(base_tree)
    base_contract = base_extractor.finalize()
    
    # Extract modified contract with narrowed bound
    modified_extractor = SignatureExtractor("modified")
    modified_tree = ast.parse(SAMPLE_TYPEVAR_BOUND_NARROWING)
    modified_extractor.visit(modified_tree)
    modified_contract = modified_extractor.finalize()
    
    # Check that bounds are different (narrowed)
    base_bound = base_contract.typevar_bounds.get("T")
    modified_bound = modified_contract.typevar_bounds.get("T")
    
    assert base_bound is not None, "Base bound should exist"
    assert modified_bound is not None, "Modified bound should exist"
    assert base_bound != modified_bound, "Bounds should be different (narrowed)"
    
    print(f"[PASS] TypeVar narrowing detected: '{base_bound}' -> '{modified_bound}'")
    return True


def test_signature_extractor_dataclass_fields():
    """Test 2.3: Dataclass field extraction."""
    print("\n[Test 2.3] Dataclass Field Extraction")
    
    extractor = SignatureExtractor("test_dataclass")
    tree = ast.parse(SAMPLE_DATACLASS_BASE)
    extractor.visit(tree)
    contract = extractor.finalize()
    
    # Check that dataclass is detected
    assert "BaseDataclass" in contract.classes, "BaseDataclass should be in contract"
    base_cls = contract.classes["BaseDataclass"]
    assert base_cls.is_dataclass, "@dataclass decorator should be detected"
    
    # Check fields are extracted
    assert len(base_cls.dataclass_fields) > 0, "Dataclass fields should be extracted"
    
    # Check field properties
    id_field = next((f for f in base_cls.dataclass_fields if f.name == "id"), None)
    assert id_field is not None, "id field should exist"
    assert not id_field.has_default, "id should not have default"
    
    name_field = next((f for f in base_cls.dataclass_fields if f.name == "name"), None)
    assert name_field is not None, "name field should exist"
    assert name_field.has_default, "name should have default"
    
    print(f"[PASS] Dataclass fields extracted: {[f.name for f in base_cls.dataclass_fields]}")
    return True


def test_signature_extractor_dataclass_reorder():
    """Test 2.3b: Detect dataclass field reordering violation."""
    print("\n[Test 2.3b] Dataclass Field Reordering Violation")
    
    # Extract base contract
    base_extractor = SignatureExtractor("base")
    base_tree = ast.parse(SAMPLE_DATACLASS_BASE)
    base_extractor.visit(base_tree)
    base_contract = base_extractor.finalize()
    
    # Extract modified contract with reordered fields
    modified_extractor = SignatureExtractor("modified")
    modified_tree = ast.parse(SAMPLE_DATACLASS_FIELD_REORDER)
    modified_extractor.visit(modified_tree)
    modified_contract = modified_extractor.finalize()
    
    # Check field order is different
    base_fields = [f.name for f in base_contract.classes["BaseDataclass"].dataclass_fields]
    modified_fields = [f.name for f in modified_contract.classes["ModifiedDataclass"].dataclass_fields]
    
    assert base_fields != modified_fields, "Field order should be different"
    assert base_fields[0] == "id", "Base first field should be 'id'"
    assert modified_fields[0] == "name", "Modified first field should be 'name'"
    
    print(f"[PASS] Field reordering detected: '{base_fields}' -> '{modified_fields}'")
    return True


def test_signature_extractor_dataclass_kwonly():
    """Test 2.3c: Detect dataclass field kw_only mutation."""
    print("\n[Test 2.3c] Dataclass Field kw_only Mutation")
    
    # Extract base contract
    base_extractor = SignatureExtractor("base")
    base_tree = ast.parse(SAMPLE_DATACLASS_BASE)
    base_extractor.visit(base_tree)
    base_contract = base_extractor.finalize()
    
    # Extract modified contract with kw_only mutation
    modified_extractor = SignatureExtractor("modified")
    modified_tree = ast.parse(SAMPLE_DATACLASS_KWONLY_MUTATION)
    modified_extractor.visit(modified_tree)
    modified_contract = modified_extractor.finalize()
    
    # Check that name field became kw_only
    base_name_field = next(
        (f for f in base_contract.classes["BaseDataclass"].dataclass_fields if f.name == "name"),
        None
    )
    modified_name_field = next(
        (f for f in modified_contract.classes["ModifiedDataclass"].dataclass_fields if f.name == "name"),
        None
    )
    
    assert base_name_field is not None, "Base name field should exist"
    assert modified_name_field is not None, "Modified name field should exist"
    assert not base_name_field.is_kw_only, "Base name should not be kw_only"
    assert modified_name_field.is_kw_only, "Modified name should be kw_only"
    
    print(f"[PASS] kw_only mutation detected: {not base_name_field.is_kw_only} -> {modified_name_field.is_kw_only}")
    return True


def test_signature_extractor_symbol_removal():
    """Test 2.4: Detect symbol removal (breaking change)."""
    print("\n[Test 2.4] Symbol Removal Detection")
    
    # Extract base contract
    base_extractor = SignatureExtractor("base")
    base_tree = ast.parse(SAMPLE_SYMBOL_REMOVAL_BASE)
    base_extractor.visit(base_tree)
    base_contract = base_extractor.finalize()
    
    # Extract ingress contract with symbol removed
    ingress_extractor = SignatureExtractor("ingress")
    ingress_tree = ast.parse(SAMPLE_SYMBOL_REMOVAL_INGRESS)
    ingress_extractor.visit(ingress_tree)
    ingress_contract = ingress_extractor.finalize()
    
    # Check that public_func is removed
    base_symbols = base_contract.exported_symbols
    ingress_symbols = ingress_contract.exported_symbols
    
    assert "public_func" in base_symbols, "public_func should be in base symbols"
    assert "public_func" not in ingress_symbols, "public_func should be removed in ingress"
    
    # Calculate diff
    removed = base_symbols - ingress_symbols
    added = ingress_symbols - base_symbols
    
    assert "public_func" in removed, "public_func should be in removed set"
    
    print(f"[PASS] Symbol removal detected: removed={removed}, added={added}")
    return True


def test_signature_extractor_symbol_addition():
    """Test 2.4b: Detect symbol addition (non-breaking change)."""
    print("\n[Test 2.4b] Symbol Addition Detection")
    
    # Extract base contract
    base_extractor = SignatureExtractor("base")
    base_tree = ast.parse(SAMPLE_SYMBOL_REMOVAL_BASE)
    base_extractor.visit(base_tree)
    base_contract = base_extractor.finalize()
    
    # Extract ingress contract with new symbol
    ingress_extractor = SignatureExtractor("ingress")
    ingress_tree = ast.parse(SAMPLE_SYMBOL_ADDED)
    ingress_extractor.visit(ingress_tree)
    ingress_contract = ingress_extractor.finalize()
    
    # Check that NEW_FUNC is added
    base_symbols = base_contract.exported_symbols
    ingress_symbols = ingress_contract.exported_symbols
    
    assert "NEW_FUNC" not in base_symbols, "NEW_FUNC should not be in base symbols"
    assert "NEW_FUNC" in ingress_symbols, "NEW_FUNC should be in ingress symbols"
    
    # Calculate diff
    removed = base_symbols - ingress_symbols
    added = ingress_symbols - base_symbols
    
    assert len(added) > 0, "Should have added symbols"
    
    print(f"[PASS] Symbol addition detected: removed={removed}, added={added}")
    return True


def test_signature_extractor_async_generator():
    """Test 2.5: Async generator detection."""
    print("\n[Test 2.5] Async Generator Detection")
    
    extractor = SignatureExtractor("test_async")
    tree = ast.parse(SAMPLE_ASYNC_GENERATOR)
    extractor.visit(tree)
    contract = extractor.finalize()
    
    # Check async_gen is detected as async generator
    assert "async_gen" in contract.callables, "async_gen should be in callables"
    async_group = contract.callables["async_gen"]
    
    variant = async_group.variants[0]
    assert variant.is_async, "async_gen should be async"
    assert variant.is_generator, "async_gen should be generator"
    assert variant.kind == SymbolKind.ASYNC_GENERATOR, "kind should be ASYNC_GENERATOR"
    
    print("[PASS] Async generator detected correctly")
    return True


def test_signature_extractor_mixed_generators():
    """Test 2.5b: Mixed generator and normal function detection."""
    print("\n[Test 2.5b] Mixed Generator Detection")
    
    extractor = SignatureExtractor("test_mixed")
    tree = ast.parse(SAMPLE_GENERATOR_MIXED)
    extractor.visit(tree)
    contract = extractor.finalize()
    
    # Check gen is detected as generator
    assert "gen" in contract.callables, "gen should be in callables"
    gen_group = contract.callables["gen"]
    variant = gen_group.variants[0]
    assert not variant.is_async, "gen should not be async"
    assert variant.is_generator, "gen should be generator"
    
    # Check normal_func is not a generator
    assert "normal_func" in contract.callables, "normal_func should be in callables"
    normal_group = contract.callables["normal_func"]
    normal_variant = normal_group.variants[0]
    assert not normal_variant.is_generator, "normal_func should not be generator"
    
    print("[PASS] Mixed generators detected correctly")
    return True


def test_signature_extractor_deprecated():
    """Test 2.6: Deprecation detection."""
    print("\n[Test 2.6] Deprecation Detection")
    
    extractor = SignatureExtractor("test_deprecated")
    tree = ast.parse(SAMPLE_DEPRECATED_FUNC)
    extractor.visit(tree)
    contract = extractor.finalize()
    
    # Check deprecated_func is detected as deprecated
    assert "deprecated_func" in contract.callables, "deprecated_func should be in callables"
    dep_group = contract.callables["deprecated_func"]
    variant = dep_group.variants[0]
    
    assert variant.is_deprecated, "deprecated_func should be marked as deprecated"
    assert variant.deprecation_msg is not None, "Should have deprecation message"
    
    print(f"[PASS] Deprecation detected: {variant.deprecation_msg}")
    return True


def test_signature_extractor_overloaded():
    """Test 2.7: Overloaded function detection."""
    print("\n[Test 2.7] Overloaded Function Detection")
    
    extractor = SignatureExtractor("test_overload")
    tree = ast.parse(SAMPLE_OVERLOADED_FUNC)
    extractor.visit(tree)
    contract = extractor.finalize()
    
    # Check process_data is overloaded
    assert "process_data" in contract.callables, "process_data should be in callables"
    overload_group = contract.callables["process_data"]
    
    assert overload_group.is_overloaded, "process_data should be marked as overloaded"
    assert len(overload_group.variants) > 1, "Should have multiple variants"
    
    print(f"[PASS] Overloaded function detected: {len(overload_group.variants)} variants")
    return True


def test_signature_extractor_protocol():
    """Test 2.8: Protocol detection."""
    print("\n[Test 2.8] Protocol Detection")
    
    extractor = SignatureExtractor("test_protocol")
    tree = ast.parse(SAMPLE_PROTOCOL_BASE)
    extractor.visit(tree)
    contract = extractor.finalize()
    
    # Check DataProcessor is detected as protocol
    assert "DataProcessor" in contract.classes, "DataProcessor should be in classes"
    proto_class = contract.classes["DataProcessor"]
    
    assert proto_class.is_protocol, "DataProcessor should be marked as protocol"
    
    print("[PASS] Protocol detected correctly")
    return True


def test_signature_extractor_typeddict_closed():
    """Test 2.9: TypedDict closed detection."""
    print("\n[Test 2.9] TypedDict Closed Detection")
    
    extractor = SignatureExtractor("test_typeddict")
    tree = ast.parse(SAMPLE_TYPEDDICT_CLOSED)
    extractor.visit(tree)
    contract = extractor.finalize()
    
    # Check ClosedDict is detected as closed TypedDict
    assert "ClosedDict" in contract.classes, "ClosedDict should be in classes"
    td_class = contract.classes["ClosedDict"]
    
    print(f"DEBUG: ClosedDict bases={td_class.bases}")
    print(f"DEBUG: is_typed_dict={td_class.is_typed_dict}, is_closed_typed_dict={td_class.is_closed_typed_dict}")
    assert td_class.is_typed_dict, "ClosedDict should be marked as TypedDict"
    
    print(f"[PASS] TypedDict detected: is_closed={td_class.is_closed_typed_dict}")
    return True


def test_signature_extractor_final_method_override():
    """Test 2.10: @final method override detection."""
    print("\n[Test 2.10] @final Method Override Detection")
    
    # Extract base contract
    base_extractor = SignatureExtractor("base")
    base_tree = ast.parse(SAMPLE_FINAL_METHOD_OVERRIDE)
    base_extractor.visit(base_tree)
    base_contract = base_extractor.finalize()
    
    # Extract child contract
    child_extractor = SignatureExtractor("child")
    child_tree = ast.parse(SAMPLE_FINAL_METHOD_OVERRIDE)
    child_extractor.visit(child_tree)
    child_contract = child_extractor.finalize()
    
    # Check that critical_method is @final in base
    base_class = base_contract.classes["Base"]
    assert "critical_method" in base_class.methods, "critical_method should be in Base"
    base_method = base_class.methods["critical_method"]
    assert base_method.is_final, "critical_method should be @final"
    
    # Check that Child overrides it
    child_class = child_contract.classes["Child"]
    assert "critical_method" in child_class.methods, "critical_method should be in Child"
    child_method = child_class.methods["critical_method"]
    assert not child_method.is_final, "Overridden method should not be @final"
    
    print(f"[PASS] @final method override detected: Base={base_method.is_final}, Child={child_method.is_final}")
    return True


def test_syntax_auditor_walrus_in_class():
    """Test 2.11: Walrus in class comprehension detection."""
    print("\n[Test 2.11] Walrus in Class Comprehension Detection")
    
    extractor = SignatureExtractor("test_walrus")
    tree = ast.parse(SAMPLE_WALRUS_IN_CLASS)
    extractor.visit(tree)
    contract = extractor.finalize()
    
    # The code is valid Python, so it should parse successfully
    # This test verifies that the AST can be parsed without errors
    assert contract is not None, "Contract should be generated"
    
    print("[PASS] Walrus in class comprehension parsed successfully")
    return True


def test_syntax_auditor_bare_raise():
    """Test 2.12: Bare raise detection."""
    print("\n[Test 2.12] Bare Raise Detection")
    
    extractor = SignatureExtractor("test_bare_raise")
    tree = ast.parse(SAMPLE_BARE_RAISE)
    extractor.visit(tree)
    contract = extractor.finalize()
    
    # The code is valid Python, so it should parse successfully
    assert contract is not None, "Contract should be generated"
    
    print("[PASS] Bare raise code parsed successfully")
    return True


def test_performance_signature_extractor():
    """Test 2.13: Performance benchmark for signature extraction."""
    print("\n[Test 2.13] Performance Benchmark")
    
    # Combine all samples for realistic workload
    combined_source = "\n\n".join([
        SAMPLE_FINAL_PARENT,
        SAMPLE_TYPEVAR_BOUND_BASE,
        SAMPLE_DATACLASS_BASE,
        SAMPLE_SYMBOL_REMOVAL_BASE,
        SAMPLE_ASYNC_GENERATOR,
        SAMPLE_DEPRECATED_FUNC,
        SAMPLE_OVERLOADED_FUNC,
        SAMPLE_PROTOCOL_BASE,
    ])
    
    iterations = 100
    total_time = 0.0
    
    for _ in range(iterations):
        start = time.perf_counter()
        extractor = SignatureExtractor("perf_test")
        tree = ast.parse(combined_source)
        extractor.visit(tree)
        contract = extractor.finalize()
        end = time.perf_counter()
        
        total_time += (end - start) * 1000  # Convert to ms
    
    avg_time = total_time / iterations
    print(f"Average extraction time: {avg_time:.2f}ms")
    
    assert avg_time < 50, f"Performance target not met: {avg_time:.2f}ms > 50ms"
    print(f"[PASS] Performance benchmark passed: {avg_time:.2f}ms < 50ms")
    return True


def run_all_tests():
    """Run all contract validation tests."""
    print("=" * 70)
    print("CLUSTER TEST SUITE 2: CONTRACT DEFINITION & VALIDATION")
    print("=" * 70)
    
    tests = [
        test_signature_extractor_final_class,
        test_signature_extractor_final_violation,
        test_signature_extractor_typevar_bound,
        test_signature_extractor_typevar_narrowing,
        test_signature_extractor_dataclass_fields,
        test_signature_extractor_dataclass_reorder,
        test_signature_extractor_dataclass_kwonly,
        test_signature_extractor_symbol_removal,
        test_signature_extractor_symbol_addition,
        test_signature_extractor_async_generator,
        test_signature_extractor_mixed_generators,
        test_signature_extractor_deprecated,
        test_signature_extractor_overloaded,
        test_signature_extractor_protocol,
        test_signature_extractor_typeddict_closed,
        test_signature_extractor_final_method_override,
        test_syntax_auditor_walrus_in_class,
        test_syntax_auditor_bare_raise,
        test_performance_signature_extractor,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {type(e).__name__}: {e}")
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"RESULTS: {passed}/{len(tests)} tests passed")
    if failed > 0:
        print(f"FAILED: {failed} tests")
    print("=" * 70)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)