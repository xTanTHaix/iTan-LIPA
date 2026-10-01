"""Root conftest.py — adds src/ to sys.path so tests can import lipa directly."""
import sys
from pathlib import Path

# Prepend src/ so that ``import lipa`` resolves to src/lipa without installation.
sys.path.insert(0, str(Path(__file__).parent / "src"))
