"""
Report Generator Module - Audit Result Formatting & Output

Implements report generation in multiple formats (JSON, Markdown).
Creates human-readable audit summaries with issue details.

Blueprint Reference: Lines 751-850 (Local Ingress Pre-flight.md)
Performance Target: < 20ms per report
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional


class ReportFormat(Enum):
    """Supported report output formats."""
    JSON = auto()
    MARKDOWN = auto()
    TEXT = auto()


@dataclass
class AuditReport:
    """Container for generated audit report."""
    title: str
    file_path: str
    verdict: str
    issues_count: int
    details: List[dict] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = []
    
    def generate(self, format_type: ReportFormat) -> str:
        """Generate report in specified format."""
        if format_type == ReportFormat.JSON:
            return json.dumps(self.to_dict(), indent=2)
        elif format_type == ReportFormat.MARKDOWN:
            return self._generate_markdown()
        else:
            return self._generate_text()
    
    def to_dict(self) -> dict:
        """Convert report to dictionary."""
        return {
            "title": self.title,
            "file_path": self.file_path,
            "verdict": self.verdict,
            "issues_count": self.issues_count,
            "details": self.details
        }
    
    def _generate_markdown(self) -> str:
        """Generate markdown format report."""
        lines = [
            f"# {self.title}",
            "",
            f"**File:** `{self.file_path}`",
            f"**Verdict:** {self.verdict.upper()}",
            f"**Issues Found:** {self.issues_count}",
            ""
        ]
        
        if self.details:
            lines.append("## Issues")
            for issue in self.details:
                lines.append(f"- **{issue.get('type', 'unknown')}**: {issue.get('description', '')}")
        
        return "\n".join(lines)
    
    def _generate_text(self) -> str:
        """Generate plain text format report."""
        return (
            f"{self.title}\n"
            f"{'=' * len(self.title)}\n\n"
            f"File: {self.file_path}\n"
            f"Verdict: {self.verdict.upper()}\n"
            f"Issues: {self.issues_count}\n\n"
        )


class ReportGenerator:
    """Main report generator class."""
    
    def __init__(self) -> None:
        """Initialize report generator."""
        pass
    
    def generate_report(
        self, 
        file_path: str, 
        verdict: str, 
        issues_count: int,
        details: Optional[List[dict]] = None,
        format_type: ReportFormat = ReportFormat.MARKDOWN
    ) -> str:
        """Generate audit report."""
        report = AuditReport(
            title="LIPA Audit Report",
            file_path=file_path,
            verdict=verdict,
            issues_count=issues_count,
            details=details or []
        )
        
        return report.generate(format_type)
