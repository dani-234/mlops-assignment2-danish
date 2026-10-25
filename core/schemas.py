from typing import Literal

from pydantic import BaseModel, Field

AllowedSeverity = Literal["critical", "high", "medium", "low"]

AllowedCategory = Literal[
    "repository_hygiene",
    "dependency_management",
    "code_quality",
    "testing",
    "github_actions_ci",
    "security",
    "configuration",
    "collaboration",
    "build_and_release",
]


class Violation(BaseModel):
    rule_id: str = Field(
        ...,
        description="Standardized identifier, e.g., SEC-001, CI-001, DEP-001, HYG-001, CFG-001, TST-001, QLT-001, COL-001, BLD-001",
    )
    category: AllowedCategory = Field(
        ...,
        description="Must match one of the 9 DevOps inspection categories.",
    )
    severity: AllowedSeverity = Field(
        ...,
        description="Allowed values: critical, high, medium, low",
    )
    file: str | None = Field(
        default=None,
        description="Relative POSIX path to the file, or null if repository-wide.",
    )
    line: int | None = Field(
        default=None,
        description="1-based line number where the violation occurs, or null if file/repository-wide.",
    )
    description: str = Field(
        ...,
        description="Concise explanation of the DevOps best-practice violation.",
    )
    evidence: str = Field(
        ...,
        description="Concrete evidence from tool output with any actual secret values redacted.",
    )
    recommendation: str = Field(
        ...,
        description="Actionable remediation steps to fix the violation.",
    )


class ViolationListWrapper(BaseModel):
    violations: list[Violation] = Field(default_factory=list)


class AuditReport(BaseModel):
    repository: str
    violations: list[Violation] = Field(default_factory=list)
