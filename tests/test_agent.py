import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent import main, parse_args
from core.loop import sanitize_and_deduplicate_violations
from core.schemas import AuditReport, Violation


def test_cli_arg_parsing_supports_both_dash_styles():
    args1 = parse_args(["--repo", "[https://github.com/dani-234/mlops-assignment2-danish](https://github.com/dani-234/mlops-assignment2-danish)", "--output", "out.json"])
    assert args1.repo == "[https://github.com/dani-234/mlops-assignment2-danish](https://github.com/dani-234/mlops-assignment2-danish)"
    assert args1.output == "out.json"

    args2 = parse_args(["-repo", "[https://github.com/dani-234/mlops-assignment2-danish](https://github.com/dani-234/mlops-assignment2-danish)", "--output", "out.json"])
    assert args2.repo == "[https://github.com/dani-234/mlops-assignment2-danish](https://github.com/dani-234/mlops-assignment2-danish)"


def test_violation_sanitization_and_deduplication(tmp_path: Path):
    (tmp_path / "config.py").write_text("x = 1\n", encoding="utf-8")

    raw_list = [
        Violation(
            rule_id="sec-001",
            category="security",
            severity="critical",
            file="./config.py",
            line=17,
            description="Hardcoded secret",
            evidence='api_key = "supersecret12345"',
            recommendation="Use env vars",
        ),
        Violation(
            rule_id="SEC-001",
            category="security",
            severity="critical",
            file="config.py",
            line=17,
            description="Hardcoded secret",
            evidence='api_key = "supersecret12345"',
            recommendation="Use env vars",
        ),
        Violation(
            rule_id="HYG-001",
            category="repository_hygiene",
            severity="medium",
            file="N/A",
            line=0,
            description="Missing README",
            evidence="No README.md in root",
            recommendation="Add a README.md",
        ),
    ]

    cleaned = sanitize_and_deduplicate_violations(raw_list, tmp_path)
    assert len(cleaned) == 2

    sec = cleaned[0]
    assert sec.rule_id == "SEC-001"
    assert sec.file == "config.py"
    assert sec.line == 17
    assert "supersecret12345" not in sec.evidence

    hyg = cleaned[1]
    assert hyg.file is None
    assert hyg.line is None


@patch("agent.run_audit_agent")
def test_end_to_end_cli_writes_valid_json(mock_run_agent: MagicMock, tmp_path: Path):
    mock_report = AuditReport(
        repository="[https://github.com/example/demo-project](https://github.com/example/demo-project)",
        violations=[
            Violation(
                rule_id="SEC-001",
                category="security",
                severity="critical",
                file="config.py",
                line=17,
                description="Hardcoded API credential",
                evidence="Credential assigned directly in source code",
                recommendation="Use a secrets manager or environment variable",
            )
        ],
    )
    mock_run_agent.return_value = mock_report

    out_file = tmp_path / "report.json"
    exit_code = main(
        ["--repo", "[https://github.com/example/demo-project](https://github.com/example/demo-project)", "--output", str(out_file)]
    )

    assert exit_code == 0
    assert out_file.exists()

    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["repository"] == "[https://github.com/example/demo-project](https://github.com/example/demo-project)"
    assert len(payload["violations"]) == 1
