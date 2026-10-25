import subprocess
from pathlib import Path

import pytest

from tools import RepositorySandbox, redact_secrets


@pytest.fixture
def dummy_git_repo(tmp_path: Path) -> Path:
    repo_dir = tmp_path / "sample_repo"
    repo_dir.mkdir()

    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo_dir), check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(repo_dir), check=True)

    (repo_dir / "config.py").write_text(
        'import os\nAPI_KEY = "sk-1234567890abcdefghijklmnop"\nDB_PATH = "/Users/admin/local.db"\n',
        encoding="utf-8",
    )
    wf_dir = repo_dir / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )

    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit with config"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
    )
    return repo_dir


def test_secret_redaction():
    raw = 'password = "MySuperSecretPassword123!" and token sk-proj1234567890abcdefghij and AKIAIOSFODNN7EXAMPLE'
    scrubbed = redact_secrets(raw)
    assert "MySuperSecretPassword123!" not in scrubbed
    assert "sk-proj1234567890abcdefghij" not in scrubbed
    assert "AKIAIOSFODNN7EXAMPLE" not in scrubbed
    assert "[REDACTED" in scrubbed


def test_sandbox_tools_lifecycle(dummy_git_repo: Path):
    with RepositorySandbox(str(dummy_git_repo)) as sandbox:
        files_out = sandbox.list_files()
        assert "config.py" in files_out
        assert ".github/workflows/ci.yml" in files_out
        assert ".git/HEAD" not in files_out

        read_out = sandbox.read_file("config.py")
        assert "2: API_KEY =" in read_out
        assert "sk-1234567890abcdefghijklmnop" not in read_out
        assert "[REDACTED" in read_out

        search_out = sandbox.search_code("API_KEY|DB_PATH")
        assert "config.py:2:" in search_out
        assert "config.py:3:" in search_out
        assert "sk-1234567890abcdefghijklmnop" not in search_out

        log_out = sandbox.git_log(max_commits=5)
        assert "Initial commit with config" in log_out

        traversal_out = sandbox.read_file("../../outside.txt")
        assert "Access denied" in traversal_out or "Error" in traversal_out
