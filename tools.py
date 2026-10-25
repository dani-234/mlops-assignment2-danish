import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

MAX_TOOL_OUTPUT_CHARS = 12000

SKIP_SEARCH_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "cargo.lock",
    "composer.lock",
}

SECRET_PATTERNS = [
    (
        re.compile(
            r'(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)(\s*[=:]\s*)(["\'])([^\3\r\n]{4,})\3'
        ),
        r"\1\2\3[REDACTED_SECRET]\3",
    ),
    (
        re.compile(
            r"(?i)^(export\s+)?([A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|PWD)[A-Z0-9_]*)\s*=\s*([^\s#\"']{5,})",
            re.MULTILINE,
        ),
        r"\1\2=[REDACTED_SECRET]",
    ),
    (re.compile(r"\bsk-[a-zA-Z0-9_-]{16,}\b"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"\bgh[pousr]_[a-zA-Z0-9]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[a-zA-Z0-9_]{20,}\b"), "[REDACTED_GITHUB_PAT]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bxox[baprs]-[a-zA-Z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "[REDACTED_GOOGLE_KEY]"),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
        ),
        "-----BEGIN PRIVATE KEY-----[REDACTED_KEY_MATERIAL]-----END PRIVATE KEY-----",
    ),
]


def redact_secrets(text: str) -> str:
    """Scrub sensitive credential values before they reach the LLM or output JSON."""
    if not text:
        return text
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _remove_readonly(func, path, _):
    """Clear read-only bit on Windows (.git packfiles) and retry deletion."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


class RepositorySandbox:
    """Manages an isolated temporary clone of the target GitHub repository."""

    def __init__(self, repo_url: str):
        self.repo_url = repo_url.strip()
        self.temp_dir: str | None = None
        self.root_path: Path | None = None

    def __enter__(self) -> "RepositorySandbox":
        self.clone()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def clone(self) -> None:
        if not (
            self.repo_url.startswith("[https://github.com/](https://github.com/)")
            or self.repo_url.startswith("[http://github.com/](http://github.com/)")
            or os.path.isdir(self.repo_url)
        ):
            raise ValueError(
                f"Invalid repository URL: '{self.repo_url}'. Must be a public GitHub URL."
            )

        self.temp_dir = tempfile.mkdtemp(prefix="devops_audit_")
        self.root_path = Path(self.temp_dir).resolve()

        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

        try:
            subprocess.run(
                ["git", "clone", "--depth", "50", self.repo_url, str(self.root_path)],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=90,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            self.cleanup()
            raise RuntimeError(f"Timed out cloning repository: {self.repo_url}") from exc
        except subprocess.CalledProcessError as exc:
            self.cleanup()
            stderr_msg = exc.stderr.strip() if exc.stderr else "Unknown git clone error"
            raise RuntimeError(
                f"Failed to clone repository '{self.repo_url}': {stderr_msg}"
            ) from exc

    def cleanup(self) -> None:
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, onerror=_remove_readonly)
            self.temp_dir = None
            self.root_path = None

    def _resolve_safe_path(self, relative_path: str) -> Path:
        if not self.root_path:
            raise RuntimeError("Repository sandbox is not initialized.")
        clean_rel = relative_path.lstrip("/\\") if relative_path else "."
        resolved = (self.root_path / clean_rel).resolve()
        if not str(resolved).startswith(str(self.root_path)):
            raise PermissionError(f"Access denied: Path '{relative_path}' escapes sandbox.")
        return resolved

    def list_files(self, directory: str = ".") -> str:
        """Discover repository files and structure (including dotfiles like .github, excluding .git)."""
        try:
            target_dir = self._resolve_safe_path(directory)
            if not target_dir.exists():
                return f"Error: Directory '{directory}' does not exist."
            if not target_dir.is_dir():
                return f"Error: '{directory}' is a file, not a directory."

            files_info: list[str] = []
            max_files = 500
            count = 0

            for root, dirs, files in os.walk(target_dir):
                if ".git" in dirs:
                    dirs.remove(".git")
                dirs.sort()
                files.sort()

                for file in files:
                    full_path = Path(root) / file
                    rel_path = full_path.relative_to(self.root_path).as_posix()
                    try:
                        size_bytes = full_path.stat().st_size
                    except OSError:
                        size_bytes = 0
                    files_info.append(f"{rel_path} ({size_bytes} bytes)")
                    count += 1
                    if count >= max_files:
                        files_info.append(f"... [Truncated at {max_files} files]")
                        break
                if count >= max_files:
                    break

            return "\n".join(files_info) if files_info else "No files found in directory."
        except Exception as e:
            return f"Error in list_files: {e}"

    def read_file(self, path: str, start_line: int = 1, end_line: int = 250) -> str:
        """Inspect relevant source or configuration file with 1-based line numbers and secret redaction."""
        try:
            file_path = self._resolve_safe_path(path)
            if not file_path.exists():
                return f"Error: File '{path}' does not exist."
            if file_path.is_dir():
                return f"Error: '{path}' is a directory. Use list_files instead."

            with open(file_path, "rb") as bf:
                if b"\x00" in bf.read(2048):
                    return f"Binary file detected: '{path}' ({file_path.stat().st_size} bytes). Cannot read as text."

            content = file_path.read_text(encoding="utf-8", errors="replace")
            redacted_content = redact_secrets(content)
            lines = redacted_content.splitlines()

            total_lines = len(lines)
            if total_lines == 0:
                return f"File '{path}' is empty (0 lines)."

            start_idx = max(1, int(start_line)) - 1
            end_idx = min(total_lines, max(int(start_line), int(end_line)))

            numbered_lines = [
                f"{idx + 1}: {lines[idx]}" for idx in range(start_idx, end_idx)
            ]
            rel_posix = file_path.relative_to(self.root_path).as_posix()
            header = f"--- File: {rel_posix} (Lines {start_idx + 1}-{end_idx} of {total_lines}) ---\n"
            return header + "\n".join(numbered_lines)
        except Exception as e:
            return f"Error in read_file('{path}'): {e}"

    def search_code(self, pattern: str) -> str:
        """Search for suspicious regex patterns across repository text files."""
        try:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error as rex:
                return f"Invalid regex pattern '{pattern}': {rex}"

            matches: list[str] = []
            max_matches = 100

            for root, dirs, files in os.walk(self.root_path):
                if ".git" in dirs:
                    dirs.remove(".git")
                dirs.sort()
                files.sort()

                for file in files:
                    if file in SKIP_SEARCH_FILES:
                        continue
                    full_path = Path(root) / file
                    rel_path = full_path.relative_to(self.root_path).as_posix()

                    try:
                        if full_path.stat().st_size > 1_000_000:
                            continue
                        with open(full_path, "rb") as bf:
                            if b"\x00" in bf.read(1024):
                                continue
                        text = full_path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue

                    for line_num, line in enumerate(text.splitlines(), start=1):
                        if regex.search(line):
                            safe_line = redact_secrets(line.strip())
                            if len(safe_line) > 200:
                                safe_line = safe_line[:200] + "..."
                            matches.append(f"{rel_path}:{line_num}: {safe_line}")
                            if len(matches) >= max_matches:
                                matches.append(f"... [Truncated at {max_matches} matches]")
                                return "\n".join(matches)

            return "\n".join(matches) if matches else f"No matches found for pattern: '{pattern}'"
        except Exception as e:
            return f"Error in search_code('{pattern}'): {e}"

    def git_log(self, max_commits: int = 15, show_diffs: bool = False) -> str:
        """Inspect commit history, messages, modified files, and optionally recent diffs."""
        try:
            limit = max(1, min(30, int(max_commits)))
            cmd = [
                "git",
                "log",
                f"-n{limit}",
                "--pretty=format:COMMIT: %h | AUTHOR: %an | DATE: %ad | MSG: %s",
                "--date=short",
            ]
            cmd.append("-p" if show_diffs else "--stat")

            result = subprocess.run(
                cmd,
                cwd=str(self.root_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
            )
            if result.returncode != 0:
                return f"Error running git log: {result.stderr.strip()}"
            output = redact_secrets(result.stdout.strip()) or "No commit history found."
            if len(output) > MAX_TOOL_OUTPUT_CHARS:
                output = output[:MAX_TOOL_OUTPUT_CHARS] + "\n... [Truncated git_log output]"
            return output
        except Exception as e:
            return f"Error in git_log: {e}"

    def git_status(self) -> str:
        """Inspect repository working tree status."""
        try:
            result = subprocess.run(
                ["git", "status", "--short", "--branch"],
                cwd=str(self.root_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            if result.returncode != 0:
                return f"Error running git status: {result.stderr.strip()}"
            return result.stdout.strip()
        except Exception as e:
            return f"Error in git_status: {e}"

    def run_ruff(self) -> str:
        """Run Ruff static linter and Bandit security rules on Python files without executing untrusted code."""
        try:
            result = subprocess.run(
                [
                    "ruff",
                    "check",
                    ".",
                    "--select=E,F,S,B",
                    "--output-format=concise",
                ],
                cwd=str(self.root_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            output = (result.stdout or "") + "\n" + (result.stderr or "")
            clean_out = redact_secrets(output.strip())
            if not clean_out:
                return "Ruff check passed: 0 issues detected."
            lines = clean_out.splitlines()
            if len(lines) > 100:
                return "\n".join(lines[:100]) + f"\n... [Truncated {len(lines) - 100} additional lines]"
            return clean_out
        except FileNotFoundError:
            return "Ruff binary is not installed in the current environment."
        except Exception as e:
            return f"Error in run_ruff: {e}"

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> str:
        dispatch_map = {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "search_code": self.search_code,
            "git_log": self.git_log,
            "git_status": self.git_status,
            "run_ruff": self.run_ruff,
        }
        if tool_name not in dispatch_map:
            return f"Error: Unknown tool '{tool_name}'."
        try:
            return dispatch_map[tool_name](**arguments)
        except TypeError as te:
            return f"Error: Invalid arguments for tool '{tool_name}': {te}"
        except Exception as e:
            return f"Error executing tool '{tool_name}': {e}"


TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "Discover repository files and directory structure (with file sizes).",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Relative directory path to list (default is '.').",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Inspect the contents of a source code, workflow, or configuration file with 1-based line numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the file inside the repository.",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Starting 1-based line number (default 1).",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Ending 1-based line number (default 250).",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Search across all text files in the repository for a suspicious regex pattern.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regular expression pattern to search for (case-insensitive).",
                    }
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_log",
            "description": "Inspect commit history, commit messages, modified files, and optionally commit diffs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "max_commits": {
                        "type": "integer",
                        "description": "Maximum number of recent commits to retrieve (default 15).",
                    },
                    "show_diffs": {
                        "type": "boolean",
                        "description": "If true, include patch diffs (-p) to check for historical or deleted secrets (default false).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_status",
            "description": "Check git status of the repository.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ruff",
            "description": "Run static Python linter and Bandit security checks on the repository.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]
