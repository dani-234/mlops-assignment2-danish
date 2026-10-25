import json
import sys
from pathlib import Path
from typing import Any

from core.llm_client import LLMClient
from core.prompts import AGENT_SYSTEM_PROMPT
from core.schemas import AuditReport, Violation
from tools import MAX_TOOL_OUTPUT_CHARS, TOOL_DEFINITIONS, RepositorySandbox, redact_secrets


def sanitize_and_deduplicate_violations(
    violations: list[Violation], repo_root: Path | None
) -> list[Violation]:
    cleaned: list[Violation] = []
    seen_keys: set[tuple[str, str, str | None, int | None]] = set()
    null_equivalents = {"", "none", "null", "n/a", "na", ".", "/", "repository", "repo-wide"}

    for v in violations:
        norm_file: str | None = None
        if v.file and v.file.strip().lower() not in null_equivalents:
            candidate = v.file.strip().replace("\\", "/").lstrip("./")
            if repo_root:
                full_candidate = (repo_root / candidate).resolve()
                is_within_repo = False
                try:
                    full_candidate.relative_to(repo_root)
                    is_within_repo = True
                except ValueError:
                    is_within_repo = False
                if is_within_repo and full_candidate.exists() and full_candidate.is_file():
                    norm_file = candidate
            else:
                norm_file = candidate

        norm_line: int | None = None
        if norm_file is not None and v.line is not None and v.line > 0:
            norm_line = int(v.line)

        safe_desc = redact_secrets(v.description.strip())
        safe_evid = redact_secrets(v.evidence.strip())
        safe_rec = redact_secrets(v.recommendation.strip())

        dedup_key = (v.category, v.description.strip().lower()[:60], norm_file, norm_line)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        cleaned.append(
            Violation(
                rule_id=v.rule_id.strip().upper(),
                category=v.category,
                severity=v.severity,
                file=norm_file,
                line=norm_line,
                description=safe_desc,
                evidence=safe_evid,
                recommendation=safe_rec,
            )
        )

    return cleaned


def run_audit_agent(repo_url: str, max_iterations: int = 15) -> AuditReport:
    llm = LLMClient()
    print(
        f"[Agent] Initialized with provider='{llm.provider_name}', model='{llm.model}'",
        file=sys.stderr,
    )
    print(f"[Agent] Cloning target repository into isolated sandbox: {repo_url}", file=sys.stderr)

    with RepositorySandbox(repo_url) as sandbox:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": AGENT_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Audit the repository '{repo_url}'. "
                    "Begin by discovering the repository structure and commit history, then dynamically select tools "
                    "to inspect configuration files, dependencies, CI/CD workflows, testing setup, and source code "
                    "for DevOps and security violations."
                ),
            },
        ]

        total_tool_calls = 0
        nudged_for_depth = False
        allowed_tool_names = {tool["function"]["name"] for tool in TOOL_DEFINITIONS}

        for iteration in range(1, max_iterations + 1):
            print(f"[Agent] --- Cycle {iteration}/{max_iterations} (Observe & Reason) ---", file=sys.stderr)
            assistant_content = ""
            planned_tool_calls: list[dict[str, Any]] = []

            if llm.supports_native_tool_calling:
                assistant_msg = llm.chat_step(messages=messages, tools=TOOL_DEFINITIONS)
                assistant_content = assistant_msg.content or ""
                if assistant_msg.tool_calls:
                    planned_tool_calls = [
                        {
                            "id": tc.id,
                            "name": tc.function.name,
                            "arguments": tc.function.arguments or "{}",
                        }
                        for tc in assistant_msg.tool_calls
                    ]
                msg_dict: dict[str, Any] = {"role": "assistant", "content": assistant_content}
                if planned_tool_calls:
                    msg_dict["tool_calls"] = [
                        {
                            "id": tc["id"],
                            "type": "function",
                            "function": {
                                "name": tc["name"],
                                "arguments": tc["arguments"],
                            },
                        }
                        for tc in planned_tool_calls
                    ]
                messages.append(msg_dict)
            else:
                action_payload = llm.choose_tool_action(
                    messages=messages,
                    tool_names=sorted(allowed_tool_names),
                )
                action_name = action_payload.get("action")
                assistant_content = json.dumps(action_payload)

                if action_name == "tool":
                    tool_name = str(action_payload.get("tool", "")).strip()
                    if tool_name not in allowed_tool_names:
                        messages.append(
                            {"role": "assistant", "content": assistant_content}
                        )
                        messages.append(
                            {
                                "role": "user",
                                "content": (
                                    f"Invalid tool selection '{tool_name}'. Choose one of: "
                                    + ", ".join(sorted(allowed_tool_names))
                                ),
                            }
                        )
                        continue
                    arguments = action_payload.get("arguments", {})
                    if not isinstance(arguments, dict):
                        arguments = {}
                    planned_tool_calls = [
                        {
                            "id": f"gemini-tool-{iteration}",
                            "name": tool_name,
                            "arguments": json.dumps(arguments),
                        }
                    ]
                messages.append({"role": "assistant", "content": assistant_content})

            if assistant_content:
                thought_preview = assistant_content.strip().replace("\n", " ")[:180]
                print(f"[Agent][Reason] {thought_preview}...", file=sys.stderr)

            if not planned_tool_calls:
                if total_tool_calls < 3 and not nudged_for_depth:
                    nudged_for_depth = True
                    print(
                        "[Agent][Guard] Premature stop detected (< 3 tool calls). Prompting deeper inspection.",
                        file=sys.stderr,
                    )
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "You have only executed a superficial check so far. Before concluding, use `read_file` "
                                "and `search_code` (and `run_ruff` if Python files exist) to inspect the actual contents "
                                "of dependency files, CI workflows, configuration files, and source code."
                            ),
                        }
                    )
                    continue

                print("[Agent] Investigation complete. Moving to report synthesis.", file=sys.stderr)
                break

            for tool_call in planned_tool_calls:
                func_name = tool_call["name"]
                raw_args = tool_call["arguments"]
                try:
                    parsed_args = json.loads(raw_args)
                    if not isinstance(parsed_args, dict):
                        parsed_args = {}
                except json.JSONDecodeError:
                    parsed_args = {}

                print(f"[Agent][Tool Call] {func_name}({json.dumps(parsed_args)})", file=sys.stderr)
                raw_result = sandbox.execute_tool(func_name, parsed_args)
                total_tool_calls += 1

                if len(raw_result) > MAX_TOOL_OUTPUT_CHARS:
                    raw_result = (
                        raw_result[:MAX_TOOL_OUTPUT_CHARS]
                        + f"\n... [Truncated tool output at {MAX_TOOL_OUTPUT_CHARS} chars]"
                    )

                if llm.supports_native_tool_calling:
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call["id"],
                            "name": func_name,
                            "content": raw_result,
                        }
                    )
                else:
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Tool execution result:\n"
                                f"Tool: {func_name}\n"
                                f"Arguments: {json.dumps(parsed_args, ensure_ascii=True)}\n"
                                f"Output:\n{raw_result}"
                            ),
                        }
                    )

        print(
            f"[Agent] Synthesizing structured report after {total_tool_calls} tool executions...",
            file=sys.stderr,
        )
        raw_violations = llm.parse_structured_report(messages)
        clean_violations = sanitize_and_deduplicate_violations(
            raw_violations, sandbox.root_path
        )

        return AuditReport(repository=repo_url, violations=clean_violations)
