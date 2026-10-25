import json
import os
import sys
import time
from typing import Any

from openai import APIError, OpenAI, RateLimitError

from core.schemas import Violation, ViolationListWrapper


def _get_configured_key(env_name: str) -> str | None:
    value = os.getenv(env_name, "").strip()
    if not value:
        return None
    lowered = value.lower()
    if lowered.startswith("your_") and lowered.endswith("_here"):
        return None
    return value


def normalize_model_name(provider_name: str, raw_model: str) -> str:
    model = raw_model.strip()
    if model.upper().startswith("LLM_MODEL="):
        model = model.split("=", 1)[1].strip()
    if provider_name == "Google Gemini" and not model.startswith("models/"):
        model = f"models/{model}"
    return model


class LLMClient:
    """Multi-provider OpenAI SDK client supporting OPENAI_API_KEY, GITHUB_TOKEN, and GEMINI_API_KEY."""

    def __init__(self):
        self.api_key: str | None = None
        self.base_url: str | None = None
        self.provider_name: str = "OpenAI"

        openai_key = _get_configured_key("OPENAI_API_KEY")
        github_key = _get_configured_key("GITHUB_TOKEN")
        gemini_key = _get_configured_key("GEMINI_API_KEY")

        if openai_key:
            self.api_key = openai_key
            self.base_url = os.getenv("OPENAI_BASE_URL")
            self.default_model = "gpt-4o-mini"
            self.provider_name = "OpenAI"
        elif github_key:
            self.api_key = github_key
            self.base_url = "https://models.inference.ai.azure.com"
            self.default_model = "gpt-4o"
            self.provider_name = "GitHub Models"
        elif gemini_key:
            self.api_key = gemini_key
            self.base_url = "https://generativelanguage.googleapis.com/v1beta/openai/"
            self.default_model = "gemini-3.8-flash"
            self.provider_name = "Google Gemini"
        else:
            raise OSError(
                "Missing LLM API credentials. Set OPENAI_API_KEY, GITHUB_TOKEN, or GEMINI_API_KEY in .env or environment."
            )

        self.model = normalize_model_name(
            self.provider_name,
            os.getenv("LLM_MODEL", self.default_model),
        )
        self.supports_native_tool_calling = self.provider_name != "Google Gemini"
        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=90.0)

    def _call_with_retry(self, func, *args, **kwargs) -> Any:
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                return func(*args, **kwargs)
            except RateLimitError as e:
                if attempt == max_retries:
                    raise RuntimeError(f"LLM rate limit exceeded after {max_retries} attempts: {e}") from e
                wait_time = 2 ** attempt
                print(f"[Agent][Warn] Rate limit hit. Retrying in {wait_time}s...", file=sys.stderr)
                time.sleep(wait_time)
            except APIError as e:
                status_code = getattr(e, "status_code", None)
                if attempt == max_retries or (status_code and status_code < 500 and status_code != 429):
                    raise RuntimeError(f"LLM API error ({self.provider_name}): {e}") from e
                wait_time = 2 ** attempt
                print(f"[Agent][Warn] Transient API error. Retrying in {wait_time}s...", file=sys.stderr)
                time.sleep(wait_time)

    def chat_step(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Any:
        response = self._call_with_retry(
            self.client.chat.completions.create,
            model=self.model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0.0,
        )
        return response.choices[0].message

    def choose_tool_action(
        self, messages: list[dict[str, Any]], tool_names: list[str]
    ) -> dict[str, Any]:
        chooser_instruction = {
            "role": "user",
            "content": (
                "Choose exactly one next step and return ONLY JSON in this schema: "
                '{"action":"tool","tool":"<name>","arguments":{}} OR '
                '{"action":"final","summary":"<brief reason>"}.\n'
                f"Allowed tool names: {', '.join(tool_names)}.\n"
                "Do not include markdown, explanations, or extra keys."
            ),
        }
        response = self._call_with_retry(
            self.client.chat.completions.create,
            model=self.model,
            messages=messages + [chooser_instruction],
            response_format={"type": "json_object"},
            temperature=0.0,
        )
        raw_json = response.choices[0].message.content or '{"action":"final","summary":"No output"}'
        data = json.loads(raw_json)
        if not isinstance(data, dict):
            return {"action": "final", "summary": "Invalid action payload"}
        return data

    def parse_structured_report(self, messages: list[dict[str, Any]]) -> list[Violation]:
        synthesis_instruction = {
            "role": "user",
            "content": (
                "Investigation complete. Based strictly on the tool evidence gathered in this conversation, "
                "produce the final deduplicated list of confirmed DevOps violations. "
                "Follow all schema rules: allowed categories, allowed severities (critical, high, medium, low), "
                "POSIX relative file paths (or null if repository-wide), 1-based line numbers (or null if file/repo-wide), "
                "and ensure all secret values are redacted."
            ),
        }
        final_messages = messages + [synthesis_instruction]

        try:
            completion = self._call_with_retry(
                self.client.beta.chat.completions.parse,
                model=self.model,
                messages=final_messages,
                response_format=ViolationListWrapper,
                temperature=0.0,
            )
            parsed = completion.choices[0].message.parsed
            if parsed and isinstance(parsed, ViolationListWrapper):
                return parsed.violations
        except Exception as e:
            print(
                f"[Agent][Info] Structured parse fallback triggered ({e}). Using JSON object mode.",
                file=sys.stderr,
            )

        fallback_prompt = {
            "role": "user",
            "content": (
                "Return ONLY a valid JSON object matching this exact schema: "
                '{"violations": [{"rule_id": "SEC-001", "category": "security", "severity": "critical", '
                '"file": "path/or/null", "line": 10, "description": "...", "evidence": "...", "recommendation": "..."}]}'
            ),
        }
        response = self._call_with_retry(
            self.client.chat.completions.create,
            model=self.model,
            messages=final_messages + [fallback_prompt],
            response_format={"type": "json_object"},
            temperature=0.0,
        )
        raw_json = response.choices[0].message.content or '{"violations": []}'
        data = json.loads(raw_json)
        wrapper = ViolationListWrapper.model_validate(data)
        return wrapper.violations
