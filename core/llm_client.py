import json
import os
import sys
import time
from typing import Any

from openai import APIError, OpenAI, RateLimitError

from core.schemas import Violation, ViolationListWrapper


class LLMClient:
    """Multi-provider OpenAI SDK client supporting OPENAI_API_KEY, GITHUB_TOKEN, and GEMINI_API_KEY."""

    def __init__(self):
        self.api_key: str | None = None
        self.base_url: str | None = None
        self.provider_name: str = "OpenAI"

        if os.getenv("OPENAI_API_KEY"):
            self.api_key = os.getenv("OPENAI_API_KEY")
            self.base_url = os.getenv("OPENAI_BASE_URL")
            self.default_model = "gpt-4o-mini"
            self.provider_name = "OpenAI"
        elif os.getenv("GITHUB_TOKEN"):
            self.api_key = os.getenv("GITHUB_TOKEN")
            self.base_url = "[https://models.inference.ai.azure.com](https://models.inference.ai.azure.com)"
            self.default_model = "gpt-4o"
            self.provider_name = "GitHub Models"
        elif os.getenv("GEMINI_API_KEY"):
            self.api_key = os.getenv("GEMINI_API_KEY")
            self.base_url = "[https://generativelanguage.googleapis.com/v1beta/openai/](https://generativelanguage.googleapis.com/v1beta/openai/)"
            self.default_model = "gemini-2.5-flash"
            self.provider_name = "Google Gemini"
        else:
            raise OSError(
                "Missing LLM API credentials. Set OPENAI_API_KEY, GITHUB_TOKEN, or GEMINI_API_KEY in .env or environment."
            )

        self.model = os.getenv("LLM_MODEL", self.default_model)
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
                if attempt == max_retries or (e.status_code and e.status_code < 500 and e.status_code != 429):
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
