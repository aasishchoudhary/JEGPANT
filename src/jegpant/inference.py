"""Provider-neutral chat interface and private-by-default local HTTP adapter."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from math import isfinite
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)


class InferenceProviderError(RuntimeError):
    """A safe, content-free inference transport or response error."""


class _NoRedirectHandler(HTTPRedirectHandler):
    """Prevent a local inference endpoint from redirecting prompts elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True, slots=True)
class ChatMessage:
    role: str
    content: str

    def __post_init__(self) -> None:
        if self.role not in {"system", "user", "assistant"}:
            raise ValueError("role must be system, user, or assistant")
        if not isinstance(self.content, str):
            raise ValueError("message content must be a string")


@dataclass(frozen=True, slots=True)
class ChatResponse:
    content: str
    model: str


class ChatCompletionClient(Protocol):
    def complete(
        self,
        messages: tuple[ChatMessage, ...],
        *,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> ChatResponse:
        """Return one assistant response."""
        ...


class OpenAICompatibleClient:
    """Minimal adapter for local OpenAI-compatible inference servers.

    Remote hosts are rejected unless allow_remote=True, HTTPS is used, and an
    API key is supplied. Redirects and implicit environment proxies are
    disabled so a loopback request cannot silently leave the local boundary.
    The caller remains responsible for provider review and endpoint isolation.
    """

    MAX_RESPONSE_BYTES = 8 * 1024 * 1024

    def __init__(
        self,
        *,
        base_url: str = "http://127.0.0.1:3001/v1",
        model: str = "local-model",
        api_key: str | None = None,
        timeout_seconds: float = 120.0,
        allow_remote: bool = False,
    ) -> None:
        if not model.strip():
            raise ValueError("model must not be empty")
        if not isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        api_key = api_key.strip() if api_key else None
        self.base_url = self._validate_base_url(base_url, allow_remote, api_key)
        self.model = model
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        # Do not inherit system proxy settings for private inference traffic.
        self._opener = build_opener(ProxyHandler({}), _NoRedirectHandler())

    @classmethod
    def from_environment(cls) -> "OpenAICompatibleClient":
        """Load configuration without printing or logging credentials."""
        allow_remote = os.getenv("JEGPANT_ALLOW_REMOTE_INFERENCE", "").lower() == "true"
        return cls(
            base_url=os.getenv(
                "JEGPANT_LLM_BASE_URL", "http://127.0.0.1:3001/v1"
            ),
            model=os.getenv("JEGPANT_LLM_MODEL", "local-model"),
            api_key=os.getenv("JEGPANT_LLM_API_KEY"),
            timeout_seconds=float(os.getenv("JEGPANT_LLM_TIMEOUT_SECONDS", "120")),
            allow_remote=allow_remote,
        )

    @staticmethod
    def _validate_base_url(
        base_url: str, allow_remote: bool, api_key: str | None
    ) -> str:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain credentials, query, or fragment")

        host = parsed.hostname.lower()
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        is_local = host in local_hosts
        if not is_local:
            if not allow_remote:
                raise ValueError(
                    "remote inference is disabled; set explicit remote opt-in after review"
                )
            if parsed.scheme != "https":
                raise ValueError("remote inference requires HTTPS")
            if not api_key:
                raise ValueError("remote inference requires an API key")

        return base_url.rstrip("/")

    def complete(
        self,
        messages: tuple[ChatMessage, ...],
        *,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> ChatResponse:
        if not messages:
            raise ValueError("at least one message is required")
        if not isfinite(temperature) or not 0.0 <= temperature <= 2.0:
            raise ValueError("temperature must be finite and between 0 and 2")
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")

        payload = {
            "model": self.model,
            "messages": [
                {"role": item.role, "content": item.content} for item in messages
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        request = Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                response_body = response.read(self.MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise InferenceProviderError(
                f"inference endpoint returned HTTP {exc.code}"
            ) from None
        except (URLError, TimeoutError, OSError):
            raise InferenceProviderError(
                "inference endpoint could not be reached or timed out"
            ) from None

        if len(response_body) > self.MAX_RESPONSE_BYTES:
            raise InferenceProviderError("inference response exceeded the size limit")

        try:
            result = json.loads(response_body.decode("utf-8"))
            content = result["choices"][0]["message"]["content"]
            response_model = result.get("model", self.model)
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, IndexError, TypeError):
            raise InferenceProviderError("inference endpoint returned an invalid response") from None
        if not isinstance(content, str) or not content.strip():
            raise InferenceProviderError("inference endpoint returned empty content")
        return ChatResponse(content=content, model=str(response_model))
