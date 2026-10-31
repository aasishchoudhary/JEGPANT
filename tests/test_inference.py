import io
import json
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request

import pytest

from jegpant.inference import (
    ChatMessage,
    InferenceProviderError,
    OpenAICompatibleClient,
)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class FakeOpener:
    def __init__(self, body=b"{}", error=None):
        self.body = body
        self.error = error
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        if self.error:
            raise self.error
        return FakeResponse(self.body)


def test_local_endpoint_is_default_and_allowed():
    client = OpenAICompatibleClient()
    assert client.base_url == "http://127.0.0.1:3001/v1"


def test_remote_endpoint_requires_explicit_opt_in():
    with pytest.raises(ValueError):
        OpenAICompatibleClient(base_url="https://api.example.com/v1")


def test_remote_endpoint_requires_https_and_api_key():
    with pytest.raises(ValueError):
        OpenAICompatibleClient(
            base_url="http://api.example.com/v1",
            allow_remote=True,
            api_key="test-key",
        )
    with pytest.raises(ValueError):
        OpenAICompatibleClient(
            base_url="https://api.example.com/v1",
            allow_remote=True,
        )


def test_remote_endpoint_with_explicit_opt_in_is_configurable():
    client = OpenAICompatibleClient(
        base_url="https://api.example.com/v1",
        allow_remote=True,
        api_key="test-key",
    )
    assert client.base_url == "https://api.example.com/v1"


def test_response_is_parsed_without_exposing_credentials():
    body = json.dumps(
        {"model": "local-qwen", "choices": [{"message": {"content": "ready"}}]}
    ).encode()
    client = OpenAICompatibleClient()
    fake = FakeOpener(body)
    client._opener = fake

    result = client.complete((ChatMessage("user", "ping"),))

    assert result.content == "ready"
    assert result.model == "local-qwen"
    assert fake.request.get_header("Authorization") is None
    assert fake.timeout == 120.0


def test_invalid_endpoint_response_is_rejected():
    client = OpenAICompatibleClient()
    client._opener = FakeOpener(b"not-json")
    with pytest.raises(InferenceProviderError):
        client.complete((ChatMessage("user", "ping"),))


def test_redirect_handler_refuses_redirects():
    client = OpenAICompatibleClient()
    handlers = [
        handler
        for handler in client._opener.handlers
        if isinstance(handler, HTTPRedirectHandler)
    ]
    assert len(handlers) == 1
    request = Request("http://127.0.0.1:3001/v1/chat/completions")
    assert handlers[0].redirect_request(
        request, None, 302, "Found", {}, "https://external.example/collect"
    ) is None


def test_non_finite_timeout_is_rejected():
    with pytest.raises(ValueError):
        OpenAICompatibleClient(timeout_seconds=float("nan"))


def test_response_size_limit_is_enforced():
    client = OpenAICompatibleClient()
    client._opener = FakeOpener(b"x" * (client.MAX_RESPONSE_BYTES + 1))
    with pytest.raises(InferenceProviderError, match="size limit"):
        client.complete((ChatMessage("user", "ping"),))
