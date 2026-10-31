import io
import json
from unittest.mock import patch

import pytest

from jegpant.inference import (
    ChatMessage,
    InferenceProviderError,
    OpenAICompatibleClient,
)


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

    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    client = OpenAICompatibleClient()
    with patch("jegpant.inference.urlopen", return_value=FakeResponse(body)):
        result = client.complete((ChatMessage("user", "ping"),))

    assert result.content == "ready"
    assert result.model == "local-qwen"


def test_invalid_endpoint_response_is_rejected():
    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    client = OpenAICompatibleClient()
    with patch("jegpant.inference.urlopen", return_value=FakeResponse(b"not-json")):
        with pytest.raises(InferenceProviderError):
            client.complete((ChatMessage("user", "ping"),))
