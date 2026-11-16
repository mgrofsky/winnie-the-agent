import json

import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from pydantic import BaseModel

from agents import llm
from agents.llm import BedrockJsonLLM, LLMOutputError, LLMRequestError, LLMUnavailable


class Verdict(BaseModel):
    judgement: str
    score: int


def _reply(text, stop="end_turn"):
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}},
            "stopReason": stop, "usage": {"inputTokens": 11, "outputTokens": 7}}


class Client:
    def __init__(self, *results):
        self.results = list(results)
        self.requests = []

    def converse(self, **kwargs):
        self.requests.append(kwargs)
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def _client_error(code, status):
    return ClientError({"Error": {"Code": code, "Message": "x"},
                        "ResponseMetadata": {"HTTPStatusCode": status}}, "Converse")


def test_reply_is_validated_and_the_request_offers_no_tools():
    client = Client(_reply('{"judgement": "MALICIOUS", "score": 9}'))
    model = BedrockJsonLLM(model="model-x", client=client)
    out = model.complete_json("You are an analyst.", "data", Verdict)
    assert out == Verdict(judgement="MALICIOUS", score=9)
    request = client.requests[0]
    assert set(request) == {"modelId", "system", "messages", "inferenceConfig"}
    assert request["modelId"] == "model-x"
    assert request["inferenceConfig"] == {"maxTokens": 2048}
    assert '"judgement"' in request["system"][0]["text"]
    assert request["messages"] == [{"role": "user", "content": [{"text": "data"}]}]
    assert (model.calls, model.input_tokens, model.output_tokens) == (1, 11, 7)


def test_json_inside_a_code_fence_is_accepted():
    client = Client(_reply('```json\n{"judgement": "BENIGN", "score": 1}\n```'))
    assert BedrockJsonLLM(model="m", client=client).complete_json("s", "u", Verdict).score == 1


def test_invalid_output_is_retried_once_then_dropped():
    client = Client(_reply("I think it is malicious"), _reply('{"judgement": 5}'))
    with pytest.raises(LLMOutputError):
        BedrockJsonLLM(model="m", client=client).complete_json("s", "u", Verdict)
    assert len(client.requests) == 2


def test_filtered_reply_is_an_output_error():
    client = Client(_reply("", stop="content_filtered"))
    with pytest.raises(LLMOutputError):
        BedrockJsonLLM(model="m", client=client, validation_retries=0).complete_json(
            "s", "u", Verdict)


@pytest.mark.parametrize("error,expected", [
    (_client_error("ThrottlingException", 429), LLMUnavailable),
    (_client_error("ServiceUnavailableException", 503), LLMUnavailable),
    (_client_error("ModelTimeoutException", 408), LLMUnavailable),
    (_client_error("ValidationException", 400), LLMRequestError),
    (_client_error("AccessDeniedException", 403), LLMRequestError),
    (NoCredentialsError(), LLMUnavailable),
])
def test_provider_errors_map_to_the_agent_error_types(error, expected):
    client = Client(error)
    with pytest.raises(expected):
        BedrockJsonLLM(model="m", client=client).complete_json("s", "u", Verdict)
    assert len(client.requests) == 1


def test_factory_picks_the_provider(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    assert llm.build_json_llm({}, None) is None                      # anthropic, no key

    class Session:
        def __init__(self, profile_name=None, region_name=None):
            self.args = (profile_name, region_name)

        def get_credentials(self):
            return object()

        def client(self, name, config=None):
            return ("client", name, self.args)

    import boto3
    monkeypatch.setattr(boto3, "Session", Session)
    built = llm.build_json_llm({"agents": {
        "provider": "Bedrock", "aws_region": "us-west-2", "aws_credentials_profile": "lab",
        "model": "model-x"}})
    assert isinstance(built, BedrockJsonLLM)
    assert built.client == ("client", "bedrock-runtime", ("lab", "us-west-2"))

    monkeypatch.setattr(Session, "get_credentials", lambda self: None)
    assert llm.build_json_llm({"agents": {"provider": "bedrock"}}, "model-x") is None

    with pytest.raises(ValueError):
        llm.build_json_llm({"agents": {"provider": "bedrock"}}, None)
    with pytest.raises(ValueError):
        llm.build_json_llm({"agents": {"provider": "other"}}, "m")


def test_schema_text_is_compact_json():
    client = Client(_reply('{"judgement": "X", "score": 0}'))
    BedrockJsonLLM(model="m", client=client).complete_json("s", "u", Verdict)
    schema_text = client.requests[0]["system"][0]["text"].split("JSON schema:\n", 1)[1]
    assert json.loads(schema_text)["required"] == ["judgement", "score"]
