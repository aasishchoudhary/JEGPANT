# Inference boundary and model-provider policy

## Default is local

The first model adapter speaks the OpenAI-compatible chat-completions protocol. Its default endpoint is:

```text
http://127.0.0.1:3001/v1
```

The client makes no request until a caller invokes it. It has no default remote provider, no embedded API key, and no telemetry. Configure with:

- `JEGPANT_LLM_BASE_URL`
- `JEGPANT_LLM_MODEL`
- `JEGPANT_LLM_API_KEY` (optional for a local endpoint)
- `JEGPANT_LLM_TIMEOUT_SECONDS`
- `JEGPANT_ALLOW_REMOTE_INFERENCE=true` (remote use only after explicit review)

Remote endpoints are rejected by default. To opt in, the endpoint must use HTTPS, an API key must be configured, and the opt-in flag must be true. This is a guardrail, not a complete provider compliance review.

## Data classification before inference

Before sending any content, the calling service must classify it:
- public/non-sensitive;
- owner-private;
- highly sensitive (original video, intimate conversation, investigative records, identity materials, memory).

Highly sensitive material stays in the private execution boundary by default. Sending data to an external provider requires explicit owner approval, provider retention/training review, purpose limitation, and a record of the data sent.

Embeddings, frame crops, audio snippets, OCR, transcripts, summaries, and retrieved memory can disclose the same underlying facts as the original source. They are not automatically anonymous or harmless.

## Model output is untrusted

- Treat all model responses as untrusted data.
- Parse typed structured outputs and reject invalid schemas.
- Validate every referenced evidence ID against the case ledger.
- Reject unknown IDs, malformed output, and contradictory field combinations.
- Model-generated evidence relationships are proposals for human/analytic review.
- The model cannot alter owner keys, access policies, memory approval, or action permissions.
- Tool execution and external actions are separated from text generation.

The current `HypothesisGenerator` is deliberately narrow. It generates alternatives and proposed evidence links; it does not determine guilt, deception, diagnosis, or truth.

## Operational limitations

- The local endpoint must be bound to loopback or an appropriately isolated private network.
- The adapter does not provide authentication, TLS termination, model sandboxing, resource isolation, or server-side authorization.
- A local endpoint may itself proxy to a remote provider. JEGPANT cannot infer that from an OpenAI-compatible URL; the operator must verify the endpoint's data flow.
- The API adapter is a development component, not a production security boundary.
