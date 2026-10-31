# JEGPANT

**A private, owner-bound cognitive system — research and engineering workspace.**

JEGPANT is being developed as a persistent cognitive system, not a character simulator or a thin chat interface. Its purpose is to coordinate evidence-grounded perception, memory, hypothesis formation, adversarial testing, planning, and metacognitive review across sessions.

The initial implementation is deliberately conservative: a deterministic Python core, explicit evidence provenance, and tests. Model providers, video models, Android interfaces, and private compute are adapters to be added behind stable boundaries—not trusted as the cognitive system itself.

> **Development status:** foundation stage. This repository currently contains architecture specifications and a small, testable epistemic core. It does not yet contain a trained model, autonomous agent, production security boundary, Android application, or validated psychological inference system.

## Non-negotiable design principles

1. **One owner, one cognitive instance.** No public registration, tenants, guest identities, or shared memory.
2. **Private runtime, separable from public source.** Public code is not permission to access the running system. No private data, keys, tokens, video, memory exports, or credentials belong in Git.
3. **Evidence before interpretation.** Raw observations, extracted features, hypotheses, and conclusions remain distinct and traceable.
4. **Uncertainty is represented, not hidden.** The system must preserve alternatives, contradictions, unknowns, and source limitations.
5. **A hypothesis is not a fact.** No inference about deception, intent, guilt, personality, or mental state from appearance or a single behavioural cue.
6. **Human authority over consequential actions.** External actions, memory promotion, and high-impact conclusions require explicit owner review.
7. **Model-neutral cognitive state.** The persistent identity and memory must survive model-provider changes.
8. **Test mechanisms, not personas.** Historical people and fictional characters are research inspirations; their capabilities must be translated into testable methods rather than imitated as personalities.

## Current milestone

- [x] Establish project charter and architectural boundaries.
- [x] Define single-owner security and privacy model.
- [x] Define evidence-first reasoning and post-hoc video analysis.
- [x] Add a small deterministic evidence ledger and hypothesis comparison core.
- [x] Add tests for ledger integrity and uncertainty-preserving comparisons.
- [ ] Add persistent, encrypted memory storage with an independently reviewed key lifecycle.
- [ ] Add model-provider interface and evaluation harness.
- [ ] Add long-video indexing, temporal retrieval, and multimodal evidence adapters.
- [ ] Add owner-bound Android client and device enrolment.
- [ ] Complete threat-model review and deployment acceptance tests.

## Quick start

Requires Python 3.11 or newer.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

python -m pip install -e ".[dev]"
pytest
```

The core has no runtime network calls and does not send content to an AI provider.

## Repository map

- `src/jegpant/` — deterministic cognitive/evidence primitives.
- `tests/` — executable behavioural and integrity tests.
- `docs/PRODUCT_CHARTER.md` — product definition and non-goals.
- `docs/COGNITIVE_ARCHITECTURE.md` — proposed cognitive mechanisms and state model.
- `docs/SYSTEM_ARCHITECTURE.md` — deployment boundaries and data flow.
- `docs/OWNER_SECURITY_MODEL.md` — owner identity, device trust, keys, and recovery.
- `docs/VIDEO_EVIDENCE_PIPELINE.md` — asynchronous video ingestion and evidence traceability.
- `docs/RESEARCH_AND_EVALUATION.md` — evidence standards and validation programme.
- `docs/100_MIND_RESEARCH_ROSTER.md` — provisional research roster; not a scientific ranking.

## Public-repository warning

This repository is public during the development period. Treat everything committed here as permanently public, even after the repository is later made private. Do not commit private data or secrets. Making the repository private later does not erase copies, forks, caches, logs, or previously cloned history.

See [SECURITY.md](SECURITY.md) before contributing or deploying.
