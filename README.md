# JEGPANT

**A private, owner-bound cognitive system — research and engineering workspace.**

JEGPANT is being developed as a persistent cognitive system, not a character simulator or a thin chat interface. Its purpose is to coordinate evidence-grounded perception, memory, hypothesis formation, adversarial testing, planning, and metacognitive review across sessions.

The implementation is being built as a hybrid system: explicit cognitive state and typed evidence models, deterministic controls, specialist processors, and model-provider adapters. A language model is a reasoning component—not the identity, memory, policy engine, or complete mind.

> **Development status:** foundation and prototype stage. The repository now contains an encrypted SQLite memory-record store with an external key-provider interface, local video metadata intake, a deterministic epistemic core, a loopback-default inference adapter, a structured hypothesis generator, architecture specifications, and automated tests. It does not yet contain production owner key custody, owner recovery, a deployed private backend, an Android application, a trained model, or validated psychological inference.

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

- [x] Establish project charter, cognitive architecture, and system boundaries.
- [x] Define single-owner identity, device trust, recovery, and privacy model.
- [x] Define asynchronous post-hoc video evidence pipeline.
- [x] Add local video hashing and bounded ffprobe metadata intake.
- [x] Add append-only evidence ledger with hash-chain verification.
- [x] Add typed hypotheses, evidence-linked claims, and contradiction-preserving comparison.
- [x] Add temporal video metadata and event-timeline primitives.
- [x] Add global-workspace Pareto selection for competing specialist outputs.
- [x] Add owner-authorised memory proposal/promotion contract.
- [x] Add encrypted SQLite memory-record store using AES-256-GCM and an external key-provider interface.
- [x] Add key-version rotation and ciphertext integrity tests.
- [x] Add forecast resolution and Brier-score calibration primitives.
- [x] Add loopback-default OpenAI-compatible inference client and structured hypothesis generation.
- [x] Add GitHub Actions matrix, compile and Ruff checks.
- [ ] Implement production Android Keystore/HSM-backed key provider and owner recovery.
- [ ] Implement encrypted media vault, upload workflow, and sandboxed media workers.
- [ ] Implement encrypted backup/restore and deletion lifecycle.
- [ ] Implement durable cognitive-state orchestration and temporal knowledge graph.
- [ ] Add frame/audio extraction, visual indexing, event detection, and temporal retrieval.
- [ ] Add model-provider evaluation, red-team benchmarks, and calibration datasets.
- [ ] Build the owner-bound Android application and device enrolment.
- [ ] Complete independent security review and deployment acceptance tests.

## Quick start

Requires Python 3.11 or newer and FFmpeg/ffprobe for local video metadata intake.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\\Scripts\\Activate.ps1

python -m pip install -e ".[dev]"
pytest
```

The package makes no inference request automatically. The OpenAI-compatible adapter defaults to `http://127.0.0.1:3001/v1`; remote endpoints are rejected unless explicitly opted in, configured for HTTPS, and supplied an API key. Review [INFERENCE_BOUNDARY.md](docs/INFERENCE_BOUNDARY.md) before connecting any provider.

The encrypted memory store requires an externally supplied 32-byte data key. Do not use a source-code constant or a plaintext environment variable as the production key source. The repository does not yet provide Android Keystore, HSM, or owner-recovery integration. Review [MEMORY_AND_METACOGNITION.md](docs/MEMORY_AND_METACOGNITION.md).

The video intake helper only hashes and probes metadata. It does not decode frames or analyse people. Production media parsing requires a hardened, unprivileged sandbox. Review [VIDEO_EVIDENCE_PIPELINE.md](docs/VIDEO_EVIDENCE_PIPELINE.md).

## Repository map

- `src/jegpant/` — evidence, claims, hypotheses, video, media intake, memory, encrypted storage, workspace, metacognition, and inference primitives.
- `tests/` — executable behavioural, integrity, encryption, and media-intake tests.
- `docs/PRODUCT_CHARTER.md` — product definition and non-goals.
- `docs/COGNITIVE_ARCHITECTURE.md` — cognitive processes, state, specialist roles, and memory lifecycle.
- `docs/SYSTEM_ARCHITECTURE.md` — deployment boundaries and data flow.
- `docs/OWNER_SECURITY_MODEL.md` — owner identity, device trust, keys, and recovery.
- `docs/VIDEO_EVIDENCE_PIPELINE.md` — asynchronous video ingestion and evidence traceability.
- `docs/MEMORY_AND_METACOGNITION.md` — encrypted memory prototype, memory promotion, key rotation, and calibration.
- `docs/INFERENCE_BOUNDARY.md` — model-provider boundary and privacy controls.
- `docs/RESEARCH_AND_EVALUATION.md` — research standards and validation programme.
- `docs/100_MIND_RESEARCH_ROSTER.md` — provisional research roster, with Patrick Jane at #100.
- `docs/CAPABILITY_EXTRACTION_MATRIX_01_20.md` — research-to-engineering mapping for the first 20 candidates.

## Public-repository warning

This repository is public during the development period. Treat everything committed here as permanently public, even after the repository is later made private. Do not commit private data or secrets. Making the repository private later does not erase copies, forks, caches, logs, or previously cloned history.

See [SECURITY.md](SECURITY.md) before contributing or deploying.
