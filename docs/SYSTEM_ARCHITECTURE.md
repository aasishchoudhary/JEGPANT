# System architecture

## Deployment target

The target is a dedicated single-owner instance accessed through an Android application. The phone is the primary interface and may perform selected preprocessing. Compute-heavy video analysis and reasoning may run on dedicated private compute.

The first deployment should be private and isolated rather than a public multi-tenant service. Do not assume that a private cloud VPC or a private repository alone makes data confidential.

## Logical components

```text
Android owner app
  ├─ owner/device authentication
  ├─ local encrypted staging
  ├─ upload and review interface
  └─ signed requests
           |
      private gateway
           |
  owner authorization service
           |
  JEGPANT cognitive runtime
  ├─ cycle coordinator
  ├─ global workspace
  ├─ specialist processors
  ├─ evidence/provenance service
  ├─ memory and temporal knowledge graph
  ├─ evaluation/metacognition
  └─ policy/action gate
           |
  private storage boundary
  ├─ encrypted original media
  ├─ derived observations and indexes
  ├─ memory store
  ├─ evidence ledger and manifests
  └─ encrypted backups
```

## Trust boundaries

1. **Owner device:** can be lost, rooted, compromised, or exposed to malicious apps. Use platform-backed keys where supported; do not assume the device is uncompromised.
2. **Network edge:** all requests are untrusted until authenticated, authorised, and checked for replay/expiry.
3. **Cognitive runtime:** model output is untrusted data. It cannot bypass the policy gate.
4. **Storage:** encrypt at rest, separate keys from data, and verify backup/restore. At-rest encryption does not protect plaintext from a process that has legitimately decrypted it.
5. **Model providers:** treat any external inference provider as a separate data recipient. If readable video, text, embeddings, or memory are sent to it, the data has left the private execution boundary.
6. **Operations:** infrastructure administrators should not automatically receive application-level plaintext access. This requires a real key architecture, not a policy statement alone.

## Data-flow policy

- Original media is immutable after ingestion; edits create a new asset version.
- Derived frames, transcripts, detections, and summaries link to the original source and processing version.
- Every inference links to one or more evidence items and states its limitations.
- Sensitive data is not sent to external models by default.
- External network access and tools are disabled unless a specific capability is authorised.
- Logs contain event IDs and security metadata, not raw video, prompts, transcripts, or memory content.
- Temporary data has explicit deletion/retention rules.

## Model-provider adapter

The cognitive engine calls a provider-neutral interface. A provider adapter must declare:
- model identifier and version;
- data categories transmitted;
- region and retention terms where known;
- whether data is used for training;
- timeout and retry rules;
- response schema and validation;
- failure/abstention behaviour.

A provider-neutral interface is not a privacy guarantee. Each provider must pass a data-protection review before receiving owner data.

## Availability and recovery

- The application must distinguish unavailable compute from lost cognitive state.
- Every durable state transition uses a versioned schema and integrity check.
- Backups are encrypted under owner-controlled recovery material.
- Restore is tested on a clean environment.
- Model upgrades do not migrate or rewrite memory without a versioned transformation and rollback plan.
- Recovery must not create an undocumented vendor or administrator backdoor.

## Quality attributes

- Evidence traceability over response speed.
- Reproducibility of deterministic processing.
- Graceful degradation when vision/LLM providers fail.
- Resource-aware scheduling for long offline jobs.
- Observability without content leakage.
- Portability across private compute providers.
