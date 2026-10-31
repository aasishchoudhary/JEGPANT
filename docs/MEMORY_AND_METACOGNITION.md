# Memory and metacognition mechanisms

## Memory proposal and owner approval

Transient conversation text is not automatically durable memory. The system creates a memory proposal with:
- memory type (episodic, semantic, procedural, prospective, self-performance);
- summary and source provenance;
- sensitivity classification;
- contextual tags;
- review lifecycle.

The `MemoryCatalog` is the proposal layer. A proposal can only be promoted after an external owner-authorization service verifies signed approval bound to the instance and proposal. The LLM must not mint or validate owner approval.

## Encrypted persistent store prototype

`EncryptedMemoryStore` is the first persistent memory-storage component. It stores one cognitive instance's memory records in SQLite and encrypts each record using AES-256-GCM. The encrypted payload includes the summary, provenance references, sensitivity, tags, timestamps, and approval reference. The database retains only a memory ID, key version, schema version, nonce, and ciphertext as routing metadata.

The cryptographic key is supplied by an external `DataKeyProvider`; it is not stored in SQLite, generated from a user password, or committed to source control. The intended production key sources are hardware-backed Android Keystore, a suitable HSM/KMS integration, or an owner-controlled recovery/key-wrapping flow. The current repository provides only the interface and tests; it does **not** yet implement these real key providers.

Security properties:
- Each record receives a fresh 96-bit random nonce.
- The AES-GCM authentication tag protects both ciphertext and associated data.
- Associated data binds the encrypted record to the JEGPANT instance, memory ID, key version, and schema version.
- A key-versioned rotation operation decrypts and re-encrypts records transactionally.
- SQLite `secure_delete` is enabled as a secondary storage hygiene control.

Critical limitations:
- A key provider that returns a key from a plaintext environment variable, local file, or source code defeats the intended key-custody boundary.
- AES-GCM protects stored payload confidentiality and integrity; it does not protect plaintext while the authorised process is using it.
- Memory IDs and key/schema versions remain visible in SQLite metadata.
- SQLite's secure-delete setting is not a universal forensic-erasure guarantee; backups, filesystem snapshots, flash wear-levelled blocks, crash dumps, and replicas require separate retention and destruction policies.
- The present store has no semantic search/index, owner recovery, backup encryption protocol, server attestation, or Android Keystore adapter.
- This component has not received an independent security review and is not production-ready.

The implementation uses the maintained PyCA `cryptography` AESGCM API. Its documentation explicitly warns that a nonce must never be reused with the same key: https://cryptography.io/en/latest/hazmat/primitives/aead/

SQLite documents that `PRAGMA secure_delete=ON` overwrites deleted content in ordinary tables, but also documents limitations and recommends additional handling for forensic traces: https://www.sqlite.org/pragma.html#pragma_secure_delete

## Key rotation and recovery

`rotate_key(new_version)` is an atomic record re-encryption operation. The old key must remain available until the transaction is committed and backup/restore has been tested. The key provider—not the database—controls whether old keys are retained or revoked.

Production still requires:
- owner-bound key provisioning and device enrolment;
- hardware-backed key protection where available;
- owner-controlled offline recovery material;
- backup/restore testing, including WAL/journal sidecar handling if journal mode changes;
- revocation and secure key destruction procedures;
- versioned schema migrations;
- an audit trail for memory changes.

## Why memory is versioned

A later observation may overturn an earlier interpretation. JEGPANT should add a new version or superseding record rather than silently overwrite the old conclusion. The source episode remains intact while the current semantic interpretation changes.

## Metacognitive calibration

A system's confidence must be tested against outcomes. The first implementation records binary forecasts with explicit resolution criteria and a verification reference. Resolved predictions receive a Brier score:

```text
Brier = (forecast_probability - observed_outcome)^2
```

Lower is better. This score is meaningful only for well-defined binary propositions with defensible resolution criteria. Forecasts should be grouped by task domain, horizon, and evidence conditions. Aggregated scores can conceal systematic failure. Samples below 30 are explicitly labelled too small for stable calibration claims; 30 is a reporting caution, not a universal statistical sufficiency threshold.

## Attention and global workspace

Specialists submit candidate signals with multiple objective estimates: relevance, novelty, uncertainty, information gain, source quality, cost, and risk. The workspace currently computes a Pareto frontier rather than forcing all trade-offs into an arbitrary weighted score. It may return several non-dominated candidates. A later scheduler chooses among them under explicit resource and safety constraints.

These priority metrics allocate computation and attention; they do **not** determine whether a claim is true.
