# Memory and metacognition mechanisms

## Memory promotion

Transient conversation text is not automatically durable memory. The system creates a memory proposal with:
- memory type (episodic, semantic, procedural, prospective, self-performance);
- summary and source provenance;
- sensitivity classification;
- contextual tags;
- review lifecycle.

The current `MemoryCatalog` is process-local and is a contract prototype, not persistent encrypted storage. A proposal can only be promoted after an external owner-authorization service verifies a signed approval bound to the instance and proposal. The LLM must not mint or validate owner approval.

A production implementation still needs:
- cryptographic signature verification and challenge/replay protection;
- encrypted persistent storage;
- envelope-encryption key hierarchy;
- owner-controlled backup/recovery;
- retention, deletion, and backup-expiry semantics;
- schema versioning, migrations, and audit history.

## Why the memory is versioned

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
