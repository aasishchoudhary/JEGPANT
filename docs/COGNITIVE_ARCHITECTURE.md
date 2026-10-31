# Cognitive architecture

## Architectural stance

JEGPANT will use a hybrid, modular cognitive architecture. A language model may be a powerful reasoning substrate, but it is not the architecture, the identity, the memory system, or the authority layer. Cognitive state must be explicitly represented outside any model's transient context window.

The architecture borrows questions and mechanisms from cognitive architectures such as LIDA and Soar, global-workspace theories, memory research, metacognition, causal inference, and predictive-processing work. These are research inspirations, not settled descriptions of the human brain.

References:
- LIDA tutorial: https://doi.org/10.1016/j.bica.2016.04.003
- Soar architecture and decision cycle: https://soar.eecs.umich.edu/soar_manual/02_TheSoarArchitecture/
- Baars & Franklin, global workspace / IDA: https://pubmed.ncbi.nlm.nih.gov/17998071/
- Review of predictive coding and active inference evidence: https://pubmed.ncbi.nlm.nih.gov/38030100/

## Persistent cognitive identity

The cognitive identity is a versioned, owner-bound state object. It is distinct from:
- the Android application installation;
- the owner's login or device credential;
- a model provider or model version;
- the storage database;
- an individual conversation or investigation.

The identity manifest references:
- immutable instance identifier;
- owner public-key identity and enrolled-device set;
- memory namespace and key version;
- cognitive schema version;
- active model/adapter configuration;
- durable memory root and integrity metadata;
- policy and capability versions;
- migration and recovery history.

The manifest must not contain private keys or plaintext secrets. Model changes must not silently reset identity, goals, preferences, memories, or evaluation history.

## Processing systems

### 1. Input and perceptual systems

Adapters transform external material into typed, source-linked observations:
- video/audio segmentation and event extraction;
- OCR/ASR outputs with timestamps;
- object/person tracking with track IDs and uncertainty;
- document parsing and structured-data import;
- user-provided descriptions and direct observations.

Perception outputs are *claims about the source*, not facts about the world. Every observation records its source, extraction method, time/region, model version, quality limitations, and review status.

### 2. Working state

Short-lived, actively manipulated state for the current cognitive cycle:
- current goal and subgoals;
- retrieved context;
- candidate observations;
- candidate hypotheses;
- constraints and action options;
- unresolved contradictions;
- temporary reasoning products.

Working state is bounded and reconstructible. It is not the only location where important knowledge lives.

### 3. Global coordination workspace

Specialist processors publish candidate results to a shared workspace. A coordinator chooses which items deserve attention based on relevance to current goals, novelty, uncertainty, expected information gain, safety, and resource cost.

The workspace does not make a statement true by selecting it. Selection is an attention/allocation decision, not an epistemic certification.

### 4. Specialist processors

Initial specialist roles:
- evidence and provenance auditor;
- causal analyst;
- hypothesis generator;
- Analysis of Competing Hypotheses (ACH) auditor focused on diagnostic contradictions and source dependence;
- adversarial reviewer / red team;
- temporal and spatial analyst;
- social-interaction analyst (strictly bounded to observable behaviour and contextual alternatives);
- planner and counterfactual simulator;
- memory retriever and consolidator;
- metacognitive evaluator;
- safety and authorisation guard.

Specialists may disagree. Their outputs remain inspectable and linked to the evidence and method used. The ACH auditor orders hypotheses by a contradiction-focused triage score; it does not produce probabilities or automatically select a true explanation.

### 5. World and self models

The world model represents entities, events, locations, temporal intervals, relations, source reliability, and known unknowns.

The self model represents operational state rather than human-like feelings:
- current goals and commitments;
- known capabilities and limitations;
- tools and permissions available;
- uncertainty about its own output quality;
- past predictions and observed outcomes;
- unresolved errors and model drift.

The system must not invent autobiographical memories or present generated narrative as lived experience.

### 6. Metacognitive controller

Before presenting a high-impact conclusion, the controller asks:
- Which claims are directly observed?
- Which claims are inferred?
- What evidence would falsify the leading explanation?
- Are sources independent or merely repetitions of one source?
- What information is missing?
- Are uncertainty and confidence calibrated on comparable tasks?
- Did a specialist or model overstate its competence?
- Should the system abstain or ask for another observation?

Confidence is task-specific and measured against outcomes. Fluent language is not a confidence signal.

## Memory systems and lifecycle

| Memory class | Purpose | Example |
|---|---|---|
| Working | Current task state | Current question and active candidates |
| Episodic | What happened in a specific investigation/session | Reviewed event timeline |
| Semantic | Generalised knowledge with source provenance | A verified definition or relation |
| Procedural | How to perform a validated operation | Video indexing procedure |
| Prospective | Future commitments and pending work | Revisit a question when new footage arrives |
| Self/performance | System capability, error and calibration history | Known failure on low-light footage |

Memory operations:
1. **Encode:** preserve source-linked material and context.
2. **Index:** make it retrievable by time, entity, concept, modality, and investigation.
3. **Retrieve:** return both content and provenance; expose retrieval uncertainty.
4. **Consolidate:** derive stable semantic summaries without deleting original episodes.
5. **Reconsolidate:** create a new version when verified evidence changes an interpretation.
6. **Decay/archive:** reduce retrieval priority for stale or low-value data without silently deleting audit-critical records.
7. **Forget/delete:** execute owner-directed deletion across primary storage, indexes, caches, and backups according to a documented retention process.

A generated summary must never replace its source evidence. Old interpretations remain versioned and auditable.

## Strategic cognition

Strategic capability is modelled as explicit operations:
- infer another actor's possible goals without treating them as known;
- generate multiple opponent models;
- identify information asymmetry and decision constraints;
- simulate plausible responses and second-order effects;
- detect deception indicators as hypotheses, not conclusions;
- design lawful, non-coercive tests that discriminate between explanations;
- evaluate reversibility, downside risk, and evidence contamination.

The system may learn to recognise manipulation and reason adversarially. It must not autonomously coerce, blackmail, impersonate, exploit vulnerabilities, fabricate evidence, or manipulate vulnerable people.

## Decision cycle and stopping

The system continues investigating while the expected value of another operation exceeds its cost and risk. It stops or asks the owner when:
- evidence is insufficient;
- remaining hypotheses are observationally indistinguishable;
- required data is unavailable or unlawful to obtain;
- the next operation exceeds granted permissions;
- a consequential action needs owner approval;
- uncertainty cannot be responsibly reduced.

## Implementation sequence

1. Typed evidence and hypothesis objects.
2. Append-only provenance ledger.
3. Explicit cognitive-cycle state machine.
4. Working/episodic memory interfaces.
5. Retrieval and consolidation evaluations.
6. Specialist processor contracts.
7. Multimodal adapters.
8. Metacognitive calibration and longitudinal learning.
9. Runtime and owner-security integration.
