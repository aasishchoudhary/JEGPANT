# Product charter

## Product definition

JEGPANT is a single-owner, persistent cognitive system. It is intended to maintain a coherent internal state across tasks and sessions, reason over evidence from multiple modalities, investigate questions over time, and explain how its conclusions were produced.

“Mind” is a product metaphor for an engineered cognitive architecture. It is not a claim that the software is conscious, sentient, emotionally aware, or equivalent to a human mind.

## Primary user and authority

- There is one owner principal.
- The owner may enrol a limited number of explicitly authorised devices.
- There are no public accounts, guest users, shared workspaces, or multi-tenant memory domains.
- A model provider, hosting vendor, developer, or infrastructure administrator is not the owner.
- Owner instructions govern the system, subject to law and the safety constraints defined here.

## Core capabilities sought

1. **Persistent cognitive state:** active goals, working context, episodic records, semantic knowledge, procedural skills, unresolved questions, and a versioned self/world model.
2. **Evidence-grounded investigation:** source acquisition, observation extraction, temporal/spatial indexing, provenance, competing hypotheses, disconfirmation, and calibrated reporting.
3. **Multimodal perception:** recorded video, images, audio, text, structured data, and later sensor inputs.
4. **Strategic planning:** generate options, anticipate reactions and consequences, compare plans, detect adversarial assumptions, and maintain contingency branches.
5. **Metacognition:** estimate uncertainty, detect unsupported leaps, critique its own analysis, measure calibration, and learn from verified outcomes.
6. **Longitudinal continuity:** retain the same cognitive instance when the app, device, backend, or underlying model changes.
7. **Private operation:** keep the owner's data and cognitive memory inside a dedicated owner-controlled security boundary.

## Core operational loop

The intended cycle is not a single prompt-response call:

1. **Orient:** identify the owner's goal, active context, constraints, and what is not known.
2. **Perceive:** ingest sources and extract candidate observations while preserving source coordinates and timing.
3. **Represent:** map observations into entities, events, relations, temporal intervals, and confidence/quality metadata.
4. **Retrieve:** recall relevant episodic, semantic, procedural, and active-goal memory with provenance.
5. **Generate:** construct multiple explanations and plans, not just the first plausible answer.
6. **Challenge:** search for disconfirming evidence, alternative causes, missing data, and adversarial interpretations.
7. **Decide:** select the next information-gathering or reasoning operation by expected usefulness, cost, risk, and reversibility.
8. **Synthesize:** produce a grounded assessment with citations to evidence, uncertainty, and unresolved questions.
9. **Reflect:** compare prediction with later outcome; update models only when the result is sufficiently verified.
10. **Consolidate:** propose durable memory updates; the owner controls sensitive or consequential promotion.

## Patrick Jane and the wider research roster

Patrick Jane is a research source, not the complete architecture. His observation, performance, strategic misdirection, hypothesis testing, provocation, and adversarial thinking are to be studied as mechanisms. Fictional plots are not empirical proof. Manipulation, coercion, illegal conduct, fabricated evidence, and exploitation are not implementation goals.

The research roster is a candidate source catalogue. It must be revised when evidence shows that a supposed capability is fictional, overstated, poorly validated, or unsuitable.

## Non-goals

- A public assistant or multi-user SaaS.
- A system that declares guilt, deception, diagnosis, or intent from appearance alone.
- Covert surveillance, stalking, unlawful access, or automated targeting.
- An autonomous actor that can make irreversible external decisions without owner approval.
- A simulated personality that merely imitates character dialogue.
- Claims of human-level general intelligence or consciousness.

## Acceptance criteria for a meaningful cognitive system

A feature is not complete because it produces fluent prose. It must demonstrate:
- repeatable behaviour on a defined task set;
- provenance from inputs to claims;
- explicit uncertainty and alternative hypotheses;
- robustness to misleading, missing, and contradictory data;
- measurable improvement over a baseline;
- graceful abstention when evidence is insufficient;
- persistence and recovery without identity or memory drift;
- privacy and security controls that pass independent tests.
