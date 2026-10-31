# Research and evaluation programme

## Evidence hierarchy

JEGPANT must distinguish:
1. peer-reviewed empirical findings and benchmark results;
2. replicated or independently validated methods;
3. technical standards and authoritative engineering documentation;
4. expert practitioner methods with transparent limitations;
5. historical accounts and biographies;
6. fictional character portrayals;
7. unsupported claims, anecdotes, or marketing.

A source's reputation does not automatically validate every method attributed to it. Fictional characters are useful for generating design hypotheses, not empirical evidence that a technique works.

## Research record schema

Every proposed capability should have:
- capability ID and plain-language definition;
- source person/character or scientific literature;
- primary source(s) and secondary source(s);
- evidence class and confidence in attribution;
- mechanism, not just a personality adjective;
- prerequisites and operating conditions;
- failure modes and known biases;
- ethical/legal constraints;
- proposed implementation;
- measurable task and baseline;
- pass/fail criteria;
- status: proposed, researched, prototyped, evaluated, accepted, rejected.

## Capability extraction method

1. Identify a concrete behaviour or reasoning operation.
2. Trace it to primary sources, empirical research, or canonical examples.
3. Decompose it into input, internal representation, transformation, decision, and output.
4. Determine whether the operation is computationally implementable.
5. Identify where fictional depiction exaggerates real capability.
6. Build a narrow benchmark.
7. Compare against a baseline and ablation.
8. Accept only if measurable gains generalise beyond the example that inspired it.

## Evaluation suites

### Epistemic integrity
- evidence citation coverage;
- unsupported-claim rate;
- contradiction detection;
- alternative-hypothesis coverage;
- source independence detection;
- uncertainty calibration;
- abstention quality.

### Cognitive continuity
- memory retrieval precision/recall;
- episodic-to-semantic consolidation accuracy;
- memory provenance retention;
- identity continuity across model upgrades;
- correction propagation and rollback;
- stale-memory handling.

### Strategy and planning
- plan success under partial observability;
- robustness to opponent adaptation;
- second-order consequence detection;
- reversibility and risk awareness;
- performance under adversarially misleading information.

### Video intelligence
- temporal localisation;
- object tracking quality;
- event reconstruction;
- multimodal alignment;
- evidence-groundedness;
- counterevidence retrieval;
- robustness to camera, lighting, occlusion, and compression.

### Security and privacy
- authentication and authorisation tests;
- replay and revocation;
- key separation and recovery;
- data-flow verification;
- secret scanning;
- dependency and build provenance;
- backup/restore and deletion validation.

## Research caveats

Predictive processing and active inference are promising theoretical frameworks, but their empirical status and explanatory scope remain actively debated. They should not be treated as proven universal algorithms for cognition. See Hodson, Mehta & Smith (2024): https://pubmed.ncbi.nlm.nih.gov/38030100/

Soar provides an explicit computational decision cycle with working-memory state and impasse-driven subgoals; it is a source of implementable architectural ideas, not evidence that all human cognition follows this model: https://soar.eecs.umich.edu/soar_manual/02_TheSoarArchitecture/

LIDA's global-workspace-inspired cognitive model is a research architecture with a published tutorial; its proposed cognitive mechanisms should be evaluated individually: https://doi.org/10.1016/j.bica.2016.04.003

## Security standards to map against

- NIST SP 800-207, Zero Trust Architecture: https://csrc.nist.gov/pubs/sp/800/207/final
- OWASP ASVS 5.0.0: https://asvs.owasp.org/
- OWASP MASVS: https://mas.owasp.org/
- Android Keystore system: https://developer.android.com/privacy-and-security/keystore

These references guide requirements; citing a standard does not mean JEGPANT is compliant. Compliance requires a mapped control set, implementation evidence, and testing.

## Release gates

No release is production-ready until:
- security architecture is independently reviewed;
- privacy/data-flow inventory is complete;
- tests pass on supported devices and server environments;
- owner recovery and revocation are tested;
- model outputs are bounded by typed schemas and policy checks;
- benchmark results and known failure modes are published;
- the system can abstain when evidence is insufficient.
