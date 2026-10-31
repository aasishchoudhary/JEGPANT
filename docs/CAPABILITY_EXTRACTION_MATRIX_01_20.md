# Capability extraction matrix: ranks 1–20

## Purpose

This is the first research tranche for the 100-mind roster. It is a **source triage and capability translation plan**, not a claim that every candidate has scientifically established superiority. Each entry must be decomposed into implementable operations, checked against primary material, and tested against a baseline.

### Evidence classes

- **A — primary/authoritative source:** original work, formal publication, institutional archive, or authoritative technical text.
- **B — scholarly synthesis:** peer-reviewed or scholarly interpretation of primary work.
- **F — fiction:** primary narrative work can establish what the character is depicted doing, but cannot establish real-world effectiveness.
- **P — practitioner method:** a documented professional method; usefulness must still be independently evaluated.

## Candidate analysis

| Rank | Candidate | Source class | Mechanism worth extracting | What must not be assumed | Proposed JEGPANT test |
|---:|---|---|---|---|---|
| 1 | Sherlock Holmes [F] | F | Observation/inference separation; abductive hypothesis generation; prediction of discriminating details | A fictional detective's correct solution rate is not empirical evidence; narrative author controls clues | Give the system incomplete case packets with decoys; measure alternative hypotheses, evidence attribution, and falsification questions |
| 2 | Alan Turing [R] | A | Formalise vague questions; operational definitions; distinguish observable test criteria from metaphysical claims | The 1950 imitation-game paper is not a complete architecture for general intelligence | Require the system to turn ambiguous questions into operational tests and identify what a test can/cannot establish |
| 3 | John von Neumann [R] | A | Formal strategic interaction, payoff representation, minimax reasoning in bounded games | Mathematical game-theoretic optimality does not imply accurate human opponent psychology or real-world predictability | Run small adversarial games with known payoff structures; compare decisions to minimax baseline and track model assumptions |
| 4 | Sun Tzu [R / historical attribution] | A/B | Indirect strategy, information asymmetry, deception recognition, adaptation to constraints | Authorship, historical context, translation, and modern applicability require critical treatment; maxims are not validated algorithms | Translate a selected principle into a falsifiable planning heuristic; compare against a neutral baseline in simulated tasks |
| 5 | Judea Pearl [R] | A | Causal graphs, interventions, counterfactual reasoning, confounding analysis | Correlation or temporal order alone does not identify cause; a causal graph depends on assumptions | On synthetic causal benchmarks, test intervention queries and counterfactuals with known ground truth |
| 6 | Spock [F] | F | Explicit premises, consistency checking, controlled separation of observation and value judgement | Fictional emotional detachment is not a scientifically optimal general decision strategy | Test logical consistency and constraint satisfaction while comparing performance with uncertainty-aware human-value handling |
| 7 | Batman / Bruce Wayne [F] | F | Evidence fusion, preparation, contingency planning, forensic workflow | "Preparation" and access to unlimited resources are narrative devices; detective feats are often impossible or legally problematic | Constrained-resource planning tasks; measure contingency coverage, provenance and legal/ethical compliance |
| 8 | Charles Darwin [R] | A | Patient accumulation of observations, comparison of competing explanations, delayed commitment | Historical method should not be reduced to a simplistic "observe then discover" story; evaluate actual notebooks and correspondence | Longitudinal benchmark where evidence arrives in batches; measure premature commitment and revision quality |
| 9 | Claude Shannon [R] | A | Information theory, channel noise, compression, signal/noise reasoning | Entropy is not semantic meaning; information-theoretic measures do not themselves understand context | Test information loss in summaries and retrieval under controlled noise, measuring task-relevant information preservation |
| 10 | Hari Seldon [F] | F | Scenario analysis and aggregate forecasting as a thought experiment | Psychohistory is fictional; social systems are reflexive and predictions can change behaviour | Use only as a forecasting stress-test: require assumptions, uncertainty intervals, sensitivity and feedback effects |
| 11 | Daniel Kahneman [R] | A/B | Bias detection, heuristics, base-rate neglect, anchoring and confidence review | A list of biases is not a universal debiasing algorithm; findings vary by task and context | Construct paired tasks with misleading anchors/base rates; measure whether the system detects and corrects bias |
| 12 | Columbo [F] | F | Low-pressure information gathering, discrepancy tracking, iterative questioning | Fictional questioning sequences are not a validated interrogation protocol; avoid coercion and false confession risks | Benign role-play with scripted facts; measure question efficiency, consistency tracking and respect for consent |
| 13 | Herbert Simon [R] | A | Bounded rationality, satisficing, decomposition, allocation of work among specialists | Bounded rationality does not mean arbitrary heuristics; thresholds depend on resources and task | Resource-constrained planning benchmark; measure solution quality against cost/time budgets and optimal small-instance baselines |
| 14 | L (Death Note) [F] | F | Adversarial hypothesis testing and strategic test selection | A scripted adversary with plot-specific information is not a real intelligence benchmark | Red-team puzzles with hidden information and fair scoring; measure calibration and resistance to overfitting |
| 15 | Ibn al-Haytham [R] | A/B | Experimental design, criticism of premises, caution in drawing conclusions, mathematical/empirical cross-checks | Historical claims about the "scientific method" can be oversimplified; use historical scholarship and primary works | Require a test plan that discriminates hypotheses, exposes confounds and records failed trials |
| 16 | Mycroft Holmes [F] | F | Knowledge integration across institutions and large information collections | Omniscient information access is a narrative convenience; information quantity is not truth | Multi-source synthesis task with stale, duplicated and contradictory records; evaluate source provenance and uncertainty |
| 17 | Richards Heuer [R] | P/A | Structured analytic techniques, especially Analysis of Competing Hypotheses and cognitive-bias awareness | A professional tradecraft method is not automatically a validated cognitive intervention; measure its effect | Blind analysts/system runs with and without ACH; measure hypothesis coverage, diagnostic evidence and hindsight bias |
| 18 | Leonardo da Vinci [R] | A/B | Visual observation, cross-domain analogy, sketching as external cognition, iterative inquiry | Genius narratives often mythologise the notebooks; attribution and historical context matter | Test visual-to-symbolic representation and cross-domain transfer on tasks with known solutions |
| 19 | Hercule Poirot [F] | F | Motive hypotheses, timeline consistency, structured evidence review | "Reading psychology" cannot establish guilt or motive; narrative solutions compress uncertainty | Mystery benchmark with explicit clue trail; score evidence-supported explanation, alternatives and unsupported inference rate |
| 20 | Charles Sanders Peirce [R] | A/B | Abduction generates explanations; deduction derives consequences; induction tests them | Abduction is not proof and is not always "the best explanation"; it generates provisional hypotheses | Enforce a three-stage cycle; measure whether generated hypotheses lead to testable predictions and are revised after evidence |

## Primary and authoritative starting sources

1. **Turing:** A. M. Turing, “Computing Machinery and Intelligence,” *Mind* (1950), https://doi.org/10.1093/mind/LIX.236.433 ; original archive record: https://turingarchive.kings.cam.ac.uk/publications-lectures-and-talks-amtb/amt-b-9
2. **von Neumann and game theory:** John von Neumann and Oskar Morgenstern, *Theory of Games and Economic Behavior* (1944); historical/technical grounding is required before translating any result to social behaviour.
3. **Sun Tzu:** *The Art of War*; compare multiple translations and historical scholarship. Treat strategic maxims as hypotheses, not scientific laws.
4. **Pearl:** UCLA faculty bibliography and causal reasoning publications, https://samueli.ucla.edu/people/judea-pearl/ and https://bayes.cs.ucla.edu/BOOK-2K/
5. **Darwin:** first edition of *On the Origin of Species* (1859), Darwin Online, https://darwin-online.org.uk/content/contentblock?basepage=1&itemID=F373&viewtype=text
6. **Kahneman and Tversky:** “Judgment under Uncertainty: Heuristics and Biases,” *Science* (1974), https://doi.org/10.1126/science.185.4157.1124
7. **Shannon:** “A Mathematical Theory of Communication,” *Bell System Technical Journal* (1948), https://doi.org/10.1002/j.1538-7305.1948.tb01338.x
8. **Simon:** Nobel Prize lecture, “Rational Decision-Making in Business Organizations” (1978), https://www.nobelprize.org/prizes/economic-sciences/1978/simon/lecture/
9. **Ibn al-Haytham:** UNESCO historical overview, https://courier.unesco.org/en/articles/ibn-al-haythams-scientific-method ; MacTutor history of mathematics biography, https://mathshistory.st-andrews.ac.uk/Biographies/Al-Haytham/
10. **Heuer:** CIA Center for the Study of Intelligence, *Psychology of Intelligence Analysis* (1999), https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/
11. **Peirce:** Stanford Encyclopedia of Philosophy, “Charles Sanders Peirce,” section on deduction, induction and abduction, https://plato.stanford.edu/entries/peirce/

## Immediate engineering translation

The first five reusable capabilities to prototype should be:

1. **Abductive hypothesis generator:** propose multiple explanations and mark them provisional.
2. **Causal model builder:** distinguish observations, confounders, interventions and counterfactuals.
3. **Competing-hypotheses auditor:** inspect each hypothesis against all diagnostic evidence, including evidence that contradicts it.
4. **Information-seeking planner:** choose the next observation/test that best distinguishes alternatives under cost and risk constraints.
5. **Metacognitive calibration:** score forecasts only after explicit, independently verifiable resolution.

Every capability must be implemented as a versioned specialist with a benchmark and regression tests. The roster is not allowed to turn into a collection of personas that merely imitate character dialogue.
