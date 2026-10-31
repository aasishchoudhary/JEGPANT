# Analysis of Competing Hypotheses (ACH)

## Purpose

The ACH component gives JEGPANT a structured way to compare explanations without choosing the first plausible narrative. It is inspired by Richards Heuer's intelligence-analysis method and the broader requirement to test explanations against evidence that could disconfirm them.

Primary starting point:
- Richards J. Heuer Jr., *Psychology of Intelligence Analysis*, CIA Center for the Study of Intelligence (1999): https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/

## Data model

Each investigation supplies:
- multiple explicit hypotheses;
- a set of evidence records;
- an independence group for each evidence record;
- a quality level (1–3) and a diagnosticity rating (1–3);
- a judgement for each hypothesis/evidence pair.

Judgements use these categories:
- strongly inconsistent;
- inconsistent;
- neutral;
- consistent;
- strongly consistent;
- not applicable;
- unassessed.

A judgement must include rationale at the call site in serious investigations. Model-generated judgements are proposals until checked against the underlying source.

## Contradiction score

The implementation gives contradiction values:
- inconsistent = 1;
- strongly inconsistent = 2.

For each contradictory evidence item, the contribution is:

```text
severity × diagnosticity × source_quality
```

Within one source-independence group, only the strongest contradiction contributes to the score. This is intended to reduce double-counting when several reports derive from the same underlying observation.

Consistent evidence is retained in the matrix but does not cancel contradictions. The result is ordered by ascending contradiction score only as an analyst triage aid. It does not identify a winner.

## What the score does not mean

The score is:
- not a probability;
- not a confidence estimate;
- not a measure of guilt or deception;
- not a substitute for evidence quality review;
- not valid when source-independence groups are incorrectly assigned;
- not an objective measure if diagnosticity and source quality are subjective.

The output deliberately preserves raw evidence IDs, contradictions, supporting/consistent evidence, neutral evidence, and unassessed items so that an analyst can inspect the underlying judgements.

## Safeguards

- Unknown hypothesis or evidence IDs are rejected.
- Duplicate hypothesis/evidence judgements are rejected.
- Duplicate IDs are rejected.
- Unassessed evidence remains visible.
- Multiple reports from one source group do not receive full independent weight.
- No automatic accusation, diagnosis, or external action is generated.

## Evaluation plan

Build benchmark case packets with known ground truth and independent expert labels. Measure:
- completeness of hypothesis set;
- diagnostic-evidence identification;
- contradiction detection recall;
- source-dependence recognition;
- agreement with expert judgements;
- sensitivity to missing or misleading evidence;
- rate of unjustified certainty;
- whether adding irrelevant duplicated reports changes the ordering.

Run ablations:
1. raw evidence count;
2. simple support/contradiction count;
3. ACH contradiction-only triage;
4. ACH with source grouping;
5. ACH with explicit evidence-quality and diagnosticity judgements.

A method is retained only if it improves relevant outcomes over baselines without increasing unsupported conclusions.
