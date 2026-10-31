# Post-hoc video evidence pipeline

## Operating assumption

The owner uploads a recorded video. JEGPANT performs asynchronous analysis and may take substantial time. Live camera streaming is not a requirement for the initial product.

Video analysis is an evidence acquisition and organisation process. It is not a reliable lie detector, guilt detector, or direct window into a person's private mental state.

## Pipeline

### 1. Secure intake
- Validate file type by content, not filename alone.
- Record cryptographic hash, byte size, duration, codec, frame rate, dimensions, audio streams, and source metadata.
- Keep the original immutable.
- Assign an asset ID and investigation/case ID.
- Encrypt and store inside the private media boundary.

### 2. Timeline normalisation
- Use media timestamps and presentation timestamps, not assumed frame-number arithmetic alone.
- Detect variable frame rate, timestamp discontinuities, missing audio, rotation, and clock offsets.
- Preserve original timestamps and all transformations.
- Never claim temporal precision finer than the source permits.

### 3. Coarse indexing
- Detect shot/scene boundaries.
- Build a coarse visual/audio index.
- Generate low-resolution thumbnails and audio segments only as derived assets.
- Store model/tool version and parameters.

### 4. Query-directed reinspection
- The question determines which periods need closer review.
- Retrieve candidate intervals, then inspect denser frame sequences or original clips.
- Adaptive sampling must not silently omit brief events; the report states sampling limits.
- Keep a route back from each claim to exact timestamps and source regions.

### 5. Specialist extraction
Possible extractors include:
- object and person detection;
- multi-object tracking;
- pose/keypoint estimation;
- OCR and speech transcription;
- sound-event detection;
- scene and interaction segmentation.

Every extractor records confidence, known failure modes, version, and input timestamps. A track ID is an algorithmic association, not a verified real-world identity.

### 6. Event representation
Represent events with:
- subject/object track IDs (not real identities by default);
- action or interaction label;
- start/end timestamps;
- spatial region or bounding box;
- source segment and derived asset references;
- direct observation text;
- extractor provenance and uncertainty;
- reviewer status.

### 7. Investigative reasoning
- Generate several plausible explanations.
- Separate direct observations from interpretations.
- Look for confirming and disconfirming intervals.
- Compare alternative explanations and mundane causes.
- Preserve contradictory observations.
- Identify what additional footage, metadata, or witness information would discriminate between hypotheses.

### 8. Owner-facing report
Every material claim must include:
- timestamp(s) and source clip;
- whether it is a direct observation or inference;
- method/model used;
- uncertainty and known limitations;
- alternatives and contrary evidence;
- unresolved questions.

## Behavioural and psychological limits

Video may support statements about visible actions and interaction patterns, with context and uncertainty. It does not by itself establish honesty, deception, criminal intent, diagnosis, character, motive, or stable personality. Facial expression, gaze, posture, fidgeting, pauses, and vocal characteristics are not standalone proof of a hidden mental state.

The system should say “the person looked toward the exit at 00:02:14” rather than “the person wanted to escape,” unless the latter is explicitly framed as one hypothesis among alternatives and supported by additional independent evidence.

## Evaluation

Measure:
- event detection precision/recall by event class;
- tracking identity switches and fragmentation;
- timestamp localisation error;
- OCR/ASR word error under noise and accents;
- evidence-groundedness of generated claims;
- rate of unsupported claims;
- false certainty under occlusion, low light, camera motion, and compression;
- ability to find counterevidence;
- reviewer agreement and correction rate.

Long-video research indicates that answers can be plausible yet misaligned with the evidence actually inspected. JEGPANT therefore requires explicit temporal/semantic grounding and evidence-linked claims:
- VideoSEAL, ICML 2026: https://proceedings.mlr.press/v306/qiu26v.html
- Open-o3-Video, ICML 2026: https://proceedings.mlr.press/v306/meng26e.html
- MMR-V, ICLR 2026: https://proceedings.iclr.cc/paper_files/paper/2026/hash/6f1989abe9562c5cd306e070725fe0a3-Abstract-Conference.html
