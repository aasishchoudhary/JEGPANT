# Post-hoc video evidence pipeline

## Operating assumption

The owner uploads a recorded video. JEGPANT performs asynchronous analysis and may take substantial time. Live camera streaming is not a requirement for the initial product.

Video analysis is an evidence acquisition and organisation process. It is not a reliable lie detector, guilt detector, or direct window into a person's private mental state.

## Current implementation boundary

The repository now includes `probe_local_video()` in `src/jegpant/media_intake.py`. It:
- accepts an existing regular file and rejects symbolic-link paths;
- enforces a configurable source-file size limit;
- computes a SHA-256 digest in chunks;
- invokes `ffprobe` using an argument array, never shell interpolation;
- disables network protocols with `-protocol_whitelist file`;
- applies an FFmpeg allocation cap and a timeout;
- limits the returned metadata size;
- avoids exposing probe stderr, which may contain private paths;
- detects common source-file changes during inspection;
- validates codec, dimensions, duration, frame rate and audio-stream presence.

The intake primitive does **not** decode frames, extract audio, detect people, track objects, or analyse behaviour. It is a first gate, not a complete video-analysis pipeline. Production must run media parsers in a sandboxed, unprivileged worker with restricted filesystem access and no network egress; command-line restrictions alone are not a sandbox.

## Pipeline

### 1. Secure intake
- Validate file type by content, not filename alone.
- Record cryptographic hash, byte size, duration, codec, frame rate, dimensions, audio streams, and source metadata.
- Keep the original immutable.
- Assign an asset ID and investigation/case ID.
- Encrypt and store inside the private media boundary.

**Implemented:** source hashing, size checks, basic ffprobe metadata, no-shell execution, network-protocol restriction, bounded timeout/output and source-change checks.  
**Not yet implemented:** immutable encrypted media vault, production sandbox, upload API, malware scanning, full container validation and owner-device upload workflow.

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

The current timeline primitive stores event time intervals, track IDs, extractor version and limitations. Its optional extraction-confidence field is an extractor score, not a probability that the event interpretation is true.

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
