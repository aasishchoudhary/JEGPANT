# Security and privacy policy

## Public development repository

JEGPANT is public while its source is being developed. Assume all committed material can be copied indefinitely. A later visibility change cannot retract clones, forks, cached copies, screenshots, or package artifacts.

**Never commit:**
- API keys, passwords, access tokens, private certificates, signing keys, encryption keys, recovery phrases, or database credentials.
- Owner identity material, device identifiers, private logs, memory exports, prompts containing personal data, or private case notes.
- Original videos, images, audio, transcripts, precise location trails, or biometric data.
- Production configuration, cloud account identifiers, private endpoints, or backups.

The ignore rules are defence-in-depth, not a guarantee. Review `git status` and staged diffs before every push.

## Threat model (initial)

Protect against:
- Unauthenticated internet users and opportunistic scanners.
- A lost or stolen enrolled phone.
- Session theft, replay, and revoked devices.
- Accidental exposure through logs, backups, crash reports, analytics, or model-provider calls.
- A compromised dependency or supply-chain update.
- A curious infrastructure operator who should not automatically receive plaintext access to private memory.
- Evidence alteration or accidental loss of provenance.

The design does not currently claim resistance to a fully compromised owner device, malicious OS/kernel, coercion, or all hardware/side-channel attacks.

## Security design rules

1. Deny by default; authenticate each device and authorize each protected operation.
2. Keep owner identity keys, memory-encryption keys, and service credentials separate.
3. Use platform-backed key storage where available, verify hardware properties at runtime, and provide a reviewed recovery design.
4. Do not treat biometrics, a passkey, a device ID, or a long-lived bearer token as the entire owner identity.
5. Encrypt sensitive data in transit and at rest; document that ordinary server-side encryption does not hide plaintext from a process while it is computing on that data.
6. Keep private inference local or within the dedicated trusted compute boundary by default. External model calls require an explicit data-flow decision.
7. Never let model-generated text directly authorize external actions, modify security policy, or permanently promote memory.
8. Keep append-only evidence provenance and integrity checks; a hash chain detects certain modifications but is not a substitute for access control, signatures, trusted timestamps, or secure backups.
9. Log security events without logging sensitive content.
10. Provide owner-controlled device revocation, export, backup, and destruction procedures.

## Reporting

Do not publish a vulnerability containing exploitable details in a public issue. Use GitHub's private vulnerability reporting if enabled for this repository, or contact the repository owner through a verified private channel. Do not include sensitive video or personal data in a report.
