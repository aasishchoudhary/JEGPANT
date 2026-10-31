# Single-owner security model

## Meaning of “only the owner can use it”

The requirement is implemented as an exclusive owner principal and an explicit device allowlist—not merely a hidden URL, app login, or device fingerprint.

- One immutable cognitive-instance identifier.
- One owner public-key identity.
- A small, owner-authorised set of devices.
- No registration, invitations, guests, tenants, shared accounts, or public API access.
- Every protected request is authenticated and authorised.
- Device revocation invalidates access at the authorization service.
- The system does not expose memory to a model provider or operator by default.

## Implemented prototype: Ed25519 owner/device verification

`src/jegpant/owner_auth.py` now implements the first cryptographic protocol primitives:

### Device enrolment

An enrolment request binds:
- the cognitive instance UUID;
- device UUID and raw Ed25519 public key;
- an allowlisted set of scopes;
- a unique enrolment ID;
- issue and expiry times.

The owner signs the canonical enrolment payload. The device also signs the same payload to prove possession of the corresponding private key. The runtime stores only the public key, scopes and enrolment metadata.

### Per-request authentication

Each signed request binds:
- instance ID and enrolled device ID;
- a unique UUID request ID;
- uppercase HTTP method and request path;
- issue and expiry timestamps;
- SHA-256 digest of the exact request body;
- Ed25519 device signature.

The verifier checks the instance, device status, scope, time window, body digest and signature, then atomically checks active-device status and scope while consuming the request ID. The default in-memory store is for tests only. The `SQLiteOwnerStateStore` uses `BEGIN IMMEDIATE` transactions and unique constraints so two service instances on the same host cannot accept the same request ID concurrently. It also persists enrolments, revocations and owner-approval IDs across process restarts.

### Owner-signed device revocation

The owner signs a short-lived revocation payload. The verifier records the device as revoked and denies subsequent requests.

### Owner-signed memory approval

`Ed25519ApprovalVerifier` implements the `ApprovalVerifier` interface used by the memory catalog. The owner signature binds an approval to the instance, proposal, approval ID, key ID and expiry. When backed by `SQLiteOwnerStateStore`, approval IDs are consumed once across restarts and workers. The device authorization service and approval verifier must share the same state store (or the same SQLite database path); `MemoryPromotionService` rejects separate process-local stores.

### Important implementation boundary

These are **tested protocol primitives, not a production authentication service**.

Current limitations:
- `InMemoryOwnerStateStore` remains the default when no store is supplied and is suitable only for tests/development. Production must explicitly inject `SQLiteOwnerStateStore` into both owner and device authorization components.
- `SQLiteOwnerStateStore` is a single-host, local-filesystem prototype. Do not place it on an arbitrary network share or use it as a multi-region database. A horizontally scaled deployment needs a strongly consistent transactional store with equivalent uniqueness and atomic authorization semantics.
- Expired request/approval rows currently accumulate; a retention and compaction job is still required. Do not delete replay records before their signed request/approval expiry.
- The code has no HTTP API, session/token lifecycle, TLS termination, rate limiting, intrusion detection, security-event audit pipeline or production deployment.
- There is no Android Keystore/StrongBox key-generation adapter, attestation workflow, device UI, backup/recovery protocol or key-rotation ceremony.
- Ed25519 support is implemented in the Python verifier. Android hardware-backed support depends on the platform/provider and must be verified; do not assume a device can generate or use this key type in hardware.
- Request paths are signed as supplied. A production gateway must define a single canonical request-target representation and ensure routing layers do not normalise a signed path into a different resource.
- The request body is authenticated by digest, but headers, content type, host and transport metadata are not all included in the signed message. Production protocol versioning must specify all security-relevant fields.
- SQLite transactions provide same-host cross-process arbitration for the configured database. They do not provide multi-region consistency or protect against rollback to an older database snapshot.
- Clock synchronisation and rollback handling require operational controls.
- This implementation has not had an independent cryptographic or penetration-test review.

## Key hierarchy (target design)

Use separate cryptographic purposes and rotate keys independently:

1. **Owner signing key:** signs enrolment, recovery, and high-authority owner commands.
2. **Device key:** generated on each device; proves possession for device authentication.
3. **Instance root key:** derived or unwrapped only through an owner-controlled recovery process; not stored in plaintext on the server.
4. **Data-encryption keys:** envelope-encrypt media, memory, and evidence stores; rotate by key version.
5. **Service credentials:** authenticate service-to-service calls; never double as owner identity or data-encryption keys.

Do not write custom cryptography. Use reviewed platform and cryptographic libraries, with independent security review before production.

## Device enrolment flow

1. First-run setup creates the owner identity and instance identifier.
2. The owner verifies and records recovery material offline.
3. The first device generates a non-exportable key when the platform supports it.
4. A device challenge is signed and bound to the instance ID, device public key, expiry, and requested permissions.
5. The owner signs the enrolment authorisation.
6. The service registers the device public key and issues narrowly scoped, short-lived sessions.
7. Later devices require a signed enrolment from an already trusted owner/recovery path.

Biometric unlock may gate local key use, but biometrics are not the cryptographic identity itself. Hardware-backed key storage and StrongBox availability vary by device and must be checked at runtime. Passkeys may sync between devices depending on provider configuration; they should not be assumed to mean “one physical device only.”

## Request authorisation

The current verifier checks Ed25519 signatures, instance/device binding, short TTL, UUID replay IDs, body digest and scopes. A production service must additionally define canonical HTTP request signing, transport security, request-size limits, rate limiting, durable replay storage, audit events, session revocation and key rollover.

This follows the resource-focused, no-implicit-trust model in NIST SP 800-207: https://csrc.nist.gov/pubs/sp/800/207/final

## Server and operator access

“Admin cannot read memory” must be achieved technically. Ordinary disk encryption is insufficient if the application server can decrypt data during processing.

Candidate controls, in increasing complexity:
- owner-held envelope-encryption keys with no server export;
- split administrative duties and audited privileged operations;
- local inference for the most sensitive tasks;
- confidential-computing execution with remotely attested workloads and a carefully designed key-release policy.

Confidential computing is not automatically end-to-end encryption. It requires a threat model, supported hardware, measured boot/attestation, key policy, and independent validation.

## Recovery and migration

- Recovery material belongs to the owner and is stored separately from the phone.
- Recovery must rotate/revoke old device keys and invalidate sessions.
- Server migration must re-encrypt or re-wrap data without revealing the owner root key to infrastructure staff.
- Model migration preserves the instance identity and versioned memory.
- If recovery material is lost, the system must clearly state which data is unrecoverable; no hidden vendor bypass.

## Minimum acceptance tests

- unknown device denied;
- invalid owner or device signature denied;
- invalid request body digest denied;
- replayed request denied, including concurrent duplicate attempts in one process;
- expired/overlong request denied;
- revoked device denied;
- wrong instance ID denied;
- unsupported scope denied;
- owner approval replay denied;
- copied database unreadable without required keys;
- backups restore only with owner recovery;
- model output cannot grant itself permissions;
- destructive memory action requires explicit owner authorisation;
- replay/revocation state survives server restart and concurrent multi-worker access.
