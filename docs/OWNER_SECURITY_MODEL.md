# Single-owner security model

## Meaning of “only the owner can use it”

The requirement is implemented as an exclusive owner principal and an explicit device allowlist—not merely a hidden URL, app login, or device fingerprint.

- One immutable cognitive-instance identifier.
- One owner public-key identity.
- A small, owner-authorised set of devices.
- No registration, invitations, guests, tenants, shared accounts, or public API access.
- Every protected request is authenticated and authorised.
- Device revocation invalidates access and affected sessions.
- The system does not expose memory to a model provider or operator by default.

## Key hierarchy (target design)

Use separate cryptographic purposes and rotate keys independently:

1. **Owner signing key:** signs enrolment, recovery, and high-authority owner commands.
2. **Device key:** generated on each device; proves possession for device authentication.
3. **Instance root key:** derived or unwrapped only through an owner-controlled recovery process; not stored in plaintext on the server.
4. **Data-encryption keys:** envelope-encrypt media, memory, and evidence stores; rotate by key version.
5. **Service credentials:** authenticate service-to-service calls; never double as owner identity or data-encryption keys.

Do not write custom cryptography. Use reviewed platform and cryptographic libraries, with independent security review before production.

## Device enrolment

1. First-run setup creates the owner identity and instance identifier.
2. The owner verifies and records recovery material offline.
3. The first device generates a non-exportable key when the platform supports it.
4. A device challenge is signed and bound to the instance ID, device public key, expiry, and requested permissions.
5. The owner signs the enrolment authorisation.
6. The service registers the device public key and issues narrowly scoped, short-lived sessions.
7. Later devices require a signed enrolment from an already trusted owner/recovery path.

Biometric unlock may gate local key use, but biometrics are not the cryptographic identity itself. Hardware-backed key storage and StrongBox availability vary by device and must be checked at runtime. Passkeys may sync between devices depending on provider configuration; they should not be assumed to mean “one physical device only.”

## Request authorisation

Each request must bind:
- instance identifier;
- enrolled device identifier and key;
- unique nonce or request identifier;
- timestamp and short expiry;
- HTTP method and canonical request target;
- body digest;
- requested capability/scope.

The server validates signature, expiry, replay status, device revocation, instance binding, and permission before accessing protected resources. This follows the resource-focused, no-implicit-trust model in NIST SP 800-207: https://csrc.nist.gov/pubs/sp/800/207/final

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
- invalid signature denied;
- replayed request denied;
- expired request denied;
- revoked device denied immediately;
- wrong instance ID denied;
- guest/public registration absent;
- no provider call when external inference is disabled;
- copied database is unreadable without required keys;
- backups restore only with owner recovery;
- model output cannot grant itself permissions;
- destructive memory action requires explicit owner authorisation.
