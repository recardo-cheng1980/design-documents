# Joint Working Doc: SVS Cloud / WNC IQ-9075 Gateway Architecture & Responsibility Split

**Status:** proposal draft for joint review — documentation only, no code/recipe/config change
**Date:** 2026-09-05
**Participants:** WNC (device/gateway firmware), SVS (cloud service development)
**Companion docs:** [`01-kickoff-request-for-help.md`](01-kickoff-request-for-help.md) (the WNC-framed
ask; read this doc for the neutral architecture proposal to work from together);
[`03-siem-and-production-provisioning.md`](03-siem-and-production-provisioning.md) (SIEM ingestion and
production-line provisioning detail, summarized in §1.2/§4 below)

This document is written to be presented and edited jointly — it proposes a line, not a demand.
Every claim about the device side is backed by code/test evidence in this repo; every claim about
the cloud side is either confirmed-live (per prior verification sessions) or explicitly marked as a
gap for SVS to confirm, correct, or fill in.

## 1. Current state — what exists today

### 1.1 Device side (WNC-owned, implemented)

```
IQ-9075 Gateway (QCS9075)
├── TPM2 hardware root of trust (tpm2-tss / tpm2-pkcs11)
│   └── kms-cert-manager.service
│       ├── TPMKeyManager      — RSA/EC keypair generation on TPM, never leaves hardware
│       ├── FileKeyManager     — non-TPM fallback for DMZ/IT-zone services (no TPM device access
│       │                        by design — see docs/otit-dmz-it-ldap-client-cert-plan.md)
│       ├── VaultPKIClient     — CSR → Vault PKI sign, via vault-agent UDS proxy (AppRole)
│       ├── VaultSSHClient     — SSH host cert signing + CA trust-anchor refresh (read-only)
│       └── SymmetricKeyManager — TPM-sealed KEK → wrapped DEK → AES-GCM envelope encryption
├── container-ota-agent.service
│   ├── cosign verify (public key baked into image; --insecure-ignore-tlog)
│   └── podman pull (rootless, per OT/IT/DMZ zone), gated on Vault-issued ephemeral registry creds
├── OT/IT/DMZ network zone separation (lxc-zones, rootless podman per zone)
└── sssd + OpenLDAP client (mTLS-capable, file-based cert only in DMZ zone — not yet TPM-backed)
```

### 1.2 Cloud side (currently `csyang.org` — status per endpoint)

| Endpoint | Role | Status |
|---|---|---|
| `vault.csyang.org` | PKI + SSH CA + registry-credential issuance, AppRole auth | Live, confirmed 15/15 (2026-09-01) |
| `mqtt-server.csyang.org:8443` | mTLS telemetry/command channel | Live, confirmed |
| `api.csyang.org` | IDevID/SSH cert issuance API | Live; had a prior unauthenticated-`/api/logs` incident, now gated |
| `ldaps.csyang.org` | Directory/AuthN | Live (`sssd` + OpenLDAP), client cert path not yet TPM-backed |
| OCI/container registry | Image pull source for `container-ota-agent` | **Not configured anywhere** — no `registries.conf` exists |
| OSTree update remote | Base OS image OTA | **Not configured** — `meta-updater` layer present, no live remote |
| DMS / fleet management | Inventory, per-device policy, remote config | **Does not exist** |
| Monitoring/alerting | Operational visibility | **Does not exist** — see incident below |
| Vault HA / key escrow | Unseal-key and root-CA backup | **Not confirmed** |
| RADIUS (WPA3-Enterprise) | Enterprise Wi-Fi auth | **Confirmed absent** — hardcoded WPA2-PSK |
| SIEM / log collector | Ingest the device's already-built masked/HMAC-signed audit stream | **Not configured** — rsyslog's TLS forwarder targets a loopback placeholder; CrowdSec installed with no acquisition config |
| Production-line IDevID enrollment | Issue each device's permanent manufacturing identity, register its CA with `provision.csyang.org` | **Broken/external** — live 2026-07-30 test found the broker rejects the commission MQTT connection; referenced manufacturing-enrollment design docs don't exist in this repo |

**Note on scope naming:** the working agenda for this collaboration originally referenced
"PKI/EJBCA." The implemented and verified PKI backend is **HashiCorp Vault** — no EJBCA reference
exists anywhere in this codebase. If EJBCA is part of SVS's independent standardization, this needs
an explicit joint decision (Vault-only vs. EJBCA-only vs. Vault-fronting-EJBCA) before any
migration work is scoped — see open question in §6.

## 2. Proposed architecture — SVS cloud ↔ IQ-9075 gateway

```
                              ┌─────────────────────────────────────────┐
                              │            SVS CLOUD SERVICES            │
                              │                                           │
   ┌────────────────┐        │  ┌───────────┐   ┌────────────────────┐  │
   │  IQ-9075        │  mTLS  │  │  Vault     │   │  Signing/Issuance   │  │
   │  Gateway         │◄──────┼─►│  (PKI +    │◄─►│  API                │  │
   │  (WNC-owned)     │        │  │  SSH CA +  │   │  (IDevID/SSH certs) │  │
   │                  │        │  │  KV creds) │   └────────────────────┘  │
   │  ┌────────────┐  │        │  └───────────┘                            │
   │  │kms-cert-    │  │        │  ┌───────────┐   ┌────────────────────┐  │
   │  │manager      │──┼────────┼─►│  MQTT      │   │  LDAP directory     │  │
   │  └────────────┘  │  mTLS  │  │  broker    │   │  (ldaps)             │  │
   │  ┌────────────┐  │  :8443 │  └───────────┘   └────────────────────┘  │
   │  │container-   │  │        │                                           │
   │  │ota-agent    │──┼────────┼─► ┌─────────────────────┐  ── PROPOSED ── │
   │  └────────────┘  │  image  │  │  OCI/Docker registry │   (gap, §1.2)   │
   │                  │  pull   │  └─────────────────────┘                 │
   │  ┌────────────┐  │        │  ┌─────────────────────┐  ── PROPOSED ── │
   │  │TPM (SRK/    │  │        │  │  DMS / fleet mgmt    │   (gap, §1.2)   │
   │  │hardware root)│ │        │  └─────────────────────┘                 │
   │  └────────────┘  │        │  ┌─────────────────────┐  ── PROPOSED ── │
   └──────────────────┘        │  │  Monitoring/alerting │   (gap, §1.2)   │
                                 │  └─────────────────────┘                 │
                                 │  ┌─────────────────────┐  ── PROPOSED ── │
                                 │  │  OSTree update remote│   (gap, §1.2)   │
                                 │  └─────────────────────┘                 │
                                 │  ┌─────────────────────┐  ── PROPOSED ── │
                                 │  │  SIEM / log collector│   (gap, §1.2)   │
                                 │  └─────────────────────┘                 │
                                 │  ┌─────────────────────┐  ── BROKEN ──── │
                                 │  │  Production-line     │   (gap, §1.2 — │
                                 │  │  IDevID enrollment   │   confirmed    │
                                 │  └─────────────────────┘   live failure) │
                                 └───────────────────────────────────────────┘
```

Boxes labeled **PROPOSED** are the gap-table items from
[`../cloud-services/required-cloud-services-gap-assessment.md`](../cloud-services/required-cloud-services-gap-assessment.md)
— not built anywhere today, on either side.

## 3. Container image signing & verification trust chain

This is the one flow that already spans both sides conceptually, even though the SVS half doesn't
exist yet — worth walking in detail since it's the cleanest example of the split.

```
 SVS SIDE (build/release — mostly TO BE DEFINED)          WNC SIDE (device — implemented)
 ┌────────────────────────────────┐                       ┌──────────────────────────────────┐
 │ 1. Build container image        │                       │                                   │
 │ 2. cosign sign (PRIVATE key —   │                       │  4. container-ota-agent receives  │
 │    holder = ? not yet defined)  │                       │     pull command (image, digest,  │
 │ 3. Push to OCI registry         │──── image + sig ─────►│     vault_path) via UDS from       │
 │    (registry itself = gap)      │                       │     kms-mqtt-trigger               │
 └────────────────────────────────┘                       │                                   │
                                                            │  5. Request ephemeral registry     │
                                                            │     creds from kms-cert-manager    │
                                                            │     (docker_login → Vault KV read) │
                                                            │  6. cosign verify --key cosign.pub │
                                                            │     (--insecure-ignore-tlog)       │
                                                            │  7. podman pull by digest (only if │
                                                            │     verify passed)                 │
                                                            │  8. docker_logout — creds wiped    │
                                                            └──────────────────────────────────┘
```

**Trust anchor today:** `cosign.pub` is baked into the device image at build time
(`layers/meta-wnc/recipes-security/cosign/files/cosign.pub`). The device has **no path to update
this key remotely** — a key rotation requires a new device image build. Whoever holds the
**private** signing key is the actual root of trust for every container this fleet ever runs, and
that ownership is currently undefined. This is the single highest-leverage open question in the
whole collaboration: **who runs the signing step, with what key-custody model (HSM-backed KMS,
Vault transit engine, etc.), and how does key rotation reach deployed devices?**

Also flagged: `--insecure-ignore-tlog` disables Rekor transparency-log verification. This may be an
accepted tradeoff (no transparency log operated), but it should be a stated decision, not a default
nobody revisited.

## 4. Proposed WNC / SVS responsibility split

| Layer | Owner | Rationale |
|---|---|---|
| TPM key generation, on-device CSR, cosign *verification* enforcement, SELinux/AVC policy | **WNC** | Requires device/kernel/BSP expertise; hardware-bound |
| OT/IT/DMZ network zone model, per-zone key backend selection | **WNC** | Device-topology decision, tied to physical deployment |
| Vault PKI/SSH CA operation, HA, unsealing, key escrow | **SVS (proposed)** | Cloud infra operational discipline; fleet-wide blast radius on failure |
| Signing/issuance API (`api.csyang.org`) hardening, authZ | **SVS (proposed)** | Already had one incident (`/api/logs`); needs cloud-side security ownership |
| Container image **build + signing** (private key custody) | **SVS (proposed) — TBD** | Currently unowned by either team; must be resolved (§3) |
| OCI registry hosting/access model | **SVS (proposed)** | Registry infra is not a firmware concern |
| OSTree update server / base-image OTA | **SVS (proposed)** | Fleet update orchestration is server-side |
| DMS / fleet management | **SVS (proposed)** | Inherently a multi-device, cloud-side control plane |
| Monitoring/alerting, log aggregation | **SVS (proposed)** | Needs to correlate across the fleet, not per-device |
| RADIUS/WPA3-Enterprise (if in scope) | **SVS (proposed), device does the client (WNC)** | Server operation is cloud/IT infra; device side is a config change |
| SIEM ingestion endpoint + CrowdSec wiring | **SVS (proposed)** | Collector/SIEM operation is cloud infra; device already emits a masked, integrity-signed stream ready to consume |
| Production-line IDevID issuance + broker trust registration | **SVS/manufacturing-ops (proposed) — currently has no confirmed owner** | Confirmed broken today (§1.2); blocks real field commissioning for every shipped device |

This table is a proposal for discussion, not a final allocation — rows marked "(proposed)" are
exactly the ones that should be argued over in the joint session, not rubber-stamped.

## 5. IEC 62443-4-2 controls — joint scope

**Caveat (same as the kickoff doc):** CR numbers referenced in
`docs/cloud-services/required-cloud-services-gap-assessment.md` are inferred, not confirmed against
a canonical matrix — the prior canonical file was intentionally deleted. Treat any CR number below
as a discussion starting point, not a citation.

| Service | Sub-Req (unverified) | Evidence | Gap | Verdict |
|---|---|---|---|---|
| Vault PKI/SSH CA | CR 1.5, CR 1.9 | AppRole issuance confirmed live 2026-09-01 | No confirmed key-escrow/backup for unseal keys or root CA | Partially met |
| Signing/issuance API | CR 1.5, CR 3.1 | Auth gate (`X-SSH-Sign-Key`) added after incident | Compensating control only; no defense-in-depth documented | Partially met |
| Container image trust chain | CR 3.4, CR 7.6 | cosign verify + ephemeral creds implemented device-side | No registry config; private signing key custody undefined; Rekor disabled | Partially met (device half only) |
| OTA/base image delivery | CR 3.4, CR 7.6 | `meta-updater` layer present | No live OSTree remote | Not met |
| Monitoring/alerting | CR 6.2 | None found | No paging on the Vault-token outage this session found | Not met |
| RADIUS/WPA3-Enterprise | CR 1.1, CR 1.9 | — | Hardcoded WPA2-PSK | Not met |

## 6. Open questions to resolve jointly

1. **PKI product decision** — Vault-only, EJBCA-only, or Vault-fronting-EJBCA? Blocks any further
   PKI-related scoping.
2. **Cosign private-key custody** — who signs container images, and with what key-management model?
   This is the actual root of trust for the container OTA chain and currently has no owner.
3. **Is `csyang.org` the production domain**, or does SVS plan a different production topology the
   device-side endpoint config will need to migrate to?
4. **Registry choice** — self-hosted OCI registry, managed cloud registry (e.g. GHCR/ECR/ACR
   equivalent), or something SVS already operates for other products?
5. **DMS scope** — is fleet management being built new, or does SVS have an existing platform this
   gateway should integrate into?
6. **Who holds the canonical IEC 62443-4-2 CR matrix** for this product, to replace the inferred CR
   numbers used in both this doc and the gap-assessment doc?
7. **Rekor/transparency log** — accept `--insecure-ignore-tlog` as final, or does SVS want to stand
   up a private transparency log?
8. **SIEM product and ownership** — Wazuh or otherwise; who runs it, and who issues/rotates the
   log-forwarding client certificate?
9. **Who owns `provision.csyang.org`'s CA trust store**, and where does manufacturing-line IDevID
   issuance actually happen today — this blocks real field commissioning right now (§1.2).

## Side Effects & Caveats

- This document changes no code, recipe, config, or running service.
- The architecture diagram in §2 mixes confirmed-live boxes and proposed/gap boxes explicitly
  labeled as such — do not read a proposed box as already built.
- §3's cosign private-key custody question is flagged as the single highest-priority item to resolve
  before any other cloud-side work is scoped, since every other container-trust decision depends on
  its answer.
