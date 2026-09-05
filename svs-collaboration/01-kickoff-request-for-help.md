# Kickoff: WNC (AIOT Gateway) Requesting SVS (Cloud Services) Engagement

**Status:** proposal draft — documentation only, no code/recipe/config change
**Date:** 2026-09-05
**From:** WNC — device team, owns the IQ-9075 (QCS9075) AIOT gateway firmware/hardware
**To:** SVS — cloud service development department
**Companion docs:** [`02-joint-architecture-review.md`](02-joint-architecture-review.md) (neutral working doc for a
joint session, once both teams are engaged); [`03-siem-and-production-provisioning.md`](03-siem-and-production-provisioning.md)
(SIEM log-ingestion gap and the production-line IDevID enrollment gap — including a confirmed live
broker-rejection incident)

## 1. Why we're asking

WNC owns everything that runs *on* the IQ-9075 gateway: TPM-backed identity, on-device PKI client
logic, container signing/pull enforcement, OT/IT/DMZ network segmentation, and IEC 62443-4-2
control implementation at the device layer. None of that functions in isolation — every one of
those device-side mechanisms terminates in a cloud service call, and **today those cloud services
are either informally stood up, only partially verified, or entirely undefined**. We cannot close
out several IEC 62443-4-2 requirements, or make credible claims about fleet-wide key management,
without a cloud-side counterpart owned by a team whose job is cloud infrastructure — that isn't
our department's core competency and duplicating it on the device team is the wrong tradeoff.

This document is the ask. It describes what's already built and proven on the device side, states
plainly where our current cloud dependency (`csyang.org`) is a stand-in rather than a production
service, and lists the concrete gaps that need a cloud engineering owner.

## 2. What's already built and proven on-device

These are implemented and have passed live DUT verification — not a proposal, this is running
today:

| Capability | Mechanism | Verification evidence |
|---|---|---|
| Device identity / key storage | TPM2-backed keypairs (tpm2-tss, tpm2-pkcs11) — no discrete HSM chip, the TPM is the hardware root of trust | `layers/meta-wnc/recipes-security/kms-cert-manager/files/kms-cert-manager.py` |
| Certificate issuance (X.509) | On-device CSR generation → submitted to **HashiCorp Vault PKI** via `vault-agent` (AppRole auth) over a local UDS proxy | 15/15 pass, `docs/provisioning/commission-flow-vault-approle-wait-fix.md`, 2026-08-19/09-01 |
| SSH host/user certs | Vault SSH secrets engine (`sign-host`/CA trust-anchor refresh) — device never gains user-cert signing capability | `docs/kms/ssh-ca-user-and-host-certs-plan.md` (Track A) |
| mTLS telemetry/command channel | MQTT broker at `mqtt-server.csyang.org:8443` | Live, confirmed 2026-09-01 |
| Container image trust | `cosign` signature verification (public key baked into image) + rootless `podman pull`, gated on Vault-issued ephemeral registry credentials | `layers/meta-wnc/recipes-security/container-ota-agent/files/container-ota-agent.py` |
| Directory/AuthN | `sssd` + OpenLDAP bind to `ldaps.csyang.org` | `docs/dmz-ssh-bastion/design.md` |
| Symmetric secrets at rest | TPM-sealed KEK → wrapped DEK → AES-GCM envelope encryption | `kms-cert-manager.py` `SymmetricKeyManager` |

**Read this table as: the device already assumes a capable, available cloud PKI/identity/registry
backend exists. What we need from SVS is to make that assumption true in production, not a lab
substitute.**

## 3. Important scoping correction: it's Vault PKI, not EJBCA

The agenda for this kickoff lists "PKI/EJBCA" — we want to correct that before scoping goes further
so SVS doesn't staff or design against the wrong product. **There is no EJBCA anywhere in this
codebase.** The PKI backend actually implemented and exercised end-to-end is **HashiCorp Vault**
(PKI secrets engine + SSH secrets engine + KV v2 for registry credentials), reached from the device
via a local `vault-agent` proxy using AppRole authentication. If EJBCA is something SVS is already
standardizing on independently, that's a real conversation to have explicitly — a migration from
Vault PKI to EJBCA (or a Vault-fronts-EJBCA topology) is a materially different scope than "stand up
production Vault," and we'd want that decided consciously, not by mislabeling the agenda item.

## 4. The concrete ask — cloud-side gaps that need an SVS owner

This is the literal, evidence-backed gap table from
[`docs/cloud-services/required-cloud-services-gap-assessment.md`](../cloud-services/required-cloud-services-gap-assessment.md),
filtered to items that are **not met** or **partially met** and where the fix is outside what a
device-firmware team can or should own:

| Gap | Why it's cloud-side, not device-side | Impact if unresolved |
|---|---|---|
| **No OCI/Docker registry configuration** — `container-ota-agent`/cosign chain exists, but there's no `registries.conf` or defined pull source anywhere in the tree | The registry itself, its auth model, and the cosign *signing* side (device only ever holds the public key) are inherently a build/release infrastructure concern, not firmware | Container OTA has verification logic with nothing real to verify against in production |
| **No OSTree remote configured** for the base OS image | Base-image OTA delivery is a fleet update-server concern (`meta-updater`/`aktualizr` server-side counterpart) | Base OS cannot be updated in the field today — separate and larger than the container-OTA gap above |
| **No DMS / fleet management plane** | Inventory, per-device policy, and remote configuration is inherently server-side; zero hits for "device management"/"fleet" anywhere in this repo | No way to manage devices at fleet scale once shipped |
| **No monitoring/alerting** | A `VAULT_COMMISSION_TOKEN` outage went undetected for 109 consecutive attempts (02:14–03:20 UTC) — only found by a human manually pulling 2000 log lines after a test failed | Silent failures in production go unnoticed until a customer reports them |
| **No Vault-unseal / root-CA key escrow / backup** | Loss of Vault's unseal keys or the root CA is fleet-wide and unrecoverable — this is a cloud HA/DR concern, not something a device image can mitigate | Single point of catastrophic, irreversible failure for the entire fleet's identity |
| **RADIUS / WPA3-Enterprise absent** | `hostapd.conf` is hardcoded WPA2-PSK with a plaintext passphrase; enterprise auth needs a RADIUS server SVS would run | Cannot offer enterprise-grade Wi-Fi auth; a real security gap if positioned for enterprise/OT deployments |
| **`/api/logs` prior incident** — was unauthenticated and leaked live Vault tokens/API keys; compensating control (`X-SSH-Sign-Key` gate) is the only defense today | The signing/issuance API (`api.csyang.org`) is a cloud service SVS would own/harden | A single missed auth check on that service leaks fleet-wide secrets |
| **No secrets manager for operator credentials** — `IDEVID_ISSUE_API_KEY`/`SSH_SIGN_API_KEY` are hand-carried env vars per `tests/provisioning-operator-scripts/README.md` | Operator-facing secret distribution is a cloud IAM/secrets-manager concern | Operator keys get pasted in chat/scripts today — an active practice, not a hypothetical |
| **No SIEM / log-collector endpoint** — rsyslog's TLS forwarder targets a build-time loopback placeholder (`127.0.0.1:6514`); the real target is deliberately not shipped in firmware | Device pipeline (masking, HMAC integrity, disk-backed retry queue, audit/business log split) is fully built and waiting for a collector; CrowdSec is installed but has no acquisition/notification config wired | No way to actually see the audit trail this device already produces — same blind spot that let the Vault-token outage run 109 attempts undetected |
| **Production-line IDevID enrollment is external and currently broken** — a live test (2026-07-30) found `provision.csyang.org` rejects the commissioning MQTT connection at the application layer; three referenced manufacturing-enrollment design docs (`docs/kms/reset-recovery-dual-identity-plan.md` and two others) do not exist in this repo | Manufacturing-time key/cert issuance and broker CA trust registration is inherently a production-line/cloud-ops process, not device firmware | No device shipped today can complete real field commissioning until the broker trusts a manufacturing-issued IDevID CA — see [`03-siem-and-production-provisioning.md`](03-siem-and-production-provisioning.md) §2 |

## 5. What we are explicitly NOT asking SVS to own

To keep scope honest: WNC keeps ownership of everything downstream of the cloud boundary —
TPM key generation, on-device CSR logic, cosign verification enforcement, SELinux/AVC policy, the
OT/IT/DMZ zone model, and the actual on-device secret storage/envelope encryption. This is not a
"hand the whole security model to SVS" ask. See the joint architecture doc for the proposed line.

## 6. IEC 62443-4-2 angle

**Caveat, stated up front:** the CR numbers used elsewhere in this repo's cloud-gap assessment
(CR 1.1, 1.9, 3.1, 3.4, 6.1, 6.2, 7.1, 7.6) are the author's own inference from general IEC 62443-4-2
structure — **not confirmed against a canonical CR-to-control matrix** (the prior `docs/iec62443-full.md`
was deliberately deleted and is not to be recreated). We are not presenting these as certified
compliance mapping. What we *can* say with confidence: several of the gaps above (key escrow/backup,
monitoring/alerting, comms integrity/auth) map to control *families* (identification & authentication,
system integrity, timely response to events, resource availability) that this device cannot satisfy
alone — the compliance conversation is a joint one, and whoever owns the actual CR matrix for this
product should be in the room before either team commits control language to a customer or auditor.

## 7. Open questions for SVS

1. Is `csyang.org` (Vault, MQTT broker, signing API, LDAP) intended to become the production
   backend, or is it a lab/dev stand-in SVS will replace with different infrastructure? This changes
   whether device-side endpoint/cert-pinning config is final or will need to be revisited.
2. Does SVS already run — or plan to run — EJBCA anywhere in the org? If so, is the target topology
   Vault-only, EJBCA-only, or Vault-fronting-EJBCA?
3. Who owns cosign key-pair generation and signing today (i.e., the *private* half — the device only
   ever holds `cosign.pub`)? Is that already an SVS-owned CI/release pipeline, or does one need to be
   built?
4. Does SVS have an existing OCI registry, DMS/fleet-management platform, or monitoring stack we
   should integrate against, or is greenfield build expected?
5. Who owns Vault's HA topology, unsealing procedure, and root-CA/unseal-key backup and escrow —
   is that already inside SVS's existing Vault operational practice for other products?
6. Is RADIUS/WPA3-Enterprise in scope for this product at all, or is WPA2-PSK an accepted tradeoff
   for the target deployment environment (OT/industrial vs. enterprise)?
7. Where does production-line IDevID enrollment actually happen today, and who owns
   `provision.csyang.org`'s CA trust store and `device_id`→AppRole mapping — see
   [`03-siem-and-production-provisioning.md`](03-siem-and-production-provisioning.md) §2.4.
8. Is a SIEM (e.g. Wazuh) already standard elsewhere in SVS's stack, or does one need to be stood up
   for this product specifically — see [`03-siem-and-production-provisioning.md`](03-siem-and-production-provisioning.md) §1.3.

## 8. Proposed next steps

1. Joint working session using [`02-joint-architecture-review.md`](02-joint-architecture-review.md)
   to walk the proposed architecture and responsibility split line-by-line.
2. SVS confirms or corrects the PKI product decision (§3) before any migration work is scoped.
3. Agree an owner and rough timeline for each row in §4's gap table.
4. Identify whoever holds the canonical IEC 62443-4-2 CR matrix for this product so the compliance
   conversation in §6 has an authoritative source, not two teams' independent inferences.

## Side Effects & Caveats

- This document changes no code, recipe, config, or running service — it is a collaboration
  proposal only.
- All "what's built" claims in §2 are backed by cited test evidence in this repo; all "what's
  missing" claims in §4 are backed by the cited gap-assessment doc's negative-grep evidence, not
  speculation.
- The EJBCA correction in §3 is the single most important scoping fact in this document — presenting
  the agenda as originally worded to SVS without this correction risks the wrong staffing/product
  decision on their side.
