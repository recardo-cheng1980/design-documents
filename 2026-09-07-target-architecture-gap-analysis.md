---
title: "AIoT Gateway Integrated Architecture --- Target Design vs. drop1-security Gap Analysis"
subtitle: "Cross-reference of the 6-page AIoT Gateway target design (replicate.pdf) against drop1-security @ HEAD (WNC IQ-9075 / QCS9075, Yocto)"
date: "2026-09-07"
---

# 0. Scope & Method

The target design (`replicate.pdf`, 6 pages) describes an AIoT gateway
integrated with cloud services across five areas: (1) overall
namespace/host architecture, (2) KMS device-identity lifecycle and
two-part PKI service architecture, (3) container image signing and
update, (4) Wi-Fi/SSH AAA, and (5) operational data/logging/monitoring.

This document cross-references each element of that design against the
actual state of `drop1-security` at HEAD, gathered by direct code
survey (recipes, configs, scripts, commit history) --- not inference
from the design doc. Every claim below traces to a named file, recipe,
or commit. Where evidence was not found, that is stated explicitly
rather than assumed absent by omission.

Status legend: **Matches design** (built and consistent with the
target) / **Partial** (some mechanics exist, key pieces missing) /
**Regressed** (a working control existed and was removed) / **Absent**
(no evidence found anywhere in-tree).

# 1. Executive Summary

| Domain | Status | Summary |
|---|---|---|
| KMS & Device Identity | Partial | IDevID/LDevID device-side lifecycle works end-to-end on TPM + Vault PKI and is field-tested. No revocation checking, no CA governance plane, no HSM, no factory/MES integration. |
| Container Signing & OTA | Partial | cosign verification and signed OSTree firmware OTA are real and working. No CI/CD-to-registry pipeline; trigger path is MQTT, not TR-069 as designed. |
| AAA (Wi-Fi + SSH) | **Regressed** | WPA3-Enterprise disabled, RADIUS not cloud-forwarding. SSH cert-only enforcement was removed in a recent commit. These are live defects, not missing features. |
| Namespace Isolation | Not started | No otns/dmzns/itns split anywhere in-tree. Current firewall implements the RDK-B LAN/WAN/DMZ router model, a different isolation scheme entirely. |
| Logging & Monitoring | Not started | No cloud SIEM forwarding, no Wazuh, no cloud metrics/alerting agent, no remote log server. Existing HA heartbeat/metrics is local pull-only. |

The target design assumes a cloud-integrated gateway; the current repo
implements the edge/device half of that picture. Device-anchored
cryptographic primitives (TPM, IDevID/LDevID, cosign, OSTree signing)
are real and tested. Every cloud-facing control plane the design
depends on is partial, unbuilt, or actively regressed.

# 2. Identity & Supply Chain

## 2.1 KMS --- Device Identity Lifecycle

| Target capability | Evidence in drop1-security | Status |
|---|---|---|
| Manufacturing: IDevID provisioning in TPM | TPM-sealed IDevID keypair + CSR flow in `layers/meta-wnc/recipes-security/device-commission/files/device-commission.py`; operator driver `tests/provisioning-operator-scripts/idevid-ssh-trust-provision.sh` signs against `api.csyang.org`. | **Partial** (device mechanics work; see 2.1.1 --- no factory/MES integration exists) |
| Commissioning: LDevID enrollment | IDevID-authenticated Vault AppRole exchange issues an LDevID-tier cert (e.g. `CN=mqtt.csyang.org`); field-verified 13/13 steps against a real DUT (`ldevid-commission-flow.sh`, 2026-08-04). | Matches design |
| Operation: cert-based mTLS / MQTT auth | `kms-cert-manager.py` rotates certs via a UDS daemon; `kms-mqtt-trigger`, `vault-agent`, `mosquitto-dev-selfsigned` consume them. | Partial |
| Two-part CLM / CKM plane split, dual-approval CA keys, HSM Cluster | `kms-cert-manager.py` conflates enrollment, keygen, and Vault-PKI submission in one daemon. No separated planes, no dual approval, no separated admin roles. No CA software in-tree --- signing is delegated to an external Vault instance / API. HSM hits found are unrelated (`softhsm` test target, `aktualizr` recipe). | Absent |
| OCSP / CRL revocation checking | Zero matches for revocation logic in `kms-cert-manager.py` or `device-commission.py`. | Absent |
| Certificate Policy Engine + Certificate Inventory | No fleet-wide certificate database or policy engine found; only ad hoc local state in `kms-cert-manager.py`. | Absent |

### 2.1.1 Correction: factory/MES integration

An earlier pass of this analysis marked "Manufacturing: IDevID
provisioning" as fully matching the design because the on-device TPM/CSR
mechanics are real and field-tested. On closer inspection, the only
provisioning flow that exists is a manual, human-operated script:
`idevid-ssh-trust-provision.sh`'s own header describes itself as
simulating a human operator, bridging a developer laptop through an
SSH jump box and `adb` to a single Device Under Test. There is no
station identity, no batch/queue handling, and no
MES/serial-number-database integration anywhere in the repo (`MES`,
`manufacturing execution`, `factory station`, `serial number database`
all return zero hits). The API-contract docs it references
(`docs/kms/`, `docs/provisioning/`) do not exist. The target design's
"Factory Provisioning Role" --- an authenticated production-line
station --- has no automated counterpart today.

## 2.2 Container Image Signing & Update

| Target capability | Evidence in drop1-security | Status |
|---|---|---|
| Signature verification on-device | Real cosign binary + locked-down `/etc/cosign`; `container-ota-agent.py` verifies against a bundled `cosign.pub` before `docker pull` by digest. | Matches design |
| CI/CD build-sign-push to a container registry | No CI/CD pipeline definitions found anywhere in-tree. | Absent |
| Azure Container Registry integration | `grep -rl azurecr.io` returns zero hits anywhere in the tree; the registry credential path that exists is generic Vault, not ACR-specific. | Absent (see also §4 on vendor lock-in) |
| TR-069-initiated update flow, status report to ACS | A full `CcspTr069Pa` CWMP stack exists but has zero linkage to containers/docker/podman. The actual trigger path built is MQTT (`kms-mqtt-trigger`) --- a disjoint mechanism from the design. | Absent |
| Signed firmware OTA (OSTree) | `wnc-fota` + GPG-signed OSTree commits (`wnc-ostree-keys`, `ostree-gpg-sign.bbclass`) --- a working, tested pipeline. | Matches design |

# 3. Network & Namespace

## 3.1 Authentication, Authorization, Accounting

| Target capability | Evidence in drop1-security | Status |
|---|---|---|
| Wi-Fi: WPA3-Enterprise | The WPA3 cipher line in `hostapd-enterprise.conf.template` is commented out; WPA2 is the active default. | **Regressed / not enabled** |
| Wi-Fi: cloud-forwarding RADIUS | Local FreeRADIUS terminates EAP itself (`radiusd-iq9075.conf`) --- the opposite topology from "forward to cloud RADIUS." `auth_server_addr`/`acct_server_addr` point at `127.0.0.1`. Shared secret is literally `change_me_before_production`. | Absent / live defect |
| SSH: LDAPS identity, LAN-only binding | `sshd-brlan0.socket` correctly restricts sshd to the LAN bridge; SSSD talks `ldaps://ldaps.csyang.org` over TCP 636 with no RADIUS involvement. | Matches design |
| SSH: cert-only enforcement, no shared root password | Commit `0c68d0f53` retired the build-time root-login toggle and `40-sysadmin-cert-only.conf`. Static baseline is now `PermitRootLogin yes` + `PasswordAuthentication yes`, gated only by a runtime flag. Pending product-security review since 2026-08-05. | **Regressed** |
| SSH: LDAP bind credential hygiene | `wnc-ldap.conf` ships a hardcoded plaintext admin bind password with an in-tree `TODO` to replace it with a read-only service account. | Live defect |
| SSH: remote CA / portal for local login cert issuance | Trust is entirely local and manufacturing-provisioned; `30-ssh-ca.conf` states its CA/host certs are "never fetched, generated, or written by any on-device service." No `ssh-keygen -s` signing, no enrollment API, no portal exist. The design doc `docs/kms/ssh-ca-user-and-host-certs-plan.md` cited in comments does not exist in the repo. | Absent |
| Multiple LDAPS servers per namespace (itns/dmzns) + Azure migration | Only a single LDAPS endpoint is configured (`ldaps://ldaps.csyang.org` in `sssd.conf`). Per-namespace LDAPS is blocked on namespace isolation (§3.2) not existing yet. | Absent |

## 3.2 Namespace Isolation, Logging & Monitoring

| Target capability | Evidence in drop1-security | Status |
|---|---|---|
| otns / dmzns / itns split (host + 3 isolated namespaces) | No matching names, LXC/Podman manifests, or SELinux types (`otns_t`/`dmzns_t`/`itns_t`) found anywhere. Current nftables engine (`ccsp-zone-firewall`) implements RDK-B LAN/WAN/DMZ router zones --- a different isolation model. | Absent |
| OT namespace apps (EdgeX, ChirpStack) | ChirpStack is genuinely built (`chirpstack`, `chirpstack-gateway-bridge`, REST API, MQTT creds). EdgeX code paths (`edgex`, `edgex-device-mqtt`) appear referenced in at least one incident memo (`doc/62443_Impl_P3-7_Errata_DropMergeGaps.md`) as a downstream MQTT consumer, but the design-level EdgeX/TR-181 integration itself is only a spec doc (`docs/superpowers/specs/2026-07-16-iot-tr181-edgex-integration-design.md`), not confirmed production wiring. | Partial |
| Cloud SIEM log forwarding, security event collection | rsyslog is configured for local log security/rotation only (`logsec`). No Wazuh agent, no TLS/Syslog forwarding to an external collector found. | Absent |
| Cloud metrics / alerting / heartbeat | `ha-supervisor`/`ha-heartbeat`/`ha-metrics` implement local active/standby failover with a loopback-only Prometheus endpoint --- not a cloud-facing health agent. | Absent |
| Remote log server | No remote syslog/log-shipping target configured. | Absent |

# 4. Cloud Services Not Yet Scoped

These are cloud-side services the target design specifies that fall
outside the items above and had not been separately named before this
pass:

1. **HSM Cluster / KEK & HSM Controls** (target design, KMS Part 2) ---
   the design's Cryptographic Key Management Plane calls for a
   dedicated HSM Cluster and KEK controls distinct from Vault-as-PKI.
   No HSM infrastructure exists; this is the root-of-trust layer
   everything else (signing, revocation, dual approval) is meant to
   sit on. Largest single missing cloud service in the design.
2. **Certificate Policy Engine + Certificate Inventory** (KMS Part 1) ---
   a fleet-wide database of which cert is on which device and what
   policy applies, distinct from issuance/rotation logic. Not present
   even informally.
3. **Cloud MQTT Broker** --- the design's central operational-data bus
   (mTLS:8883) between edge apps and SIEM/monitoring. Device-side MQTT
   clients exist; the broker service itself is unaddressed.
4. **OTA Firmware Repository / distribution service** --- distinct
   from the container-registry question in §2.2; the design also
   specifies a standalone cloud firmware repository with its own
   secure-distribution transport. Device-side OSTree pull/verify logic
   is real; what hosts the OSTree remote, and whether that transport is
   mTLS, is unconfirmed.
5. **Fleet Analytics, Backup/Disaster Recovery** (target design, "Other
   Cloud Services") --- named siblings to Container Registry and
   Monitoring/Alerting in the design; neither has been scoped.
6. **SVS --- Service Verifiers** --- the design's discrete enforcement
   function that checks mTLS chain/expiry and CRL/OCSP status at each
   MQTT/TR-069/OTA protocol boundary. Even if OCSP/CRL data existed
   (item 2.1, absent), nothing currently consumes it at these
   verification points --- a produce-side/consume-side gap pair.
7. **Security Administration service** --- separated roles, dual
   approval for CA-key operations, and HSM health monitoring. Distinct
   from device-facing RBAC (§5, item 3): this is governance over the
   CA/HSM itself, not over who can request a device cert.

# 5. Recommended Roadmap

Ordered by urgency, not by design-page order. Items 1--2 are defect
remediation on code that already exists; items 3--6 are net-new
build-out and should each get a `docs/` design plan before
implementation.

1. **Close the SSH regression** (Urgent). Restore cert-only /
   root-disabled enforcement removed in `0c68d0f53`; replace the
   hardcoded plaintext LDAP bind password in `wnc-ldap.conf` with a
   scoped read-only service account. Pending product-security review
   --- treat as blocking.
2. **Correct the Wi-Fi AAA topology** (Urgent). Re-enable the
   WPA3-Enterprise cipher line, replace the default RADIUS secret, and
   repoint `hostapd-radius.conf.inc` at a cloud RADIUS server instead
   of terminating EAP locally --- or explicitly document local-EAP as
   an accepted deviation if that is intentional.
3. **Stand up a remote CA issuance server + portal for DUT access
   certificates, with RBAC** (Design needed). Broaden scope from
   SSH-only to DUT access certificates generally (SSH + device
   identity), gated by role-based approval --- this connects directly
   to the Security Administration gap in §4, item 7. Sequence after
   item 1: a new issuance path is moot while password/root login
   remains a parallel bypass. Likely lowest-lift as a Vault SSH
   secrets-engine role bolted onto the existing `kms-cert-manager`/
   AppRole chain, gated behind SSSD/LDAPS identity.
4. **Add KMS governance: revocation + plane separation** (Design
   needed). Introduce OCSP/CRL checks before trusting any LDevID cert
   (both the produce-side KMS work and the consume-side SVS
   enforcement in §4, item 6); split `kms-cert-manager.py` into a
   Certificate Lifecycle plane and a Crypto/HSM plane with separated
   admin roles, matching Part 1 / Part 2 of the target design.
5. **Decide the container supply-chain path** (Design needed, and a
   deliberate architecture decision, not just a gap to fill). Options:
   (a) build the CI/CD-to-registry signing pipeline the design
   assumes, or (b) formally adopt the working Vault+MQTT path as the
   sanctioned alternative. Either way, wire status reporting into
   whichever trigger is chosen (MQTT vs. TR-069) --- don't leave both
   half-built. **Registry choice carries a vendor-lock-in
   consideration**: building strictly to Azure Container Registry as
   literally specified inherits Azure dependency; evaluate a
   registry-agnostic OCI approach as an alternative, or accept the
   lock-in as a conscious tradeoff.
6. **Scope the namespace isolation build-out** (Design needed, longest
   lead time). otns/dmzns/itns plus per-namespace LDAPS, cloud SIEM,
   and metrics forwarding is the largest gap and has no code to build
   on. Start with a design doc, not an implementation sprint.

## 5.1 Items requiring a design-owner decision, not just implementation

Two items surfaced during review diverge from the target design itself
rather than filling a gap in it, and should be raised with whoever
owns the target architecture before being folded into a roadmap as
agreed scope:

- **TR-069 → TR-369 (USP) migration + device management portal.** The
  target design explicitly specifies TR-069/CWMP for the ACS/DMS. The
  repo already has a full, working `CcspTr069Pa` CWMP stack. Moving to
  TR-369/USP is a legitimate modernization argument but represents a
  rearchitecture of a working subsystem, not a gap-fill --- it changes
  the target, not the plan to reach it.
- **Container registry vendor lock-in (ACR).** See item 5 above ---
  flagged here again because it is a strategy decision, not an
  implementation task.

# 6. Sources

- Target design: `replicate.pdf` (6 pages), read in full.
- Code survey: direct reads of recipes, configs, and scripts under
  `layers/meta-wnc/`, `layers/meta-virtualization/`, `layers/rdkb/`,
  `layers/meta-security/meta-tpm/`, `tests/provisioning-operator-scripts/`,
  and `doc/`.
- Related project memory: SSH root-login regression (commit
  `0c68d0f53`, pending product-security review since 2026-08-05);
  Commission Vault backend failure (resolved 2026-09-01).
- Companion document: `2026-09-07-device-cloud-responsibility-split.md`.
