---
title: "AIoT Gateway Gap Closure --- Device Team / Cloud Team Responsibility Split"
subtitle: "Ownership matrix for closing the gaps identified in 2026-09-07-target-architecture-gap-analysis.md"
date: "2026-09-07"
---

# 0. How to read this

For each work item from the companion gap analysis, this document
names who builds what and, where the two sides depend on each other,
what interface contract they need to agree on first. "Device team"
means on-device/platform work in `drop1-security` (Yocto recipes,
sshd/hostapd/SSSD config, on-device daemons). "Cloud team" means the
backend services the gateway talks to (Vault, RADIUS, LDAP, SIEM, ACS,
registries, portals) --- most of which live outside this repository.

Where a third stakeholder is needed (e.g. manufacturing/factory
operations), that is called out explicitly rather than forced into one
of the two columns.

# 1. Identity & PKI / KMS

| Work item | Device team | Cloud team |
|---|---|---|
| Manufacturing IDevID provisioning | Device comissioning service, TPM sealing, on-device CSR generation | Issuance API endpoint the device mTLS-authenticates to (currently `api.csyang.org`) |
| Factory/MES integration | N/A --- device side is already complete | Building the real production-line station API (station auth, serial/model validation, batch throughput). **Needs a third stakeholder (manufacturing/ops), not just cloud dev.** |
| LDevID commissioning (Vault AppRole) | Owns the on-device exchange logic in `device-commission.py` | Credentials issuance and role/policy configuration |
| Cert rotation / renewal (`kms-cert-manager`) | Owns the daemon, UDS socket, TPM-backed key operations |  Signing the certificate based on the CSR |
| OCSP/CRL revocation checking | Owns adding a revocation-check call into `kms-cert-manager` before trusting a cert | Owns standing up the OCSP responder / CRL distribution point in front of Vault |
| CLM/CKM two-plane split, HSM Cluster, KEK controls | None --- this is cloud/infra architecture | HSM procurement/integration, splitting cert-lifecycle logic from crypto-ops logic, KEK policy (HSM is for FIP140-3) |
| Certificate Policy Engine + Certificate Inventory | Emits cert metadata/telemetry the cloud side can ingest | Inventory database and policy engine |
| Remote CA issuance server + portal for DUT access certs (RBAC) | Owns client-side trust config, consuming a signed cert once issued | CA signing service, the portal UI, and RBAC policy for who can request/approve a cert |
| Security Administration (dual approval, HSM health monitoring) | None | Fully cloud/ops governance |
| WPA3-Enterprise enable | Replacing the shared secret mechanism | Owns standing up / exposing the actual cloud RADIUS server |
| RADIUS forward vs. local terminate | Owns repointing from `127.0.0.1` to the cloud server, removing local FreeRADIUS EAP termination | Owns the cloud RADIUS server's EAP-TLS/PEAP configuration and accounting |
| Multiple LDAPS servers (itns/dmzns) + Azure migration | Owns per-namespace SSSD configuration, once namespaces exist (blocked on §4) | Owns standing up multiple LDAPS endpoints and the Azure AD/Entra migration itself |
| Security event / log forwarding | Owns wiring rsyslog/journald (or adding a Wazuh agent) to forward off-device | Owns the SIEM/log collector receiving it |
| Metrics / health / heartbeat to cloud | Owns extending `ha-metrics` (currently loopback-only) to emit outward | Owns the Monitoring/Alerting service and dashboards |
| Protocol decision (stay CWMP vs. move to USP) | Provides input on the cost of replacing the working `CcspTr069Pa` stack | Owns the ACS/DMS platform decision and the device-management portal. **Needs explicit sign-off from the target-design owner --- this changes the target, not just the implementation plan.** |

# 3. Container Supply Chain & Firmware OTA
| Work item | Device team | Cloud team |
|---|---|---|
| Container signature verification | Done --- `cosign`, `container-ota-agent.py` | Owns publishing signed images to whatever registry is chosen |
| Registry decision (ACR vs. registry-agnostic OCI) | Consumes whichever registry API is decided | Owns the decision and the CI/CD build-sign-push pipeline. **Flag vendor lock-in risk before committing to ACR literally.** |
| MQTT vs. TR-069 trigger decision | Owns whichever client path is chosen (`kms-mqtt-trigger` exists; `CcspTr069Pa` exists but unwired to containers) | Owns the ACS/MQTT-broker side of whichever path is chosen, plus status-reporting ingestion |
| OTA firmware repository / distribution | Owns OSTree pull/verify logic (already built) | Owns hosting the OSTree remote and its transport security (mTLS/HTTPS) |
| Cloud MQTT Broker | Owns client integration only | Fully cloud infra --- broker, mTLS termination, topic ACLs |
