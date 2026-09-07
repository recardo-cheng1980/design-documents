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
| Manufacturing IDevID provisioning | Owns `device-commission.py`, TPM sealing, on-device CSR generation | Owns the issuance API endpoint the device mTLS-authenticates to (currently `api.csyang.org`) |
| Factory/MES integration | N/A --- device side is already complete | Owns building the real production-line station API (station auth, serial/model validation, batch throughput). **Needs a third stakeholder (manufacturing/ops), not just cloud dev.** |
| LDevID commissioning (Vault AppRole) | Owns the on-device exchange logic in `device-commission.py` | Owns Vault AppRole issuance and role/policy configuration |
| Cert rotation / renewal (`kms-cert-manager`) | Owns the daemon, UDS socket, TPM-backed key operations | Owns the Vault PKI mount/role it submits CSRs to |
| OCSP/CRL revocation checking | Owns adding a revocation-check call into `kms-cert-manager` before trusting a cert | Owns standing up the OCSP responder / CRL distribution point in front of Vault |
| CLM/CKM two-plane split, HSM Cluster, KEK controls | None --- this is cloud/infra architecture | Owns HSM procurement/integration, splitting cert-lifecycle logic from crypto-ops logic, KEK policy |
| Certificate Policy Engine + Certificate Inventory | Emits cert metadata/telemetry the cloud side can ingest | Owns the fleet-wide inventory database and policy engine |
| Remote CA issuance server + portal for DUT access certs (RBAC) | Owns client-side trust config (`30-ssh-ca.conf` and equivalents), consuming a signed cert once issued | Owns the CA signing service, the portal UI, and RBAC policy for who can request/approve a cert |
| Security Administration (dual approval, HSM health monitoring) | None | Fully cloud/ops governance |

# 2. AAA (Wi-Fi + SSH)

| Work item | Device team | Cloud team |
|---|---|---|
| WPA3-Enterprise enable | Owns flipping the cipher line in `hostapd-enterprise.conf.template`, replacing the shared secret | Owns standing up / exposing the actual cloud RADIUS server |
| RADIUS forward vs. local terminate | Owns repointing `hostapd-radius.conf.inc` from `127.0.0.1` to the cloud server, removing local FreeRADIUS EAP termination | Owns the cloud RADIUS server's EAP-TLS/PEAP configuration and accounting |
| SSH regression fix (cert-only / root-disabled) | Fully device team --- restore the retired build-time toggle and `40-sysadmin-cert-only.conf` | None |
| LDAP bind credential hygiene | Owns swapping the hardcoded bind password for a scoped service-account credential | Owns provisioning that read-only service account in the directory |
| Multiple LDAPS servers (itns/dmzns) + Azure migration | Owns per-namespace SSSD configuration, once namespaces exist (blocked on §4) | Owns standing up multiple LDAPS endpoints and the Azure AD/Entra migration itself |

# 3. Container Supply Chain & Firmware OTA

| Work item | Device team | Cloud team |
|---|---|---|
| Container signature verification | Done --- `cosign`, `container-ota-agent.py` | Owns publishing signed images to whatever registry is chosen |
| Registry decision (ACR vs. registry-agnostic OCI) | Consumes whichever registry API is decided | Owns the decision and the CI/CD build-sign-push pipeline. **Flag vendor lock-in risk before committing to ACR literally.** |
| MQTT vs. TR-069 trigger decision | Owns whichever client path is chosen (`kms-mqtt-trigger` exists; `CcspTr069Pa` exists but unwired to containers) | Owns the ACS/MQTT-broker side of whichever path is chosen, plus status-reporting ingestion |
| OTA firmware repository / distribution | Owns OSTree pull/verify logic (already built) | Owns hosting the OSTree remote and its transport security (mTLS/HTTPS) |
| Cloud MQTT Broker | Owns client integration only | Fully cloud infra --- broker, mTLS termination, topic ACLs |

# 4. Namespace Isolation (otns / dmzns / itns)

| Work item | Device team | Cloud team |
|---|---|---|
| LXC/Podman namespace split, SELinux types | Fully device/platform team --- OS-level partitioning work | None directly, but defines what each namespace is allowed to reach |
| Per-namespace cloud endpoint routing (RADIUS/LDAPS/MQTT/TR-069) | Owns nftables/routing rules per namespace | Owns making each cloud service reachable/segmented appropriately (e.g. separate LDAPS instances per §2) |

# 5. Logging, Monitoring, SIEM

| Work item | Device team | Cloud team |
|---|---|---|
| Security event / log forwarding | Owns wiring rsyslog/journald (or adding a Wazuh agent) to forward off-device | Owns the SIEM/log collector receiving it |
| Metrics / health / heartbeat to cloud | Owns extending `ha-metrics` (currently loopback-only) to emit outward | Owns the Monitoring/Alerting service and dashboards |
| Fleet Analytics, Backup/Disaster Recovery | None | Fully cloud/ops |

# 6. Device Management Protocol (TR-069 → TR-369)

| Work item | Device team | Cloud team |
|---|---|---|
| Protocol decision (stay CWMP vs. move to USP) | Provides input on the cost of replacing the working `CcspTr069Pa` stack | Owns the ACS/DMS platform decision and the device-management portal. **Needs explicit sign-off from the target-design owner --- this changes the target, not just the implementation plan.** |

# 7. Cross-team interface contracts (blocking dependencies)

These are the interfaces that must be agreed before either side can
build independently of the other:

1. CSR/cert issuance & revocation-status API shape (§1)
2. RADIUS forwarding target + shared-secret provisioning process (§2)
3. MQTT topic/message schema for OTA triggers and telemetry (§3, §5)
4. Registry credential/auth contract, whichever registry is chosen (§3)
5. Namespace-to-cloud-endpoint mapping (§4)
6. TR-069 vs. TR-369 parameter data model, if that decision is made (§6)

# 8. Sources

Companion document: `2026-09-07-target-architecture-gap-analysis.md`,
which this matrix is derived from item-for-item. No new gap claims are
introduced here beyond that document's findings.
