# IT/OT Separation Security Architecture Design

**LXC Namespace Model with DMZ SSH/SSSD Gateway**  
**Design Version:** 0.3  
**Date:** 2026-09-03

> Public version: passwords, tokens, private keys, and other credentials are intentionally omitted.

## 1. Executive Summary

This document defines an IT/OT separation architecture for an AIoT gateway using Linux LXC containers and separate namespaces. OT, DMZ, and IT workloads are separated into dedicated LXC zones while a minimal privileged Host remains the trusted control plane.

Remote SSH access terminates in the DMZ LXC. The DMZ runs `sshd`, PAM, and SSSD and performs LDAP authentication. The DMZ must not be given privileges that allow it to directly enter or manage sibling LXC namespaces. Cross-zone authorization and namespace transition are controlled by a Host-side Login Broker.

The current implementation stage does **not** require Host-side password re-authentication. The Host independently resolves current user identity and LDAP group membership through Host-side SSSD/NSS and applies Host-owned RBAC before permitting a requested target zone.

## 2. Security Objectives

- Separate OT, DMZ, and IT runtime environments using LXC namespaces.
- Prevent direct OT-to-IT Layer-2/Layer-3 bypass paths.
- Use the DMZ as the normal remote SSH ingress point.
- Keep LXC lifecycle, namespace transition, OVS, firewall, SELinux, and other high-impact controls on the Host.
- Do not trust UID, GID, role, container name, or session ID supplied by the DMZ.
- Apply role-to-zone authorization on the Host.
- Provide cross-zone management visibility to Host Admin.
- Provide cross-zone read-only visibility to Auditor.
- Audit authentication, authorization, service operations, and namespace transitions.

## 3. Zone and Component Placement

| Zone | Primary Components | Security Constraint |
|---|---|---|
| OT LXC (`otns`) | EdgeX Core/Device Services, ChirpStack, OT MQTT, OT-local DB/cache, assigned OT interfaces | No direct IT administrative access; no Host-management capability |
| DMZ LXC (`dmzns`) | `sshd`, PAM, SSSD, management WebUI, MQTT bridge/relay | Remote authentication ingress; no sibling-container management capability |
| IT LXC (`itns`) | EdgeX application services, transform/export, northbound integrations | No direct OT device access |
| Host | Kernel, LXC, OVS, inter-zone firewall, SELinux, cgroups, Host SSSD, Login Broker, audit controls | Trusted control plane; only location permitted to perform sibling-LXC namespace transition |

## 4. Network Separation and Conduits

The Host enforces inter-zone communication policy. OVS provides connectivity but must not create an unrestricted shared Layer-2 broadcast domain between OT, DMZ, and IT.

| Source | Destination | Default | Typical Exception |
|---|---|---|---|
| OT | IT | DENY | None; use OT → DMZ → IT mediated path |
| IT | OT | DENY | Explicitly approved command/API path only if required |
| OT | DMZ | DENY except allowlist | MQTT/TLS or approved telemetry |
| DMZ | IT | DENY except allowlist | MQTT/TLS or approved northbound API |
| DMZ | Host | DENY except broker interface | Host Login Broker interface only |
| External management | DMZ | DENY except management allowlist | SSH/HTTPS from approved management networks |

## 5. RBAC Model

| Role | Login Location | Visibility | Modification Scope | Namespace Transition |
|---|---|---|---|---|
| OT Admin | OT LXC | OT only | OT services/configuration | No |
| DMZ Admin | DMZ LXC | DMZ only | DMZ services/configuration | No |
| IT Admin | IT LXC | IT only | IT services/configuration | No |
| OT Operator | OT LXC | OT only | Limited operational actions | No |
| Host Admin | Host | Host + OT + DMZ + IT | Administrative control subject to policy | Controlled/allowed |
| Auditor | Host | Host + OT + DMZ + IT | Read-only | No interactive transition |

### 5.1 LDAP Groups and Test Accounts

| LDAP Group | Test User | Role | Authorized Scope |
|---|---|---|---|
| `ot-admin` | `otadmin01` | OT Admin | OT namespace |
| `dmz-admin` | `dmzadmin01` | DMZ Admin | DMZ namespace |
| `it-admin` | `itadmin01` | IT Admin | IT namespace |
| `ot-operator` | `otoperator01` | OT Operator | OT namespace, limited operational privileges |
| `host-admin` | `hostadmin01` | Host Admin | Host and controlled cross-zone management |
| `auditor` | `auditor01` | Auditor | Host and read-only cross-zone visibility |

Credentials are intentionally excluded from this public repository. Production deployments must use unique per-user credentials and must not ship with shared default passwords.

## 6. Remote Login Flow

1. User connects to the gateway management address using SSH.
2. The connection terminates at `sshd` in the DMZ LXC.
3. `sshd` invokes PAM/SSSD and authenticates the user against LDAP/AD over TLS.
4. After successful authentication, `sshd` invokes a controlled login helper/`ForceCommand` rather than giving the user arbitrary cross-zone capability.
5. The helper sends only the minimum request information to the Host Login Broker, for example `username` and `requested_target`.
6. The Host treats DMZ-supplied UID, GID, role, container name, privilege level, command line, and session ID as untrusted.
7. Host-side SSSD/NSS independently resolves the current account, UID/GID, group membership, and account status.
8. The Host applies Host-owned RBAC to the requested target.
9. The Host generates its own session ID.
10. For OT/IT users, the Host creates the session in the approved LXC using controlled LXC/namespace tooling. Host Admin and Auditor remain on the Host.

## 7. Host Login Broker

The Host Login Broker is a small privileged service and must not be a general remote-command daemon.

### 7.1 Minimal Request Contract

The DMZ helper may request:

```text
username=alice
requested_target=OT
```

The following values must not be accepted as authoritative from the DMZ:

- UID
- GID
- LDAP groups/role
- container name
- PID
- arbitrary command
- privilege level
- session ID

### 7.2 Host-side Verification

For the current implementation stage, the Host does not prompt for the LDAP password again. It performs independent identity and authorization lookup through Host-side SSSD/NSS/LDAP.

Conceptual flow:

```text
getpwnam(user)
getgrouplist(user)
verify account state
verify required LDAP group for requested target
generate Host-owned session ID
apply fixed role-to-target mapping
```

### 7.3 Authorization Mapping

| Verified LDAP Group | Allowed Target | Host Action |
|---|---|---|
| `ot-admin` | OT | Attach to `otns` as verified non-root user |
| `ot-operator` | OT | Attach to `otns` with restricted operational privilege |
| `it-admin` | IT | Attach to `itns` as verified non-root user |
| `dmz-admin` | DMZ | Use DMZ administrative environment |
| `host-admin` | Host | Host administrative session |
| `auditor` | Host | Constrained read-only audit session |

A target that does not match the verified LDAP group must be denied.

## 8. Current Threat-model Limitation

Because Host-side password re-authentication is deferred in this stage, Host-side LDAP lookup can prove that a named account exists and currently has a specific role, but it does not cryptographically prove that the broker request corresponds to a freshly authenticated human SSH session if the DMZ itself is fully compromised as root.

Current controls should therefore include:

- DMZ `ForceCommand` or equivalent controlled login helper.
- Narrow Unix-domain broker interface.
- Unix socket ownership/mode restrictions.
- `SO_PEERCRED` for helper-process validation.
- SELinux confinement of the DMZ helper and Host Broker.
- Host-side independent LDAP/NSS lookup.
- Host-generated session IDs.
- No arbitrary `nsenter`, `lxc-attach`, Host `/proc`, Host D-Bus, LXC control socket, or equivalent capabilities exposed to DMZ.

A future security enhancement may introduce Host-side re-authentication, SSH user certificates, or a signed per-session assertion if protection against a fully compromised DMZ becomes a requirement.

## 9. Host Admin Model

Host Admin logs into the Host management plane and does not need to SSH independently into every LXC for normal management.

The Host may inspect/manage LXC workloads using controlled Host-side tooling, for example:

```bash
lxc-info -n otns
lxc-attach -n otns -- systemctl status mosquitto
lxc-attach -n otns -- systemctl restart mosquitto
lxc-attach -n itns -- systemctl status edgex-app-service
lxc-attach -n dmzns -- journalctl -u sshd
```

Interactive `lxc-attach` should be reserved for troubleshooting and tightly controlled.

## 10. Auditor Model

Auditor logs into the Host but receives cross-zone **read-only** audit capability.

The preferred design is a Host-side read-only audit interface that can inspect:

- Host/OT/DMZ/IT logs
- service status
- approved configuration files
- file hashes/metadata
- CPU/memory/cgroup status
- process inventory
- network interfaces/routes/listening ports
- container state

Auditor must not receive:

- unrestricted `sudo`
- arbitrary `lxc-attach`
- arbitrary `nsenter`
- configuration write capability
- service restart capability
- firewall/network modification capability

## 11. Service Management

The Host can operate services in an LXC without SSHing into that LXC.

Examples:

```bash
lxc-attach -n otns -- systemctl restart mosquitto
lxc-attach -n itns -- systemctl status edgex-app-service
lxc-attach -n dmzns -- journalctl -u sshd
```

For non-Host roles, use allowlisted wrappers instead of exposing arbitrary `lxc-attach`.

## 12. Host and Broker Hardening

| Control | Requirement |
|---|---|
| Broker endpoint | Expose only a narrow broker socket/API to DMZ |
| Host interfaces | Do not expose Host `/proc`, `/run/lxc`, Host D-Bus, Docker/Podman sockets, or equivalent broad control surfaces |
| Caller validation | Use Unix-socket permissions and `SO_PEERCRED` for service-level validation |
| Input validation | Accept fixed target enums only; reject arbitrary PID/container/command/path/UID/GID/role |
| Execution | Use fixed argument vectors; do not construct shell commands from client input |
| SELinux | Run the broker in a dedicated confined domain with minimum required privileges |
| Audit | Record allow/deny, user, LDAP groups, target, source, Host session ID, start/end, and administrative action |
| Rate limiting | Limit repeated authentication and broker attempts |

## 13. Audit Events

At minimum retain:

- SSH connection accept/reject and source address
- PAM/SSSD authentication result, excluding passwords
- Host Broker identity/group lookup result
- authorization allow/deny result
- requested and resolved target zone
- Host-generated session ID
- LXC session start/end
- service restart/configuration changes
- Auditor read operations where required
- relevant firewall/SELinux denials

## 14. LDAP Availability Policy

The current design depends on DMZ-side LDAP authentication and Host-side LDAP/SSSD identity/group lookup. The product must define an explicit outage/island-mode policy.

Recommended default: fail closed for new cross-zone administrative sessions when sufficiently current account/group information cannot be obtained. If cached SSSD identity/group data is permitted, its validity period, revocation behavior, and emergency-use policy must be documented and auditable.

## 15. Security Verification Tests

| ID | Test | Expected Result |
|---|---|---|
| T01 | Valid OT Admin requests OT | Allowed; session lands in `otns` |
| T02 | IT Admin requests OT | Denied |
| T03 | DMZ supplies fake UID/GID/root | Ignored; Host derives identity via NSS/SSSD |
| T04 | DMZ supplies fake Host Admin role | Ignored/denied; Host uses current LDAP groups |
| T05 | Client requests arbitrary PID/container | Rejected |
| T06 | DMZ user attempts sibling namespace entry | Denied by capability/namespace/SELinux design |
| T07 | Auditor attempts service restart/config write | Denied and audited |
| T08 | Host Admin controls approved LXC service | Allowed and audited |
| T09 | Direct OT-to-IT network bypass | Dropped |
| T10 | LDAP account disabled/group removed | New access denied after current Host lookup |
| T11 | LDAP unavailable | Behavior matches documented fail-closed/cache policy |

## 16. Deployment Checklist

- Create `otns`, `dmzns`, and `itns` LXC containers.
- Configure non-overlapping user namespace ID mappings where applicable.
- Place `sshd`, PAM, and SSSD in `dmzns`.
- Restrict normal remote SSH ingress to `dmzns`.
- Configure LDAP/AD connectivity over TLS.
- Install Host-side SSSD/NSS for independent identity/group lookup.
- Implement the Host Login Broker and narrow DMZ-to-Host broker interface.
- Implement fixed Host-owned group-to-target RBAC mapping.
- Constrain helper/broker processes using SELinux and filesystem/socket permissions.
- Enforce OVS/VLAN/firewall policy with no OT↔IT bypass path.
- Implement Host Admin and read-only Auditor profiles.
- Centralize/forward security logs and validate retention.
- Execute the verification test plan before release.

## 17. Architecture Decision

The selected architecture uses LXC namespaces to enforce IT/OT/DMZ runtime separation. `sshd`, PAM, and SSSD reside in the DMZ and provide the common remote LDAP authentication ingress. The Host remains the sole namespace-control authority.

For the current implementation stage, Host-side LDAP password re-authentication is deferred. The Host independently resolves current LDAP/NSS identity and group membership, applies Host-owned RBAC, generates the session ID, and alone performs controlled namespace/LXC transitions.

**Key rule:** the DMZ may request a target zone, but it does not authoritatively define UID, GID, role, privilege, container, command, or session identity. The Host derives and enforces those attributes from trusted Host-side sources and policy.