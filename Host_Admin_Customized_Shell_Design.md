# Host Admin Customized Shell Design

_IT OT Separation SSHD RBAC_

| **Document status** | Design baseline   |
|---------------------|-------------------|
| **Version**         | 1.6               |
| **Date**            | 15 September 2026 |
| **Role**            | host-admin        |
| **Target plane**    | DUT Host plane    |

**Decision summary.** The host-admin receives a forced, allowlist-based administration shell on the Host plane. The role can manage approved Host networking, accounts, services, RDK-B parameters, approved Host configuration and Host certificates. It can harvest logs and inspect redacted configuration from ITns, OTns and DMZns, but cannot modify those namespaces.

Delivery uses two phases while preserving one command grammar, one policy model and one audit schema. Phase 1 uses the unprivileged customized shell with one root-owned privileged helper. Phase 2 replaces that execution path with one confined UNIX-socket broker. Approved Host configuration may be edited with restricted Vim only on a user-owned staging copy; the helper or broker independently validates and atomically installs it. Neither phase provides an unrestricted root shell. At login and whenever the prompt is redisplayed, the shell shows only the mapped local account, numeric UID and current system time in UTC with minute precision. The time does not tick while the shell waits for input.

## 1 Purpose and Scope

This document specifies the customized shell and two-phase privileged execution design for the host-admin role. It defines the role boundary, permitted commands, protected resources, controlled Host configuration editing, cross-namespace read access, audit behavior, migration requirements and acceptance criteria. It is intended for the SSHD, RBAC, platform security, RDK-B, networking and test teams.

### 1.1 System context

The DUT separates Host, ITns, OTns and DMZns into distinct security planes. A host administrator reaches the Host plane only through DMZNS. Online access starts with LDAP password authentication to DMZNS; offline access starts with a DMZNS SSH certificate. Both paths use a separate Host-plane certificate for the second hop and terminate as the local hostadmin identity.

### 1.2 Goals

- Provide the host-admin with sufficient Host-plane administration and troubleshooting capability.

- Prevent shell escape, arbitrary root command execution and cross-plane privilege expansion.

- Allow read-only configuration inspection and controlled log harvesting from ITns, OTns and DMZns.

- Protect audit logs, system time, CA trust and private-key material.

- Produce deterministic, attributable audit records for every operation.

- Deliver Phase 1 with one privileged helper and migrate to the Phase 2 broker without changing the user command grammar, role permissions or audit schema.

- Permit restricted Vim editing only for approved Host configuration IDs through a validated staging workflow.

- Display only the mapped local account, numeric UID and freshly read UTC system time in every command prompt. The authenticated human identity remains audit-only.

### 1.3 Non goals

- Administering applications or configuration inside ITns, OTns or DMZns.

- Managing Enterprise LDAP or Active Directory identities.

- Providing a general-purpose root, sudo, container or namespace shell.

- Revoking or deleting certificates, administering a CA, or exporting private keys.

- Changing system time, audit policy, log retention or evidence files.


## 2 Design Decisions

| **ID** | **Decision** | **Design rule** |
|--------|--------------|-----------------|
| D1 | Forced command shell | Host SSHD starts the customized shell for hostadmin. User-supplied commands are parsed by an exact grammar and are never passed to a POSIX shell. |
| D2 | Two-phase privileged execution | Phase 1 uses one root-owned helper; Phase 2 uses one privileged UNIX-socket broker. Both consume the same canonical action schema and server-owned policy. |
| D3 | Unprivileged interactive shell | The customized shell and configuration editor run as the authenticated hostadmin UID with no inherited capabilities or privileged groups. |
| D4 | Host-plane write boundary | host-admin can change approved Host resources and host-side inter-zone enforcement, but cannot change configuration inside ITns, OTns or DMZns. |
| D5 | Cross-namespace read gateway | host-admin may harvest approved logs and inspect approved redacted configuration from all namespaces through a dedicated read-only gateway. |
| D6 | No raw high-risk tools | Write-capable nft, tc, ebtables, systemctl, dmcli and account-management operations are exposed only as validated actions. |
| D7 | Controlled Host configuration editing | Configuration is selected by logical config ID, edited only as a user-owned staging copy, independently validated and atomically installed by the privileged execution backend. |
| D8 | Restricted Vim is transitional | Phase 1 may use restricted Vim for the staging copy only. Vim never runs as root and is not the authorization or installation boundary. |
| D9 | Protected evidence | Logs and time are readable but immutable to host-admin. Malformed, denied, successful and failed requests are audited. |
| D10 | Constrained certificate renewal | host-admin may renew the fixed Host-plane device certificate, but cannot choose identity, CA role, principal, TTL or key export behavior. |
| D11 | Stable migration contract | Command syntax, action IDs, validators, role policy, event IDs and audit fields remain compatible across both phases. |
| D12 | Trusted prompt identity and time | The prompt displays only the mapped local account, numeric UID and current UTC system time with minute precision. It refreshes at login, after Enter is submitted and after command completion; it does not tick while input is active. Values come from trusted sources and cannot be supplied by the user. The human account remains in protected audit data only. |
| D13 | Configuration-edit-first gate | Phase 1 implements and accepts the complete Host configuration edit transaction before enabling other state-changing Phase 1 domains. |

*Table 1 Core design decisions*


## 3 Architecture

The interactive customized shell remains unprivileged in both phases. It parses one command using an exact grammar, converts it to a canonical action and never evaluates user input through /bin/sh. Privileged execution is isolated behind a stable executor interface.

### 3.1 Phase 1 architecture: single privileged helper

Phase 1 uses one root-owned executable, /usr/libexec/host-admin-helper. The customized shell invokes only this fixed helper through the approved local privilege-delegation mechanism. The helper dispatches internally to purpose-built action handlers, revalidates role, action and parameters, performs the operation and writes protected audit records. A user cannot request an executable path or arbitrary command string.

~~~mermaid
flowchart TD
    A[Human administrator] --> B[DMZNS SSHD]
    B --> C[Host SSHD]
    C --> D[Unprivileged host-admin shell]
    D --> E[Single privileged helper]
    E --> F[Host action handlers]
    E --> G[Namespace read gateway]
    E --> H[Protected audit pipeline]
    F --> H
    G --> H
~~~

*Figure 1 Phase 1 customized shell and single-helper architecture*

### 3.2 Phase 2 architecture: privileged broker

Phase 2 keeps the shell grammar and handler contract but sends the canonical request over a local UNIX domain socket to host-admin-brokerd. The broker verifies socket peer credentials, resolves the protected server-side role policy and dispatches the same logical actions. The Phase 1 helper entry point is then removed from the active execution path.

~~~mermaid
flowchart TD
    A[Unprivileged host-admin shell] --> B[Canonical action request]
    B --> C[Privileged broker]
    C --> D[Host action handlers]
    C --> E[Namespace read gateway]
    C --> F[Protected audit pipeline]
    D --> F
    E --> F
~~~

*Figure 2 Phase 2 broker architecture*

| **Component** | **Phase** | **Responsibility** |
|---------------|-----------|--------------------|
| Host SSHD | Both | Authenticates the Host-plane SSH certificate and starts the approved existing session path. This document does not modify SSHD configuration. |
| host-admin-shell | Both | Unprivileged front end. Displays the mapped local account, UID and current UTC minute, displays help, parses exact syntax, creates canonical actions, manages staging interaction and returns bounded results. |
| host-admin-helper | Phase 1 | Single root-owned privileged executable. Revalidates identity, role, action and parameters and dispatches one internal handler. It accepts no arbitrary command. |
| host-admin-brokerd | Phase 2 | Privileged policy enforcement point. Verifies UNIX peer credentials, resolves server-side authorization, enforces limits and dispatches handlers. |
| Host action handlers | Both | Internal modules that implement network, firewall, account, service, RDK-B, diagnostics and approved Host configuration transactions; they are not user-selectable executables. |
| Namespace read gateway | Both | Reads allowlisted logs and redacted configuration from ITns, OTns and DMZns without exposing a namespace shell. |
| Configuration staging manager | Both | Internal helper/broker module that maps approved config IDs, creates isolated edit transactions, validates candidates, records hashes, installs atomically and rolls back on failure. |
| Certificate handler | Both | Uses a TPM-backed key, creates a fixed-identity CSR, requests renewal and installs validated certificate material. |
| Audit pipeline | Both | Stores protected request, decision, state-change and result records outside host-admin control. |

*Table 2 Component responsibilities*


### 3.3 Common authorization flow

1. Host SSHD validates the Host-plane user certificate and device-bound principal host-admin@kms-<device-id> using the approved current SSHD configuration.

2. SSHD maps the session to the locked local account hostadmin and starts the customized shell.

3. The shell obtains the mapped local account and numeric UID from protected identity mapping for the visible prompt. It separately retains the verified human account from authenticated session context for protected audit records. None of these values are read from user command input or user-controlled environment variables.

4. At initial login, the shell reads the system clock, converts it to UTC minute precision and renders the fixed prompt format defined in Section 5.1.

5. The shell records SSH context and parses one permitted command without invoking /bin/sh.

6. The shell converts the command into a canonical action containing an action ID and typed parameters. The request cannot select a role, identity, executable or arbitrary filesystem path.

7. In Phase 1, the single helper derives the original authenticated UID from the protected invocation context and resolves the server-owned role policy. In Phase 2, the broker derives the UID from UNIX peer credentials and resolves the same policy.

8. The selected handler independently validates resource IDs, candidate files, values, limits and protected invariants before performing an operation.

9. The trusted audit path independently generates its own event timestamp and records the authorization decision, operation result and applicable before/after state, hashes and rollback status.

10. When Enter is submitted, the shell processes the entered command. An empty command immediately causes a refreshed prompt. After a non-empty command succeeds, fails or is denied, the shell reads the clock again and displays a new prompt with the same verified identity and updated UTC minute.

## 4 Host Admin Permission Model

| **Capability**               | **Permitted**                                                                                        | **Mandatory restriction**                                                                                                        |
|------------------------------|------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| Network configuration        | View and change approved Host interfaces, routes, DNS, Wi-Fi, BLE and cellular settings.             | Interface and property allowlists; no arbitrary bridge, tunnel or namespace link.                                                |
| Firewall and traffic control | List, validate, apply and roll back approved nftables and tc policies.                               | Cannot remove mandatory default-drop, zone-isolation or audit rules; no raw write-capable nft, tc or ebtables.                   |
| Host configuration           | View and update approved files such as /etc/hosts and approved network, SSHD and SSSD configuration. | Config-ID allowlist, staged edit, syntax and invariant validation, atomic installation and rollback; secret-bearing files require structured non-secret fields or remain read-only. |
| Network diagnostics          | Use bounded ip, ss, ping, traceroute, dig, nslookup and tcpdump functions.                           | Target, interface, duration, packet count and output path limits; ifconfig and netstat are compatibility read-only views.        |
| Account lifecycle            | Create, suspend, resume and retire approved Host-local accounts.                                     | No UID or GID 0, sudo, privileged groups, arbitrary shell, LDAP or AD administration, or immediate evidence-destroying deletion. |
| Service control              | View status, reload and restart allowlisted Host services.                                           | No stop, disable, mask, arbitrary unit, transient unit or uncontrolled restart loop.                                             |
| System diagnostics           | View processes, resource usage, storage, uptime, hardware and approved kernel status.                | No arbitrary process execution, signal delivery, kernel modules, mount changes or protected sysctl writes.                       |
| RDK-B parameters             | Get and set allowlisted RDK-B parameters.                                                            | Type and range validation; security-disable, secret, factory-reset and unrestricted remote-access parameters are denied.         |
| Namespace logs               | Harvest approved logs from Host, ITns, OTns and DMZns; monitor and export collection jobs.           | Read-only source access, bounded bundles, integrity manifest and no lxc-attach, lxc exec or nsenter exposed to the user.         |
| Namespace configuration      | List, view, compare and export redacted approved configuration from ITns, OTns and DMZns.            | No write operation, arbitrary path, secret material, process environment or private-key access.                                  |
| Audit logs                   | Read, search and export approved host audit and system logs.                                         | Cannot delete, truncate, alter, rename, change permissions or change audit and retention policy.                                 |
| Time                         | View clock, timezone, RTC and synchronization status.                                                | Cannot set time or timezone, force NTP steps or change time-source configuration.                                                |
| Host certificate             | View status and renew or reissue the fixed Host-plane device certificate.                            | Cannot revoke, delete, issue user certificates, modify CA trust, choose arbitrary identity or export private keys.               |

*Table 3 Host admin authorization matrix*

### 4.1 Explicitly denied operations

- Start bash, sh, a scripting interpreter or any unrestricted command executor.

- Use sudo, su, lxc-attach, lxc exec, nsenter, podman exec or an equivalent namespace entry mechanism.

- Use shell metacharacters, pipelines, redirection, command substitution, glob expansion or user-controlled environment variables.

- Modify host-admin policy, broker binaries, SELinux policy, sudoers, AuthorizedPrincipalsFile, trusted SSH CA files or authorized_keys.

- Change configuration or service state inside ITns, OTns or DMZns.

- Delete or alter source logs, harvested evidence, audit records or integrity manifests.

- Stop, disable or mask required services; reboot, shut down, factory reset, install packages or update firmware.

- Change system time or audit configuration; revoke certificates or export TPM/private keys.


## 5 Command Interface

The shell exposes a namespaced command grammar. The parser accepts only documented tokens and option combinations. Unknown verbs, duplicate options, invalid identifiers, unsupported values, overlong input and shell metacharacters are rejected before privileged execution. The same syntax is mandatory in both phases.

### 5.1 Shell prompt

The prompt shall display only the mapped local account, numeric UID and current system time in UTC with minute precision. The verified human account is intentionally not displayed and remains available only to the protected audit path. The fixed format is:

~~~text
<local-account>:<uid> [<YYYY-MM-DDTHH:MMZ>] hostctl>
~~~

Example:

~~~text
hostadmin:10000 [2026-09-15T09:42Z] hostctl>
~~~

The displayed time is a prompt snapshot, not a live clock. It is generated at initial login and refreshed when Enter is submitted: an empty command redraws it immediately, while a non-empty command redraws it after the command completes, fails or is denied. It does not tick or redraw while the administrator is typing or while a command is running. Minute precision is required for the prompt; audit records independently retain UTC RFC 3339 timestamps with sub-second precision. The literal Z timezone marker is required so the displayed time cannot be confused with local time.

No background ticker, timerfd, periodic signal or asynchronous ANSI status-line redraw is required. A normal blocking input loop is sufficient.

The local account and UID displayed in the prompt shall be obtained from protected identity mapping. The human account shall be obtained from authenticated session context for audit use but shall not be rendered in the prompt. User input, environment variables, terminal escape sequences and configuration-editor content cannot override either identity context. Visible prompt fields shall use a restricted character set and fixed formatting so account data cannot inject terminal control characters.

The displayed timestamp is informational and shall not be copied into the audit record. The protected audit path independently reads the system UTC clock when creating each event. host-admin may view clock synchronization status through hostctl time status but cannot set time, timezone or the time source.

### 5.2 Command grammar

~~~text
hostctl network status
hostctl network interface show [<interface>]
hostctl network interface set-state <interface> <up|down>
hostctl network route show
hostctl firewall show
hostctl firewall validate <staged-policy-id>
hostctl firewall apply <validated-change-id>
hostctl firewall rollback <change-id>
hostctl config list
hostctl config show <approved-host-config-id>
hostctl config edit <approved-host-config-id>
hostctl config validate <edit-request-id>
hostctl config diff <edit-request-id>
hostctl config apply <edit-request-id>
hostctl config discard <edit-request-id>
hostctl diagnose ping <destination> [--count <1..20>]
hostctl diagnose capture <interface> --duration <1..300> [--filter <approved-filter>]
hostctl account <list|add|suspend|resume|retire> [<user>]
hostctl service <status|reload|restart> <approved-service>
hostctl rdkb get <approved-parameter>
hostctl rdkb set <approved-parameter> <validated-value>
hostctl logs harvest <host|itns|otns|dmzns|all> [--since <time>] [--until <time>]
hostctl logs job-status <job-id>
hostctl logs export <job-id>
hostctl namespace config <list|show|diff|export> <itns|otns|dmzns> [<config-id>]
hostctl time status
hostctl certificate <status|renew> --plane host
hostctl help [<domain>]
hostctl exit
~~~

| **Command domain** | **Logical handler** | **Resource** | **Access mode** |
|--------------------|---------------------|--------------|-----------------|
| network | net-handler | Host interfaces and routes | Read and constrained write |
| firewall | firewall-handler | Host and boundary policy | Validated transaction only |
| config | config-handler | Approved Host configuration IDs | Staged edit, validate, diff and atomic apply |
| diagnose | diagnostic-handler | Network and system observations | Bounded execution and output |
| account | account-handler | Approved Host-local identities | Lifecycle operation only |
| service | service-handler | Allowlisted Host units | Status, reload or restart |
| rdkb | rdkb-handler | Allowlisted parameters | Typed get or set |
| logs | log-harvest-handler | Host and namespace log sources | Read, package and export |
| namespace config | namespace-read-handler | Approved redacted configuration | Read-only |
| time | time-status-handler | Clock and synchronization status | Read-only |
| certificate | cert-renew-handler | Host-plane certificate | Status and fixed-policy renewal |

In Phase 1 these handlers are internal dispatch functions of the single helper. In Phase 2 they are reached through broker dispatch. Their action names and validation rules do not change.

*Table 4 Command to handler mapping*

## 6 Detailed Functional Design

### 6.1 Network and firewall changes

Network changes are policy transactions rather than direct execution of networking binaries. The handler loads a staged change by ID, checks its schema, validates interface and address ownership, verifies protected isolation invariants and performs a dry-run where supported. After applying the change, it verifies the expected management path and stores the prior state for rollback.

- Mandatory rules include WAN SSH denial, zone default-drop behavior, management-path allowlists and audit logging.

- The administrator cannot supply an arbitrary nftables script, executable path or output destination.

- A failed health check triggers automatic rollback and a high-severity audit event.

- ebtables compatibility is read-only; new bridging policy should be implemented with nftables where supported.


### 6.2 Approved Host configuration changes

Approved Host configuration is addressed only by logical configuration ID. Raw destination paths are never accepted from the user. The policy maps each config ID to one canonical target, validator, protected directives, ownership, mode, SELinux label, health check and rollback rule. ITns, OTns and DMZns configuration IDs remain read-only under Section 6.6.

#### 6.2.1 Edit transaction

1. The administrator runs hostctl config edit <approved-host-config-id>.

2. The privileged execution backend authorizes the config ID, captures the original file identity and SHA-256 hash and creates an opaque edit-request ID.

3. It creates a transaction directory under /run/custom-shell/edit/<uid>/<edit-request-id> with mode 0700 and a candidate regular file with mode 0600 owned by the authenticated user. Root-owned transaction metadata is stored separately and is not writable by that user.

4. The customized shell launches restricted Vim only for that exact candidate. Vim runs permanently as the authenticated UID, with no capabilities or privileged supplementary groups. It never opens the protected destination directly.

5. When Vim exits, no installation occurs automatically. The administrator may run config validate and config diff, then explicitly run config apply or config discard.

#### 6.2.2 Restricted Vim profile

The approved Phase 1 invocation is equivalent to:

~~~text
/usr/bin/vim -Z -n -X -u /etc/custom-shell/vimrc -U NONE --noplugin -i NONE -- <candidate>
~~~

The root-owned profile shall disable modelines, user plugins, user startup files, shell and filter escapes, external commands, swap files and user-controlled editor environment. The candidate path is supplied by the staging manager, not by the user. Because restricted Vim alone is not a complete filesystem sandbox, a dedicated SELinux editor domain shall permit writing only the assigned candidate and deny other configuration, audit, policy, key and executable paths.

Restricted Vim is a transitional usability control, not the privilege boundary. If an editor escape or alternate-file command is attempted, the process remains confined to the unprivileged hostadmin UID and the dedicated editor domain. The helper still reauthorizes every action and cannot execute an arbitrary command. Phase 2 may retain the same staging editor or replace it with a smaller built-in editor without changing config action semantics.

#### 6.2.3 Validation and installation

Before apply, the helper or broker shall:

- Revalidate caller UID, role, config ID, request ownership and transaction lifetime.

- Open the transaction through fixed directory file descriptors, reject symlinks, require a regular file with the expected UID and mode and prevent path traversal or replacement.

- Confirm that the protected target still matches the original identity and hash, or reject the request as a concurrent modification.

- Enforce file-size, encoding, schema, secret-handling and protected-directive rules.

- Run the native validator where applicable, such as SSHD, SSSD, nftables or systemd validation.

- Record a redacted diff and old/new hashes, create a protected versioned backup and install through an atomic same-filesystem replacement.

- Restore the required owner, group, mode and SELinux label.

- Run the configured health check and automatically restore the prior version if validation, activation or health checking fails.

Full-file Vim editing is allowed only when the candidate does not disclose protected credentials or private material. For a mixed configuration that contains protected secrets, the config ID shall expose only structured non-secret fields and preserve secret fields inside the privileged backend, or the config ID shall remain read-only.

Configuration apply and service reload or restart are separate authorized actions unless the protected policy explicitly defines one atomic transaction. The current deployed SSHD configuration is not changed by adopting this design; only a future host-admin action against an approved SSHD config ID may change it after implementation and separate authorization.

### 6.3 Service restart

A restart contains a short stop phase, but host-admin is not given an independent stop operation. The service handler accepts only an allowlisted unit, rate-limits requests, records its prior state, executes restart, waits for active state and runs the configured health check. The action fails closed when the unit name is aliased, templated or not listed in policy.

### 6.4 Account lifecycle

The account handler manages only approved Host-local accounts. Enterprise LDAP and Active Directory identities remain centrally managed. Add operations enforce allocated UID and GID ranges, a fixed home root and an approved login shell. Suspend locks authentication without removing ownership metadata. Retire disables the account and archives metadata; irreversible deletion is outside this role.

### 6.5 Cross namespace log harvesting

The host-admin role may initiate, monitor and export log-harvesting jobs from Host, ITns, OTns and DMZns. The privileged log-harvest handler reads only configured journal units and canonical file paths. Namespace entry, when technically required, occurs inside the trusted Phase 1 helper or Phase 2 broker and is never exposed as a user-controlled command.

| **Stage**  | **Requirement**                                                                                                  |
|------------|------------------------------------------------------------------------------------------------------------------|
| Request    | Namespace set, approved source or service, UTC time range, severity filter and bounded job limits.               |
| Collection | Read-only file descriptors; canonical paths; no symlink following; bounded duration, file count and total bytes. |
| Manifest   | DUT ID, namespace, boot ID, source, original timestamps, collection time, actor, session and SHA-256 hashes.     |
| Storage    | Protected spool owned by the privileged execution backend. The administrator receives an opaque job ID and read-only export stream. |
| Export     | Optional compression and signature; secrets and policy-defined sensitive fields are redacted before release.     |
| Retention  | Trusted-backend-controlled expiration. host-admin cannot delete original logs, bundles, manifests or audit records. |

*Table 5 Log harvesting requirements*

### 6.6 Cross namespace configuration visibility

Configuration visibility is read-only and uses logical configuration IDs. The namespace gateway can show effective values, compare the current state with the approved baseline and export a redacted snapshot. It does not accept raw paths and does not provide file ownership, permission or service-control operations inside a namespace.

- Allowed examples include interface, route, firewall, SSHD, SSSD where present, service and approved application configuration.

- Always protected content includes private keys, password hashes, Vault tokens, AppRole secrets, LDAP bind credentials, API tokens, Wi-Fi keys, /run/secrets and sensitive process environments.

- Every view, comparison and export records the namespace and configuration ID. OT configuration may require an additional policy approval or ticket reference.

### 6.7 RDK-B parameter management

The RDK-B handler maintains an allowlist of parameter names, operation type, data type, range, restart impact and redaction behavior. It does not pass user input directly to dmcli. Set operations record the old and new value unless the field is sensitive, in which case only a non-secret state transition and value hash are recorded.

### 6.8 Certificate renewal

Certificate renewal is limited to the DUT Host-plane certificate. The handler derives the device ID, plane, principal, target, Vault role and TTL from protected configuration. It validates the returned chain, identity, validity and key binding before atomic installation. The private key remains TPM-backed and is never returned to the administrator or written into the audit log.


## 7 Security Enforcement

| **Threat** | **Failure mode** | **Required control** |
|------------|------------------|----------------------|
| Shell escape | Pipes, redirection, substitution or interpreter execution reaches arbitrary commands. | No POSIX shell evaluation; exact grammar; no raw executable action; bounded output and fixed PAGER behavior. |
| Prompt spoofing | User-controlled identity, environment or control characters make the prompt show a false username or misleading time. | Identity from authenticated context, time from system UTC clock, restricted field character set, fixed formatting and no user overrides. |
| Editor escape | Vim escape or alternate-file commands bypass the customized-shell interface. | Restricted Vim on the candidate only, permanent unprivileged UID, dedicated SELinux editor domain, clean environment and independent helper/broker authorization. |
| Privileged editor | Vim or another general editor executes with elevated privilege. | Explicitly prohibited; the privileged backend prepares and applies, while the editor runs only as the authenticated user. |
| Helper abuse | A user invokes the Phase 1 helper outside the intended UI or supplies a hidden command. | One fixed helper, no exec/run-shell action, server-owned action table, independent role and parameter validation and protected audit. |
| Argument injection | A valid action is extended with a dangerous option or secondary command. | Typed grammar, option allowlist, no duplicate options and direct execve-style handler invocation with fixed executable paths. |
| Path traversal | A log or configuration request reaches an arbitrary file or secret. | Logical IDs, fixed directory descriptors, openat2-style resolution, no symlink following and no user-selected destination. |
| Staging tampering | A candidate or transaction is replaced between validation and installation. | Opaque request ID, protected metadata, ownership/mode checks, file-descriptor validation, hashes, transaction lock and atomic rename. |
| Cross-plane bypass | Host privilege modifies IT, OT or DMZ configuration. | Namespace read gateway, no namespace write action, no exposed setns/LXC command and SELinux confinement. |
| Audit tampering | Administrator changes time, logs or collection manifests. | No write capability to audit paths or time services; trusted logging path and remote forwarding where available. |
| Operational denial | Repeated restart, capture, edit or harvest actions exhaust resources. | Rate, concurrency, transaction, quota, timeout and bounded-output limits. |
| Credential exposure | Diagnostics, full-file staging or exports reveal secrets or private keys. | Config-ID allowlists, no full-file edit for secret-bearing files, structured non-secret fields, redaction, staging mode 0600 and no private-key API. |
| Broker impersonation | A local process submits Phase 2 requests as host-admin. | UNIX peer credentials, fixed socket ownership, authenticated session context and server-side UID-to-role mapping. |

*Table 6 Threats and required mitigations*

### 7.1 Common hardening

- Run the customized shell and restricted editor as the unprivileged hostadmin account with no privilege inheritance.

- Keep action tables, policies, helper/broker binaries, editor profile, validators and target mappings root-owned and integrity protected.

- Pin executable paths and reject user-controlled PATH, LD_PRELOAD, locale, editor and pager variables.

- Never call system(), popen(), /bin/sh -c or an equivalent shell-evaluation interface with user-controlled data.

- Return bounded output and sanitized errors without backend stack traces, tokens, private paths or secret values.

- Apply SELinux confinement to the shell, helper or broker, log-harvest path, staging area and audit path. A dedicated host_admin_editor_t domain shall allow the editor to write only its assigned candidate.

### 7.2 Phase 1 helper hardening

- Install exactly one root-owned privileged helper with an internal allowlisted action dispatcher.

- Permit only the fixed helper through the local privilege-delegation rule; do not expose general sudo, arbitrary arguments interpreted as commands or user-selected executable paths.

- Derive the original authenticated UID from the protected invocation context, resolve role server-side and treat direct helper invocation as an expected hostile path.

- Keep each action in a separate handler function with independent schema, authorization and resource limits.

- Write privileged operation results through the protected audit path. Malformed commands rejected by the shell are sent as sanitized rejection events to the protected logging service.

### 7.3 Phase 2 broker hardening

- Use a root-owned UNIX socket with peer-credential verification, fixed ownership and bounded canonical messages.

- Resolve UID-to-role mapping and policy inside the broker; do not trust role, UID or executable fields supplied by the client.

- Use systemd hardening, restrictive capability bounding sets, protected kernel tunables, cgroups, private temporary storage and explicit read-write paths.

- Remove the Phase 1 helper invocation from the active shell path after broker migration and verify that legacy privilege-delegation rules no longer permit it.

## 8 Audit Design

The audit pipeline records attempts as well as successful operations. The shell emits a sanitized request or rejection event; the Phase 1 helper or Phase 2 broker emits authorization, state-change and completion records. Records use the system UTC clock, which host-admin cannot change, and should be forwarded to a remote collector when available.

The prompt timestamp and audit timestamp are separate reads of the same protected system clock. The prompt is user feedback; it is not audit evidence and cannot be submitted back as an event timestamp.

### 8.1 Per-user command log

Every command execution attempt, including malformed, unauthorized, denied, successful and failed commands, shall be logged in `/var/log/custom-shell/${role}-${uid}.log`. The shell and privileged execution backend shall derive role and UID from the authenticated session and protected server-side identity mapping; neither value may be supplied or overridden by the user. For the host-admin account defined by this design, UID 10000 therefore writes to `/var/log/custom-shell/host-admin-10000.log`.

The file shall use JSON Lines format with one complete audit record per line. A completion record shall be written after command processing so that event_result reflects the final outcome. A failed event shall include a non-secret failed_reason that is specific enough for operations and investigation; a successful event shall omit failed_reason or set it to null.

| **Field**    | **Required content**                                                                                                              |
|--------------|-----------------------------------------------------------------------------------------------------------------------------------|
| timestamp    | UTC RFC 3339 timestamp with timezone and sub-second precision.                                                                    |
| source       | Human user account, mapped local account and numeric UID that initiated the command.                                              |
| category     | Controlled classification such as network, firewall, service, account, rdkb, logs, namespace-config, time, certificate or system. |
| type         | Controlled event type, for example command.completed, command.denied or command.failed.                                           |
| event ID     | Unique event_id for the individual record; correlation_id links records in one session or operation.                              |
| event result | success or fail. failed_reason is mandatory when the result is fail and shall not expose secrets.                                 |
| command      | Canonical command, sanitized arguments and target resource or namespace.                                                          |

*Table 7 Mandatory local command audit fields*

The /var/log/custom-shell directory shall be owned by root or the dedicated audit service with mode 0750. Audit files shall be mode 0640 and writable only through the trusted audit path. host-admin may read approved audit data but shall not modify, delete, rename, truncate, chmod or redirect output into an audit file. Rotation shall be performed only by the root-owned logging service, preserve ownership and permissions, retain the configured history and continue remote forwarding when available.

| **Field group**  | **Required data**                                                                                                                              |
|------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| Event identity   | event_id, type, correlation_id and schema_version                                                                                              |
| Time             | timestamp in UTC RFC 3339 format, monotonic duration and boot_id                                                                               |
| Source           | human user account, mapped local account, numeric UID, role and online or offline authentication path                                          |
| Classification   | controlled category and type values                                                                                                            |
| SSH context      | source address, SSH connection or session ID, certificate serial, fingerprint and principal                                                    |
| Request          | canonical command, sanitized arguments, target namespace or resource and optional change-ticket ID                                             |
| Authorization    | policy version, rollout phase, executor, decision, denial reason and selected handler                                                          |
| Change evidence  | before and after value or hash, backup ID and rollback status                                                                                  |
| Result           | event_result as success or fail; failed_reason is required on failure; include exit category, duration, bytes returned and health-check result |
| Harvest evidence | job ID, sources, time range, file count, byte count, manifest hash and bundle hash                                                             |

*Table 8 Extended audit record fields*


## 9 Policy Configuration

Authorization policy is stored in a root-owned, integrity-protected server-side file. The session cannot select or override its role, rollout phase, executor, config target or validator. Policy changes require a controlled software or configuration deployment and are not available through hostctl.

~~~yaml
role: host-admin
identity:
  local_user: hostadmin
  principal_pattern: host-admin@kms-<device-id>
execution:
  phase: phase1-helper
  helper: /usr/libexec/host-admin-helper
  broker_socket: /run/custom-shell/host-admin-broker.sock
display:
  prompt_identity: local-account-and-uid
  prompt_uid: true
  prompt_time: utc-iso8601-minute
  refresh: login-enter-command-completion
  ticking: false
permissions:
  host_network: constrained-write
  host_firewall: validated-transaction
  host_configuration:
    mode: staged-edit
    editor: restricted-vim
    config_ids: <protected-allowlist>
  host_accounts: lifecycle-only
  host_services: [status, reload, restart]
  namespace_logs: [host, itns, otns, dmzns]
  namespace_config: redacted-read-only
  system_time: status-only
  host_certificate: [status, renew]
denied:
  - arbitrary-shell
  - arbitrary-path
  - privileged-editor
  - namespace-write
  - service-stop-disable-mask
  - audit-or-time-change
  - certificate-revoke-delete-export
~~~

Changing execution.phase from phase1-helper to phase2-broker shall not change the permissions or command grammar.


## 10 Failure Handling

| **Condition** | **Required behavior** |
|---------------|-----------------------|
| Identity mapping unavailable or inconsistent | Do not present an administrative prompt or permit state-changing actions; record a protected authentication/session failure. |
| System clock read or UTC conversion fails | Do not present a misleading timestamp; display a fixed time-unavailable error, audit the condition and fail closed for state-changing operations. |
| Invalid syntax or unknown command | Reject locally, show relevant usage and submit a sanitized rejection audit event. |
| Authorization denial | Return a generic permission error; record the policy rule and detailed reason only in protected audit data. |
| Edit cancelled or Vim terminated | Leave the protected target unchanged; retain or discard the candidate according to transaction policy and audit the outcome. |
| Candidate ownership, path or transaction mismatch | Reject and quarantine or discard the transaction; never follow the substituted object. |
| Validation failure | Do not change state; retain the candidate only for authorized review within the configured retention period. |
| Concurrent target change | Reject apply and require a fresh edit transaction; do not overwrite another authorized change. |
| Partial configuration failure | Restore the prior version atomically and record rollback status. |
| Service fails health check | Attempt configured rollback or recovery; do not expose an independent stop state to the user. |
| Namespace unavailable | Mark harvest or view job failed for that namespace; do not weaken isolation or retry without limits. |
| Audit pipeline unavailable | Fail closed for state-changing operations; allow only explicitly approved read-only diagnostics with protected local buffering. |
| Phase 1 helper failure | Return a bounded failure, preserve target state and record the selected action and failure category. |
| Phase 2 broker unavailable | Do not silently fall back to the Phase 1 helper; fail closed for changes and follow the approved read-only diagnostic policy. |
| Certificate renewal failure | Keep the existing valid certificate; do not replace trust material until full validation succeeds. |

*Table 9 Failure behavior*


## 11 Acceptance Criteria

| **ID** | **Verification** | **Required result** |
|--------|------------------|---------------------|
| AUTH-01 | A valid device-bound Host-plane host-admin certificate reaches the customized shell through DMZNS. | Pass |
| AUTH-02 | A DMZNS-only, wrong-plane, wrong-role, expired or wrong-device certificate is rejected by Host SSHD. | Pass |
| SHELL-01 | bash, sh, user-facing sudo, su, pipes, redirection, command substitution and interpreter execution are rejected and audited. | Pass |
| SHELL-02 | Unknown commands, options, duplicate options and overlong input are rejected before privileged execution. | Pass |
| UI-01 | Every prompt displays only the mapped local account, numeric UID and UTC minute using the fixed <local-account>:<uid> [YYYY-MM-DDTHH:MMZ] format; the human account is not displayed. | Pass |
| UI-02 | The UTC minute is generated at login, refreshed immediately after an empty Enter, and refreshed after every successful, failed or denied command; it never ticks or redraws while input or command execution is active. | Pass |
| UI-03 | User commands, environment variables, terminal control characters and staged configuration content cannot alter or spoof prompt identity or time. | Pass |
| UI-04 | The prompt timestamp is not trusted as the audit timestamp; audit events independently obtain UTC RFC 3339 timestamps with sub-second precision. | Pass |
| PHASE-01 | Phase 1 uses exactly one privileged helper; direct invocation cannot exceed the same host-admin action policy. | Pass |
| PHASE-02 | Phase 2 uses broker peer credentials and the same command, action, policy and audit schemas; it does not silently fall back to the helper. | Pass |
| CFG-01 | Only approved Host config IDs can create an edit transaction; raw paths and namespace write targets are rejected. | Pass |
| CFG-02 | Vim runs as the authenticated UID on a mode-0600 staging copy and never runs with root UID, capabilities or privileged groups. | Pass |
| CFG-03 | User startup files, plugins, modelines, shell/filter escapes and external commands are disabled; SELinux denies editor writes outside the assigned candidate. | Pass |
| CFG-04 | Apply rejects symlinks, path replacement, wrong owner/mode, expired transaction, concurrent target change and invalid syntax. | Pass |
| CFG-05 | A valid candidate is backed up, installed atomically with correct ownership/mode/SELinux label and rolled back on failed activation or health check. | Pass |
| CFG-06 | A secret-bearing configuration cannot be exposed through full-file staging; only approved non-secret fields are editable or the config remains read-only. | Pass |
| NET-01 | Approved network and firewall changes validate, apply, health-check and support rollback. | Pass |
| NET-02 | Attempts to remove protected default-drop, WAN SSH denial or zone-isolation rules are rejected. | Pass |
| SVC-01 | Allowlisted services can be restarted and return to active state; stop, disable and mask are denied. | Pass |
| ACCT-01 | Approved account lifecycle works; UID/GID 0, privileged groups, arbitrary shells and LDAP/AD changes are denied. | Pass |
| NS-01 | host-admin can harvest approved logs from Host, ITns, OTns and DMZns with a complete integrity manifest. | Pass |
| NS-02 | host-admin can view and diff approved redacted namespace configuration but cannot change it. | Pass |
| NS-03 | lxc-attach, lxc exec, nsenter and arbitrary namespace path access are denied. | Pass |
| LOG-01 | Original logs, bundles, manifests and audit records cannot be modified or deleted by host-admin. | Pass |
| TIME-01 | Clock and synchronization status are visible; all time and timezone changes are denied. | Pass |
| CERT-01 | Host certificate renewal uses the fixed identity and TPM-backed key and installs only a fully validated certificate. | Pass |
| CERT-02 | Certificate revoke, delete, arbitrary identity, user-certificate issue, CA modification and private-key export are denied. | Pass |
| AUD-01 | Every accepted, denied, malformed and failed command writes a completion record to /var/log/custom-shell/${role}-${uid}.log with timestamp, source, category, type, event ID and event result. | Pass |
| AUD-02 | A failed command records event_result=fail and a non-secret failed_reason; a successful command records event_result=success and no failure reason. | Pass |
| AUD-03 | host-admin cannot modify, delete, rename, truncate, chmod or redirect output into its audit file; rotation preserves ownership, mode and continuity. | Pass |
| DOS-01 | Restart, packet capture, edit, export and harvesting limits prevent unbounded concurrent or repeated work. | Pass |

*Table 10 Acceptance test baseline*


## 12 Implementation Deliverables

| **Work product** | **Phase** | **Required content** |
|------------------|-----------|----------------------|
| Shell | Both | /usr/libexec/sshd-rbac-shell with trusted local-account/UID/current-time prompt, host-admin grammar, canonical action construction, help, edit orchestration and bounded output. |
| Privileged helper | Phase 1 | /usr/libexec/host-admin-helper as one root-owned executable with server-side policy, independent validation, internal handler dispatch and protected audit. |
| Broker | Phase 2 | host-admin-brokerd UNIX-socket service with peer-credential validation, the same canonical action schema and handler dispatch. |
| Configuration workflow | Both | Config-ID catalog, protected transaction metadata, user-owned staging copy, restricted Vim profile, validators, backup, atomic apply, health check and rollback. |
| Handlers | Both | Network, firewall, configuration, diagnostics, account, service, RDK-B, namespace read, log harvest, time status and certificate renewal handlers. |
| Policy | Both | Root-owned host-admin policy containing execution phase, resource allowlists, limits, protected invariants and policy version. |
| SSHD | Both | Retain the approved current Host SSHD configuration without modification in this design revision; perform compatibility verification only. |
| MAC | Both | SELinux policy for shell, helper/broker, handlers, log spool and protected audit flow, including host_admin_editor_t write access only to the assigned candidate. |
| Audit | Both | Stable event schema, protected local buffer, executor/phase field, remote forwarding integration and retention behavior. |
| Tests | Both | Parser, policy and validator unit tests plus integration, editor-escape, negative, privilege-escalation, isolation, rollback and resource-exhaustion tests. |
| Migration | Phase 2 | Compatibility test, broker activation, removal of active helper delegation, rollback plan and evidence that permissions did not expand. |
| Operations | Both | Allowlist inventory, edit recovery, rollback procedures, monitoring metrics and incident-response guidance. |

*Table 11 Implementation work products*


## 13 Parameters to Finalize

The following values are deployment policy, not architecture changes. They must be finalized before implementation freeze and recorded in the protected host-admin policy.

- Allowlisted Host services and the health check for each service.

- Permitted Host configuration IDs, destination mappings, protected directives and validators, including SSHD and SSSD activation and rollback rules.

- Prompt local-account/UID source, separate audit-only human identity mapping, fixed character set, YYYY-MM-DDTHH:MMZ rendering, login/Enter/completion refresh behavior and clock-failure behavior.

- Restricted Vim package availability, root-owned profile, disabled features and staging transaction lifetime.

- Phase 1 privilege-delegation rule and the mechanism used to derive and verify the original authenticated UID.

- Phase 2 socket path, ownership, message-size limits and migration/rollback criteria.

- Protected firewall invariants and approved interface inventory.

- Local-account UID/GID allocation, home root and retirement retention period.

- RDK-B parameter allowlist, types, ranges and sensitivity classification.

- Namespace log sources, configuration IDs, redaction rules, OT approval requirements and maximum export size.

- Packet-capture duration, file-size and destination limits.

- Certificate renewal threshold, TTL, retry policy and health-monitoring behavior.



## 14 Phase 1 Work Breakdown and Checkpoints

### 14.1 Delivery rule

Configuration editing is the first complete Phase 1 feature slice. Until the Configuration Edit Gate is accepted, no service restart, network/firewall write, account lifecycle, RDK-B set, certificate renewal or namespace state-changing action may be enabled. The current SSHD configuration remains unchanged, and SSHD/SSSD config IDs remain disabled during this first gate.

| **Work package** | **Scope** | **Checkpoint and required evidence** |
|------------------|-----------|--------------------------------------|
| P1.0 Contract freeze | Freeze config action schema, prompt behavior, identity context, audit schema, policy format and the real host.hosts config ID. | CP0: reviewed schemas, /etc/hosts policy, validator, health check, rollback and test matrix; no SSHD change. |
| P1.1 Minimal shell | Implement prompt, config grammar, help, time status and exit only; reject shell syntax and arbitrary paths. | CP1: parser tests, prompt transcript and rejection audit records pass. |
| P1.2 Single helper skeleton | Install one root-owned helper with config-only dispatch, protected identity lookup and policy validation. | CP2: direct invocation cannot exceed policy; arbitrary commands/actions are rejected and audited. |
| P1.3 Config catalog/read | Implement config.list/show and map host.hosts to the real Host-plane /etc/hosts target. | CP3: canonical mapping, raw-path denial, protected-entry enforcement, secret-target denial and namespace-write denial pass. |
| P1.4 Stage and edit | Create protected transaction metadata and a mode-0600 user-owned candidate; run restricted Vim as the user under host_admin_editor_t. | CP4: Vim is never root, writes only the candidate, cannot escape its SELinux boundary and editor exit does not apply. |
| P1.5 Validate and diff | Apply config-specific validation, protected-directive checks, candidate/original hashes and redacted bounded diff. | CP5: invalid, stale, mutated and concurrent candidates are rejected without target change. |
| P1.6 Atomic apply/rollback | Reauthorize apply, create backup, replace atomically, restore metadata/label, health-check and roll back on failure. | CP6: success, replay denial, failure injection and rollback evidence pass. |
| P1.7 Audit and recovery | Cover malformed, denied, successful, failed, discarded and rolled-back events; enforce limits and fail-closed behavior. | CP7: JSONL coverage, tamper resistance, quotas and recovery tests pass. |
| P1.CFG | End-to-end Configuration Edit Gate | Go/no-go review with CP0–CP7 evidence, policy/catalog versions, hashes, representative audit chain and signed decision. |

### 14.2 Configuration Edit Gate command scope

Only the following administrative interface is required for the initial vertical slice:

~~~text
hostctl config list
hostctl config show <config-id>
hostctl config edit <config-id>
hostctl config validate <edit-request-id>
hostctl config diff <edit-request-id>
hostctl config apply <edit-request-id>
hostctl config discard <edit-request-id>
hostctl time status
hostctl help
hostctl exit
~~~

The visible prompt shall be:

~~~text
<local-account>:<uid> [<YYYY-MM-DDTHH:MMZ>] hostctl>
~~~

Example:

~~~text
hostadmin:10000 [2026-09-15T09:42Z] hostctl>
~~~

The prompt is generated at login, refreshed after an empty Enter and refreshed after a submitted command completes, fails or is denied. It does not tick while the user types or while the command runs. The verified human account remains present in protected audit records but is not shown in the prompt.


### 14.3 Real use case: host.hosts

The first Configuration Edit Gate shall use the real Host-plane /etc/hosts file. The use case is an authorized administrator adding or updating an approved static hostname mapping required by a Host-plane management service.

The user-facing resource is the logical ID host.hosts. The shell and helper shall not accept /etc/hosts or any other raw path as an argument.

~~~yaml
config_id: host.hosts
target: /etc/hosts
access: staged-edit
expected_owner: root
expected_group: root
expected_mode: "0644"
validator: hosts-file-validator
activation: live-read
health_check: hosts-resolution-check
rollback: automatic
~~~

The exact SELinux type and size/line limits are deployment-policy values and shall be captured in the protected config catalog before CP0 approval.

#### Required edit flow

~~~text
hostctl config show host.hosts
hostctl config edit host.hosts
hostctl config validate <edit-request-id>
hostctl config diff <edit-request-id>
hostctl config apply <edit-request-id>
~~~

The administrator edits only the user-owned staging candidate. A typical authorized change adds or updates a policy-approved mapping:

~~~text
<approved-ip-address> <approved-hostname> [<approved-alias> ...]
~~~

The validator shall:

- Require a regular text file with no NUL bytes, terminal control characters or over-limit lines.

- Parse each non-comment record as one valid IPv4 or IPv6 address followed by one or more syntactically valid hostnames or aliases.

- Preserve policy-required loopback, localhost, DUT hostname and management entries.

- Reject removal or conflicting redefinition of protected entries.

- Reject unapproved addresses, names or aliases where the deployment policy defines an allowlist.

- Recheck candidate ownership, mode, transaction binding and SHA-256 hash before apply.

- Confirm the original /etc/hosts identity and hash have not changed since the transaction began.

After atomic installation, the health check shall:

- Confirm localhost and every policy-required local name still resolve to the expected address.

- Confirm the newly approved hostname resolves to the requested approved address through the system resolver path.

- Verify /etc/hosts ownership, mode and SELinux label.

- Trigger automatic rollback when parsing, resolution or metadata validation fails.

Because /etc/hosts is consumed through normal resolver calls, this use case does not require a service restart. The audit chain shall include config ID, actor, old/new hashes, redacted diff, validator result, backup ID, apply result, health-check result and rollback status.

SSHD and SSSD config IDs remain disabled throughout this first gate. Their deployed configuration hashes must remain unchanged. After host.hosts passes the gate, each additional Host config ID requires its own target mapping, validator, protected invariants, health check, rollback rules and approval.

### 14.4 Gate decision

**Go criteria**

- CP0 through CP7 pass with traceable evidence.

- list, show, edit, validate, diff, apply and discard pass end to end.

- Restricted Vim, SELinux, identity, atomicity, rollback and audit negative tests pass.

- The single helper exposes no arbitrary executable, command or path interface.

- The deployed SSHD/SSSD hashes and all namespace configurations remain unchanged.

**No-go behavior**

A failed criterion keeps every other state-changing Phase 1 handler disabled. Correct the failed work package, repeat its checkpoint and regress all earlier checkpoints.

### 14.5 Remaining Phase 1 work after gate acceptance

| **Work package** | **Capability** | **Checkpoint** |
|------------------|----------------|----------------|
| P1.8 | Read-only system/network diagnostics and bounded capture | Target, duration, output and audit limits pass. |
| P1.9 | Service status/reload/restart | Allowlist, stop/disable/mask denial, rate limit and health check pass. |
| P1.10 | Host network/firewall transactions | Isolation invariants, dry-run, management-path verification and rollback pass. |
| P1.11 | Host-local account lifecycle | UID/GID allocation, privileged-group denial and lifecycle audit pass. |
| P1.12 | RDK-B get/set | Parameter allowlist, type/range validation, redaction and failure handling pass. |
| P1.13 | Host certificate status/renewal | Fixed identity, TPM key, chain validation and revoke/delete/export denial pass. |
| P1.14 | Host/namespace log harvest and namespace config visibility | Read-only collection, redaction, integrity manifest and no namespace-shell exposure pass. |
| P1.15 | Integrated Phase 1 release | Full regression, SELinux, resource-exhaustion, recovery and security review pass. |

Every later work package reuses the action, identity, policy, audit and failure contracts accepted by the Configuration Edit Gate and cannot weaken the customized-shell/single-helper boundary.

## Appendix A SSHD Configuration Preservation

This revision shall not add, remove or modify any SSHD directive. The deployed SSHD configuration remains the approved current baseline and is outside the scope of this change. Command audit logging and staged configuration editing shall be implemented entirely in the customized shell, Phase 1 helper or Phase 2 broker, configuration staging manager and protected logging service. Any future deployed SSHD configuration change requires a separate authorized host-admin transaction or design review, validation and controlled deployment.

## Appendix B Recommended Audit Event Example

```json
{
  "timestamp": "2026-09-14T07:42:18.314Z",
  "source": {
    "human_account": "hostadmin01",
    "local_account": "hostadmin",
    "uid": 10000
  },
  "role": "host-admin",
  "category": "logs",
  "type": "command.completed",
  "event_id": "<unique-event-id>",
  "correlation_id": "<session-operation-id>",
  "principal": "host-admin@kms-1347938443",
  "source_address": "<management-address>",
  "command": "logs.harvest",
  "target": "otns",
  "event_result": "success",
  "failed_reason": null,
  "job_id": "<opaque-id>",
  "policy_version": "<version>",
  "manifest_sha256": "<hash>"
}
```

Failure example: set event_result to fail and include a stable, non-secret failed_reason such as authorization_denied, invalid_argument or health_check_failed. The event shall retain the attempted canonical command and target.

## Appendix C Two-Phase Migration and Restricted Vim Baseline

### C.1 Phase 1 deployment

1. Deploy the unchanged customized-shell entry path and exact hostctl grammar.

2. Install one root-owned host-admin-helper and the protected action policy.

3. Enable only fixed helper invocation through the approved privilege-delegation mechanism.

4. Deploy config-ID mappings, restricted Vim profile, staging controls, validators and protected audit flow.

5. Verify direct helper invocation, Vim escape attempts and malformed actions cannot expand host-admin authority.

### C.2 Phase 2 migration

1. Deploy host-admin-brokerd with the same canonical action and audit schemas.

2. Run compatibility tests against the Phase 1 action corpus and expected policy decisions.

3. Switch the shell executor from helper invocation to the UNIX socket.

4. Verify peer credentials, handler parity, failure behavior and audit continuity.

5. Remove the active Phase 1 helper privilege-delegation path after acceptance. Do not silently retain it as a broker fallback.

### C.3 Restricted Vim security baseline

Restricted Vim is permitted only while all of the following remain true:

- The editor process runs as the authenticated user UID and GID, never as root.

- No Linux capabilities, privileged supplementary groups or writable privileged executable path are inherited.

- Only the staging candidate is passed to Vim; the protected destination is never passed to the editor, and the dedicated SELinux editor domain denies access outside the approved staging scope.

- User vimrc/gvimrc files, plugins, modelines, shell/filter commands, external commands and swap files are disabled; SELinux denies writes outside the assigned candidate.

- The staging directory is private to the user, while transaction metadata is protected from that user.

- The helper or broker independently reauthorizes and validates the complete candidate before installation.

- Editor exit alone never changes the protected target; apply is an explicit audited action.

A failure of any baseline condition disables config edit for the affected config ID and leaves config show, validate of already-staged content where safe and discard available according to policy.

