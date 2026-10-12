# Consolidated RBAC Design and Host-Admin Custom Shell

**Status:** descriptive. Derived from the code and plan docs on branch `feat/rbac3-shell`, including its
uncommitted working-tree changes, as of 2026-10-12. It documents what exists and lists open gaps.
It does not propose new code.
**Supersedes (for the model):** `docs/ot-it-dmz-zones-rbac/design.md` (2026-09-03, broker/root-shell model; see section 9).
**Builds on:** `ssh-rbac-design.md` (authoritative for planes, CA trust, and login flows).
**Diagrams:** `docs/ot-it-dmz-zones-rbac/RBAC/` (`ldap online.png`, `offline.png`, `RBAC summary.png`), summarized in section 2.1.
**Related plans:** `docs/host-admin-shell/*`, `docs/otit-host-admin-login-account-mapping-plan.md`,
`docs/otit-auditor-and-direct-namespace-access-plan.md`.
**Tests:** `tests/dut/host-admin-shell/`, `tests/dut/host-admin-account-migration/`, `tests/dut/ot-it-dmz-zones-rbac/`.

## 1. Goals

1. Give each human role a fixed, minimal entry point into exactly one security plane.
2. Make Host and OT access depend on a second, plane-specific, device-bound SSH certificate. LDAP or a first-hop certificate alone is never enough.
3. Replace the unrestricted Host root shell with a bounded, audited, grammar-fixed admin shell (`hostctl`).
4. Make every privileged action attributable to a credential ID (certificate Key ID) and written to a root-owned audit log that fails closed.

## 2. Planes and roles

| Plane | Entry | Roles admitted |
|---|---|---|
| DMZNS | SSH 2220 (LDAP password or DMZ-CA cert) | host-admin, auditor, ot-admin, ot-operator, dmz-admin |
| Host | `172.31.0.1:22`, DMZ conduit only, cert only | host-admin, auditor (via DMZNS second hop) |
| OTNS | `172.31.0.10`, DMZ conduit only, cert only | ot-admin, ot-operator |
| ITNS | SSH 2230 | it-admin (direct) |

| Role | GID | Local cert user (User 1) | UID | LDAP user (User 2) | Final landing |
|---|---:|---|---:|---|---|
| host-admin | 6004 | `hostadmin` | 10000 | `hostadmin01` | Host, `host-admin-session` -> `hostctl` shell |
| auditor | 6005 | `auditor` | 10800 | `auditor01` | Host, forced read-only `host-auditor-shell` |
| ot-admin | 6001 | `otadmin` | 10400 | `otadmin01` | OTNS admin shell |
| ot-operator | 6006 | `otoperator` | 11000 | `otoperator01` | OTNS restricted shell |
| dmz-admin | 6003 | `dmzadmin` | 10200 | `dmzadmin01` | DMZNS only |
| it-admin | 6002 | `itadmin` | 10600 | `itadmin01` | ITNS only |

UID/GID allocation ranges (hard ownership boundary): fixed role accounts 10000-11999;
Host dynamic accounts 30000-39999; OTns 40000-49999; DMZns 50000-59999; ITns 60000-65533.
The Host account handler never allocates or touches ranges outside 30000-39999.

LDAP User 2 identities are never written to local `/etc/passwd`. User 1 accounts are locked, certificate-only, with private homes.

### 2.1 Login paths (online and offline)

Diagrams: [`RBAC/ldap online.png`](RBAC/ldap%20online.png), [`RBAC/offline.png`](RBAC/offline.png), [`RBAC/RBAC summary.png`](RBAC/RBAC%20summary.png).
Both modes end in the same place for each role. They differ only in how the **first hop** is authenticated.
**Second hop to Host/OTNS is always a plane-specific certificate**, never a password.

**Online path (LDAP User 2)**

| Role | Login path | Final destination |
|---|---|---|
| Host admin | `hostadmin01` + LDAP password -> DMZNS -> `hostadmin` + Host certificate | Host plane |
| Auditor | `auditor01` + LDAP password -> DMZNS -> `auditor` + Host certificate | Host plane, read-only shell |
| OT admin | `otadmin01` + LDAP password -> DMZNS -> `otadmin` + OTNS certificate | OTNS |
| OT operator | `otoperator01` + LDAP password -> DMZNS -> `otoperator` + OTNS certificate | OTNS |
| IT admin | `itadmin01` + LDAP password -> ITNS directly | ITNS |
| DMZ admin | `dmzadmin01` + LDAP password -> DMZNS directly | DMZNS |

**Offline path (local User 1 certificate)**

| Role | Login path | Final destination |
|---|---|---|
| Host admin | `hostadmin` + DMZNS certificate -> DMZNS -> `hostadmin` + Host certificate | Host plane |
| Auditor | `auditor` + DMZNS certificate -> DMZNS -> `auditor` + Host certificate | Host plane, read-only shell |
| OT admin | `otadmin` + DMZNS certificate -> DMZNS -> `otadmin` + OTNS certificate | OTNS |
| OT operator | `otoperator` + DMZNS certificate -> DMZNS -> `otoperator` + OTNS certificate | OTNS |
| IT admin | `itadmin` + ITNS certificate -> ITNS directly | ITNS |
| DMZ admin | `dmzadmin` + DMZNS certificate -> DMZNS directly | DMZNS |

**Online flow (per the online diagram)**

1. The workstation runs the SSH client with the enterprise username and password, and already holds a pre-issued target private key and certificate for the second hop.
2. The role selects the entry: `dmzadmin01` to DMZNS (2220), `itadmin01` to ITNS (2230), the other four to DMZNS as a mandatory transit.
3. DMZNS or ITNS resolves identity through SSHD -> NSS -> SSSD and verifies the password through SSHD -> PAM -> SSSD, against enterprise LDAP/AD over TLS.
4. For Host/OT roles, DMZNS stages the target key and certificate under `/run/user/<uid>/otit-ssh/`.
5. DMZNS opens the second hop, using the Host certificate to `172.31.0.1:22` or the OTNS certificate to `172.31.0.10:22`.
6. The target validates its own plane's certificate and applies the role. ITNS has no Host/OT second-hop right.

Online first hop **requires LDAP/AD to be reachable**. ITNS and DMZNS roles end at step 3.

**Offline flow (per the offline diagram)**

*A. Certificate preparation (done beforehand, on a certificate-preparation workstation)*

1. The user generates an SSH key pair on the workstation. The private key is never sent to the portal.
2. The workstation submits the public key, requested role and DUT device ID to the applicant portal.
3. The portal calls the applicant backend over HTTPS.
4. The backend authenticates the applicant and sets plane, principal and TTL server-side, then requests signing from the external KMS/Vault.
5. KMS/Vault signs with the plane-specific user CA. The CA private key stays protected there.
6. The signed certificate returns through the backend to the portal.
7. The signed certificate(s) go back to the workstation, which keeps the matching private key plus certificate(s) as a credential bundle.

*B. Login (SSH access workstation, which receives the bundle from the preparation workstation)*

1. The SSH client uses the private key and certificate. No LDAP/AD is needed.
2. `dmzadmin` logs in to DMZNS directly, `itadmin` to ITNS directly, and Host/OT roles go to DMZNS as transit and copy over the target key and certificate.
3. DMZNS (or ITNS) validates the certificate against its own user CA only.
4. DMZNS stages the target key and certificate under `/run/user/<uid>/otit-ssh/`.
5. DMZNS opens the second hop with the Host or OTNS certificate.
6. The target validates its plane certificate and applies the role.

The offline diagram places an applicant portal and backend in front of the KMS. `ssh-rbac-design.md` describes the workstation calling
the KMS signing API directly. Treat the portal/backend as an authentication and policy layer in front of that API. The caller still cannot choose the Vault mount, role, principal,
target or TTL.

**Same account name, different credential.** The online user (`hostadmin01`) and the offline user (`hostadmin`) are different identities that map to the same role group.
Both end as local `hostadmin` on Host, and both are admitted only by a Host-plane certificate. A certificate from one plane must fail on another.

**Not covered by the diagrams:** dynamic Host-local accounts (`hostctl account add`, UID 30000-39999, section 3). They are certificate-bound offline-style accounts with
principal `<role>:<account>@<device-id>`. The diagrams do not show whether an LDAP online first hop can land on them. As written, online Host access maps only to the fixed `hostadmin` and `auditor`.

### 2.2 Why a certificate issued on the workstation can log in to the DUT

The DUT never talks to the workstation, the portal, or the KMS at login time. It trusts the **CA public key** provisioned onto it earlier,
and an SSH certificate is a public key that the matching CA private key has signed.

```text
Provisioning (once)                        Issuance (per user)                    Login (every time)
KMS/Vault holds CA private key             Workstation: key pair                  Workstation presents cert + proves
DUT stores CA PUBLIC key only      ---->   public key + role + device ID  --->    it holds the private key
  /var/persist/ssh-trust/planes/<plane>/   KMS signs -> certificate               DUT checks cert against its CA public key
  -> /etc/cert/ssh/planes/<plane>/user-ca.pub                                     No network call to KMS
```

1. **Trust is established by provisioning, not by the user.** During provisioning the DUT obtains each plane's user CA public key and writes it to
   `/var/persist/ssh-trust/planes/<plane>/`. Startup reconciliation copies it to `/etc/cert/ssh/planes/<plane>/user-ca.pub`, and that plane's sshd names it in
   `TrustedUserCAKeys`. Each plane trusts only its own CA.
2. **Issuance binds identity into a signed object.** The KMS signs the user's *public key* together with the principal (`<role>@<device-id>`,
   or `<role>:<account>@<device-id>`), the validity window (TTL) and the key ID. Signing is done with the CA private key, which never leaves Vault.
   The user cannot edit any of these fields without invalidating the signature.
3. **Login verifies the signature locally.** sshd checks that:
   - the certificate was signed by a CA listed in `TrustedUserCAKeys` for that plane;
   - the certificate is inside its validity window;
   - the client holds the matching private key (SSH public-key challenge, so a copied certificate alone is useless);
   - a principal in the certificate is allowed for the requested local account, here decided by `host-authorized-principals` (Host) or the zone's principal file (OTNS).
4. **The device ID makes the certificate device-specific.** The accepted principal contains the DUT's own `kms-<SoC serial>`, so a certificate issued for another DUT is rejected even though it is validly signed by the same CA.
5. **Separate CAs per plane make it plane-specific.** The DMZNS CA does not appear in Host/OTNS/ITNS trust, so a DMZNS certificate fails on Host or OTNS. That is why a Host or OT login needs a second, separately issued target-plane certificate.

Why this is safe to do from an ordinary workstation:

- The private key is generated on the workstation and never sent to the portal, backend or KMS. Only the public key is submitted, so the KMS cannot leak a private key it never had.
- Possessing a certificate is not enough. An attacker also needs the matching private key. Intercepting the certificate in transit or from the portal does not help.
- The role, plane, principal and TTL are chosen server-side by the backend and KMS, not by the requester, so a user cannot ask for a stronger role.
- The DUT works with no connectivity to LDAP, the KMS or the portal, which is what makes the offline path possible.

Limits to keep in mind:

- **Revocation is by expiry only.** I found no `RevokedKeys` directive in `sshd_config.host-internal`. A stolen private key plus its certificate works until the TTL ends. The 24-hour TTL is therefore the replay exposure noted in `ssh-rbac-design.md`. Shorter TTLs reduce it.
- **Clock dependence.** Validity is checked against the DUT's clock. A badly wrong DUT clock can make valid certificates fail or expired ones pass.
- **The CA is the root of trust.** Anyone who can write the DUT's `user-ca.pub` can mint accepted logins, so those files must stay root-owned and are updated only by the provisioning/trust-sync path.
- **Second-hop key staging.** The target private key is briefly copied to DMZNS (`/run/user/<uid>/otit-ssh/`). It is session-scoped and removed after use, but during the session DMZNS holds it.

## 3. Authentication and authorization chain (Host admin)

```text
Workstation
  -> DMZNS (LDAP password via pam_sss, OR DMZ-CA certificate)
  -> DMZNS imports Host-CA target key+cert into /run/user/<uid>/otit-ssh/
  -> ssh hostadmin@172.31.0.1   (Host sshd, certificate only)
       TrustedUserCAKeys  = host-plane user CA only
       AuthorizedPrincipalsCommand = /usr/libexec/host-authorized-principals %u
       AllowGroups host-admin auditor
       ExposeAuthInfo yes
  -> login shell = /usr/libexec/custom-shell/host-admin-session  (setuid root)
  -> drops to the user's uid/gid, execs host-admin-shell (python)
  -> each hostctl verb -> /usr/libexec/host-admin-helper (setuid root, fixed actions)
```

Authorization is decided in four places. They overlap on purpose.

| Layer | Component | Decision |
|---|---|---|
| Network | nft plugins 40-43 (otit-separation) | Host sshd listens only on the DMZ veth. No LAN/WAN path to Host:22. |
| Certificate | Host sshd + `host-authorized-principals` | Principal must match `<device-id>`-bound value for the local account (table below). |
| Account | `AllowGroups`, `Match Group auditor` | Only GID 6004/6005. Auditor gets `ForceCommand`, no forwarding. |
| Session | `host-admin-session.c`, `host-admin-shell.py`, `host-admin-helper.c` | Each re-validates uid/gid/shell, and the helper re-validates the caller again. |

Principal derivation (`host-authorized-principals`, root-owned, ignores caller input):

| Local account | Principal accepted |
|---|---|
| `hostadmin` 10000:6004 | `host-admin@<device-id>` (legacy fixed) |
| `auditor` 10800:6005 | `auditor@<device-id>` (legacy fixed) |
| dynamic 3xxxx:6004 | `host-admin:<account>@<device-id>` |
| dynamic 3xxxx:6005 | `auditor:<account>@<device-id>` |
| anything else | rejected |

`<device-id>` is `kms-<SoC serial>`, read from `/var/persist/ssh-trust/device-id`. A certificate for another device, or a legacy generic
certificate presented to a dynamic account, fails.

## 4. Host-admin custom shell architecture

Three binaries/scripts in one recipe (`host-admin-custom-shell_1.0.bb`):

| Artifact | Install path / mode | Runs as | Role |
|---|---|---|---|
| `host-admin-session` (C) | `/usr/libexec/custom-shell/host-admin-session`, 4755 | root, then drops to user | Login shell. Validates identity, extracts certificate Key ID, writes session context, audits login/logout/idle-timeout, then `setgid/setuid` and `execle` of the shell with a scrubbed env (`PATH`, `LANG`, `CUSTOM_SHELL_SESSION_CONTEXT`). |
| `host-admin-shell` (Python) | `/usr/libexec/custom-shell/host-admin-shell`, 0755 | the admin's uid | Parser and REPL. Exact-token grammar. No `shell=True`. Never executes user text. |
| `host-admin-helper` (C, ~1200 lines) | `/usr/libexec/host-admin-helper`, 4755 | root (setuid) | The only privileged component. Fixed actions, bounded inputs, protected audit. |

### 4.1 Session setup (`host-admin-session.c`)

1. Requires `euid==0`. Accepts only `hostadmin` (10000:6004), or uid 30000-39999 with gid 6004 and the host-admin-session shell.
2. Reads `SSH_USER_AUTH` (exposed by sshd), runs `ssh-keygen -L`, and extracts the certificate **Key ID**. No Key ID means no shell (exit 126).
3. For dynamic accounts, Key ID must equal the account name. This is what binds the certificate to the account.
4. Writes `/run/custom-shell/session/<uid>/<pid>.json` containing `{"credential_id": ...}`, root-owned, 0600.
5. Appends `session.login` to `/var/log/custom-shell/host-admin-<uid>.log` (root 0640, `O_NOFOLLOW`, ownership re-checked).
6. Forks, drops privileges, execs the shell. On exit writes `session.idle_timeout` (if exit 124) and `session.logout` with duration and status.

### 4.2 Shell grammar (`host-admin-shell.py`)

Rejects any line over 256 chars or containing `| ; & \` $ < > \ /` or NUL. It then matches the token list exactly:

| Area | Commands |
|---|---|
| Config transactions | `hostctl config list \| show host.network.hosts \| edit host.network.hosts \| validate\|diff\|apply\|discard <32-hex-id>` |
| Services | `hostctl service list \| status\|reload\|restart <service>` |
| Accounts | `hostctl account list \| add <name> --group <host-admin\|auditor> \| suspend\|resume\|delete <name>` |
| Firewall (management) | `hostctl firewall management list \| stage-whitelist <wan-ssh\|wan-webui> <cidrs> \| validate\|diff\|apply\|rollback <id>` |
| Firewall (flows) | `hostctl firewall flow stage add --from --to --protocol --destination-port --ttl \| validate\|diff\|apply\|revoke <id>` |
| Diagnostics | `hostctl diagnose system status \| network interfaces\|routes\|sockets \| ping <t> [--count n] \| trace <t> \| dns <n> \| capture <if> --duration n [--filter icmp\|dns\|dhcp] \| capture status\|show <id>` |
| Misc | `hostctl help`, `hostctl time status`, `hostctl exit` |

Parser rejections are sent to the helper as `audit-denied`. The user sees only `hostctl: request denied`. Detail stays in the audit log.
The only interactive child is restricted Vim (`-Z -n -X -u /etc/custom-shell/vimrc -U NONE --noplugin -i NONE`), opened on a staged **candidate copy** of `/etc/hosts`, never on the target.
The idle timeout (default 300 s, allowed 60-3600) is read from the policy file only if it is root-owned and not group/world-writable.

### 4.3 Helper capabilities (`host-admin-helper.c`)

| Capability | Mechanism | Bounds |
|---|---|---|
| `/etc/hosts` edit | stage -> Vim on candidate -> validate (hostname/line checks) -> diff -> apply -> discard | document mode; target must be regular root:root 0644; max 4 open transactions; 900 s TTL; audit fail-closed |
| Service control | `systemctl show` eligibility check, then fixed `systemctl status/reload/restart` | concrete units only (excludes alias/template/generated/static/masked/transient/shutdown/emergency); must be active before mutation; 300 s per-unit rate limit; one fixed recovery restart on failure |
| Diagnostics | fixed `execv` of ip/ss/ping/traceroute/dig/tcpdump | host namespace only; 45 s; 64 KiB output; target/interface validated |
| Packet capture | `tcpdump` with fixed profiles (`icmp`, `dns`, `dhcp`) | 1-300 s; 16 MiB; 1 active per uid; spooled under `/var/lib/custom-shell/diagnostics`; no raw export |
| Accounts | `useradd`/`usermod`/`chage`/`userdel` via `fixed_exec` | name `[a-z][a-z0-9_-]{0,31}`, denies root/hostadmin/auditor/nobody; lowest free uid in 30000-39999; primary GID 6004 or 6005 only; no supplementary groups; locked password (`-p '!'`); home `/home/local/<name>` 0700; delete refuses if the account has running processes |
| Management firewall | `dmcli eRT getv/setv` on `Device.X_WNC_Firewall.WanSSH/WanWebUI.SourceIPv4Whitelist`, then `TriggerApply` | CIDR list only; rejects `0.0.0.0` and `/0`; never changes `Enable`; records prior value; verifies `Status=Active`, empty `LastError`; restores prior value on failure; 10 s / 4 KiB dmcli bound |
| Cross-namespace flows | writes `/etc/ccsp/firewall/plugins.d/80-50-host-admin-flows.nft` | only dmzns<->otns and dmzns<->itns, one direction per rule; TTL 5 min-8 h; explicit port or bounded range |

Helper caller validation: uid/gid must be `hostadmin` 10000:6004 or a dynamic 30000-39999:6004 account whose shell is the session binary.
The credential ID is read from the session-context file, which must be under `/run/custom-shell/session/<uid>/`, root-owned, and mode 0600 or tighter.
For dynamic accounts, the credential must equal the account name.
**Every action writes an audit record, and failure to audit fails the action** (`audit_completion_failed`).

### 4.4 Auditor shell

`host-auditor-shell` is a POSIX `sh` fixed-string dispatcher, forced by `Match Group auditor` / `ForceCommand`. Commands: `help`, `session info`,
`audit host status|network|resources|logs`, `exit`. No `eval`, no path or argument pass-through, no mutation. It runs unprivileged.

## 5. Persistent state and ownership

| Path | Owner/mode | Content |
|---|---|---|
| `/etc/custom-shell/host-admin-policy.json` | root 0644 | policy (see 7.1) |
| `/etc/custom-shell/vimrc` | root 0644 | restricted editor config |
| `/run/custom-shell/{edit,session}` | root 0711 | per-uid staging and session-context files |
| `/var/lib/custom-shell/{transactions,diagnostics,accounts,firewall,flows}` | root 0700 | transaction/capture/account/firewall/flow records |
| `/var/log/custom-shell/host-admin-<uid>.log` | root 0640 | JSONL audit, one file per uid |

All are created by `custom-shell.conf` tmpfiles, shipped by the owning recipe. They are not created in `pkg_postinst`, which is consistent with Rule 9.

## 6. Audit model

JSONL, one record per event. Fields: `timestamp` (UTC ms), `role`, `local_account`, `uid`, `credential_id`, `command`, `event_result`, `failed_reason`.
Session events add `event_type` (`session.login|idle_timeout|logout`), duration and exit status.
Records are root-owned and written with `O_APPEND|O_NOFOLLOW`, with owner and mode re-verified on every write, then `fflush` + `fsync`.
Parser denials are audited too. Console messages are generic by design.

## 7. Design observations and gaps

These are findings from reading the code. They are not yet confirmed on the DUT, so treat them as review items.

### 7.1 Policy file is mostly decorative
`host-admin-shell.py` reads only `idle_timeout_seconds` from `host-admin-policy.json`. Every other limit (TTL, rate limit, capture bounds,
account ranges, flow TTL, allowed roles) is a `#define` in `host-admin-helper.c`. The session binary hardcodes `IDLE_TIMEOUT_SECONDS 300` for its
audit record, even though the shell takes the value from the policy file. Editing the JSON therefore changes the shell's timeout but not the
audit field, and changes nothing else. The `version` field (`p1.8-p1.11`) also lags the P1.12 flow code.
Either make the helper load the policy and fail closed, or reduce the JSON to the one field it controls.

### 7.2 Session-context files are never removed
`host-admin-session.c` creates `/run/custom-shell/session/<uid>/<pid>.json` but has no `unlink` on logout. The helper accepts any root-owned 0600 file
under that uid's directory and does not check that it belongs to the current session. A stale file from an earlier session of the same uid (for
example one authenticated with a certificate with a different Key ID) would satisfy the attribution check.
For dynamic accounts the Key ID must still equal the account name, which limits the impact. For the fixed `hostadmin` account, attribution could
point at an older certificate. `/run` is tmpfs and clears on reboot, but not between sessions.

### 7.3 Plan and implementation drift (P1.12)
- The plan lists `flow list` and an ICMP protocol with an optional port. The shell accepts a fixed 15-token `flow stage add` form (port and TTL mandatory), its help text says `tcp|udp`, and there is no `flow list` verb.
- The plan says `account list` reports `retired`. `account_list()` in the working tree reports only `active` or `suspended`. `p1.11-account-delete-lifecycle-plan.md` made immediate delete the behavior, so retirement metadata is described as obsolete. The P1.12 text should be updated to match.
- `p1.10-p1.11` plan says new accounts get a private same-name group. `account-bound-host-certificate-login-plan.md` and the policy file say no private group, with a shared GID 6004/6005. The latter is current. The older plan is stale.

### 7.4 Dynamic-account blast radius
A dynamic host-admin account has the same `hostctl` rights as `hostadmin`, including creating and deleting other host-admin accounts and changing
WAN SSH/WebUI whitelists. There is no sub-role split. Whether a host-admin may delete or suspend their own account, or the last remaining admin, is not checked by the code I read.

### 7.5 Non-interactive path skips idle timeout
When `SSH_ORIGINAL_COMMAND` is set, `main()` dispatches once and returns without arming the idle timer. That is acceptable for a single command, but it is also
a path the plan docs do not describe. Note that `ForceCommand` is applied only to the auditor, not to host-admin.

### 7.6 Enforcement status
- SELinux is `permissive` distro-wide and was reported disabled on the DUT in the plan docs. No enforcing-mode AVC sweep exists for `host-admin-helper`, `host-admin-session`, or the `custom-shell` paths (Rule 6 is open).
- The setuid helper's world-executable 4755 mode depends entirely on the in-process caller check. There is no group restriction on the binary itself, for example `4750 root:host-admin`. That would add a filesystem-level layer. It must be weighed against dynamic accounts, which all share GID 6004, so it would work.
- Certificate TTL is 24 h (documented as a known replay exposure).

## 8. Side effects and caveats

- Image impact: `host-admin-custom-shell` RDEPENDS on `ccsp-dmcli` and `ccsp-zone-firewall`, so the shell now depends on the CCSP stack being healthy. A dmcli failure fails closed (request denied).
- Boot: `host-admin-account-migration.service` and `ssh-plane-trust-sync/activate` run at boot. They fail closed on UID/GID conflicts.
- Security: setuid-root C code with about 1,200 lines of helper logic is the main attack surface. Static analysis is not wired into CI.
- Identity reuse: account delete is irreversible and frees the UID/GID (`p1.11-account-delete-lifecycle-plan.md`). A later account can reuse the number, so audit analysis must key on `local_account` + `credential_id`, not UID alone.
- Compatibility: SSH usernames (`hostadmin`) differ from certificate principals (`host-admin@...`). Operators must not infer one from the other.
- Assumption: this document reflects the working tree, including uncommitted changes to the helper, shell, session, policy, tmpfiles and sshd config. Those are not yet DUT-verified in this pass.

## 9. Status of older documents

`docs/ot-it-dmz-zones-rbac/design.md` describes the earlier `dmz-access-broker` model: LDAP role claim -> broker -> host **root** shell,
with Host re-authentication explicitly deferred. The certificate second hop and the `hostctl` shell replace that model for Host access.
Keep the document as history, and add a "superseded for Host access" note at the top. Its still-valid content is the six-role GID table and the
LDAP data fixes. A grep of `layers/meta-wnc` found no `dmz-access-broker` recipe under `recipes-security` and no `.bb`/`.bbappend`/`.inc` reference to it, so the
broker and its `HOST` root-shell target appear to be gone from the current tree. I did not check git history for when it was removed.

## 10. WebGUI RBAC (separate system)

The WebUI (`rdkb-webui-spa`, `jstapi/_common.jst`) has its own roles, `admin > operator > viewer`, controlled by syscfg `webui_rbac_mode`
(`admin_only` default) and per-category write guards. It is independent of the SSH/Host RBAC above and shares no identity store with it.
A unified mapping between the two models does not exist yet.

## 11. Verification references

| Area | Artifact |
|---|---|
| Role routing end-to-end | `tests/dut/ot-it-dmz-zones-rbac/test_rbac_roles.sh`, `tests/host/T26_otit_separation_test.sh` |
| Host admin shell | `tests/dut/host-admin-shell/` |
| Account migration | `tests/dut/host-admin-account-migration/` |
| Second hop with external KMS | `tests/dut/otit-second-jump-external-kms/` |

Tests for the open items in section 7 do not exist yet. Section 7.2 (stale session context) and 7.3 (grammar versus plan) are the cheapest to cover.
