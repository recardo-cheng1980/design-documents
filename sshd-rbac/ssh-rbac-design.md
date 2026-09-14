# IT/OT separation RBAC and SSH login design

## Purpose

This design separates IT, DMZ, OT, and Host management access while allowing
authorized people to reach the plane appropriate to their role. It supports
two first-hop modes:

- Online access: an enterprise LDAP account authenticates with its password.
- Offline access: a local certificate account authenticates with a short-lived
  SSH certificate issued by the external KMS.

Host and OT access always require a second, independently issued target-plane
certificate. A workstation never connects directly to Host or OT management
SSHD from the LAN/WAN.

## Separation model

The DUT has four security planes.

```text
                     External KMS / Vault
                  issues target-bound SSH certificates
                               |
                               v
Workstation ---> DMZNS ------------------------> Host plane
      |            |                                  |
      |            +-------------------------------> OTNS
      |
      +---------------------------------------------> ITNS
```

| Plane | Purpose | External entry | Trust boundary |
|---|---|---|---|
| DMZNS | controlled management transit zone | SSH port 2220 | accepts selected LDAP and local certificate roles; may initiate permitted Host/OT second hops |
| Host plane | device host administration and audit | no LAN/WAN SSH listener | accepts only DMZ-conduit certificate sessions |
| OTNS | operational-technology management | no direct workstation listener | accepts only authorized DMZ-conduit certificate sessions |
| ITNS | information-technology administration | SSH port 2230 | accepts only IT administrator first-hop access |

Each zone is isolated by its network namespace, mount namespace, SSHD
configuration, local account set, and plane-specific SSH CA trust. A user CA
trusted by DMZNS is not trusted by Host, OTNS, or ITNS. A host certificate
presented by one plane is not the host certificate of another plane.

## RBAC model

The design distinguishes a human's online LDAP identity (User 2) from the
local certificate identity (User 1). User 2 is dynamic and supplied by LDAP;
User 1 is a locked local account installed for offline certificate login.

| Role/group | GID | User 1: certificate identity | UID | User 2: LDAP identity | UID | Allowed outcome |
|---|---:|---|---:|---|---:|---|
| host-admin | 6004 | `hostadmin` | 10000 | `hostadmin01` | 10001 | DMZNS then Host as `hostadmin` |
| auditor | 6005 | `auditor` | 10800 | `auditor01` | 10801 | DMZNS then Host as read-only `auditor` |
| ot-admin | 6001 | `otadmin` | 10400 | `otadmin01` | 10401 | DMZNS then OTNS as `otadmin` |
| ot-operator | 6006 | `otoperator` | 11000 | `otoperator01` | 11001 | DMZNS then OTNS as `otoperator` |
| dmz-admin | 6003 | `dmzadmin` | 10200 | `dmzadmin01` | 10201 | direct DMZNS access only |
| it-admin | 6002 | `itadmin` | 10600 | `itadmin01` | 10601 | direct ITNS access only |

User 2 identities are never copied to local `/etc/passwd`; LDAP changes take
effect through SSSD. User 1 accounts have locked passwords and private local
homes. They cannot use password authentication.

## Login flows

### Host administrator, auditor, OT administrator, and OT operator

These roles use DMZNS as the mandatory first hop and use a certificate-only
second hop.

```text
Online path

hostadmin01 / auditor01 / otadmin01 / otoperator01
  -> LDAP password + PAM/SSSD
  -> DMZNS
  -> import target key + target certificate into /run/user/<uid>/otit-ssh/
  -> SSH certificate login to Host or OTNS as User 1

Offline path

hostadmin / auditor / otadmin / otoperator
  -> DMZNS certificate login
  -> DMZNS
  -> import target key + target certificate into /run/user/<uid>/otit-ssh/
  -> SSH certificate login to Host or OTNS as the same User 1
```

The online and offline first-hop identities intentionally differ, but both
represent the same role group. For example, `hostadmin01` enters DMZNS with
LDAP authentication, while `hostadmin` enters it with a DMZNS certificate.
Both then use a Host-plane certificate to log in as local `hostadmin`.

The final target is fixed by role:

| Role | Target | Final local identity | Session policy |
|---|---|---|---|
| host-admin | Host (`172.31.0.1`) | `hostadmin` | host administration |
| auditor | Host (`172.31.0.1`) | `auditor` | forced read-only audit shell |
| ot-admin | OTNS (`172.31.0.10`) | `otadmin` | OT administration shell |
| ot-operator | OTNS (`172.31.0.10`) | `otoperator` | restricted OT operator shell |

### DMZ administrator

`dmzadmin01` can log in to DMZNS with LDAP password when online.
`dmzadmin` can log in to DMZNS with a DMZNS certificate when offline. Neither
identity is allowed to use this role as a Host or OT second-hop credential.

### IT administrator

`itadmin01` can log in directly to ITNS with LDAP password when online.
`itadmin` can log in directly to ITNS with an ITNS certificate when offline.
IT administration does not traverse DMZNS and does not receive Host/OT
second-hop access.

## SSH certificate and key flow

The KMS never receives a user private key. The human workstation generates a
new key pair and sends only its public key to the KMS signing API.

```text
1. Workstation generates an SSH key pair.
2. Workstation sends public key, role, device ID, and audit identity to KMS.
3. KMS validates the caller and resolves role policy.
4. Vault signs the public key using the required plane's user CA.
5. KMS returns only the signed public certificate.
6. Workstation keeps the private key and copies the required pair into its
   authenticated DMZNS runtime directory for the second hop.
7. DMZNS uses that pair with SSH -i and CertificateFile.
8. The runtime pair is deleted after the session/test operation.
```

There are two independent certificate audiences for Host/OT users:

| Certificate | Used at | Example principal | Trusting CA |
|---|---|---|---|
| DMZ first-hop certificate | DMZNS | `host-admin@kms-<serial>` | DMZNS user CA |
| Host/OT target certificate | Host or OTNS | `host-admin@kms-<serial>` | Host or OTNS user CA |

The same role name may appear in both principals, but the certificates are
different because they are signed by different plane CAs and are trusted by
different SSH servers. A target certificate must fail at DMZNS; a DMZNS
certificate must fail at Host and OTNS.

## Device binding

During provisioning, the DUT derives its device ID from the immutable SoC
serial number:

```text
device-id = kms-<SoC serial>
```

Every user certificate principal includes this device ID. For example:

```text
host-admin@kms-1347938443
auditor@kms-1347938443
ot-admin@kms-1347938443
```

The local `AuthorizedPrincipalsFile` accepts only the principal containing its
own DUT device ID. A certificate issued for `kms-A` therefore cannot be used
to authenticate to `kms-B`.

Host certificates are also device and plane bound:

```text
<device-id>.host
<device-id>.dmzns
<device-id>.otns
<device-id>.itns
```

This allows SSH clients to validate that they reached the intended plane of
the intended device.

## CA trust and certificate material

Each plane has independent SSH user and host CA material.

| Plane | Trusted User CA | Host key and certificate location |
|---|---|---|
| Host | `/etc/cert/ssh/planes/host/user-ca.pub` | `/etc/cert/ssh/planes/host/host/` |
| DMZNS | `/etc/cert/ssh/planes/dmzns/user-ca.pub` | `/etc/cert/ssh/planes/dmzns/host/` |
| OTNS | `/etc/cert/ssh/planes/otns/user-ca.pub` | `/etc/cert/ssh/planes/otns/host/` |
| ITNS | `/etc/cert/ssh/planes/itns/user-ca.pub` | `/etc/cert/ssh/planes/itns/host/` |

The persistent source of truth is `/var/persist/ssh-trust/planes/<plane>/`.
Startup reconciliation copies each plane's provisioned files to the runtime
location used by that plane's SSHD. Zone startup removes the generic Host CA
drop-in inherited from the shared root filesystem, so the effective zone SSHD
configuration contains only its plane-specific `HostKey`, `HostCertificate`,
and `TrustedUserCAKeys` directives.

## KMS and Vault control flow

```text
KMS request
  -> authenticate API caller
  -> validate requested role and DUT device ID
  -> resolve fixed {plane, target, principal, Vault sign role, TTL}
  -> call only that Vault sign path with a dedicated signing token
  -> return signed public certificate and non-secret metadata
```

The caller cannot select a Vault mount, signing role, principal, target, or
TTL. Those values are server-side policy. KMS configuration separates:

- one read-only CA token for public CA retrieval;
- role-specific signing tokens for user certificates;
- plane-specific host-certificate signing roles/tokens.

The KMS returns certificate metadata such as role, plane, target, principal,
serial, and validity. It never returns a private key or a Vault token.

## Provisioning and commissioning control flow

```text
restore
  -> removes previous readiness and commissioning state
  -> arms provision-ready watcher

provision
  -> establishes device identity
  -> obtains and validates all user CAs, host CAs, and plane host certificates
  -> writes plane trust bundles
  -> atomically creates /var/persist/ssh-trust/.provisioned

commissioning path watcher
  -> starts device commissioning only after .provisioned exists
  -> establishes Vault/LDevID operational credentials
  -> reconciles SSH trust and starts dependent services
```

The Vault Agent can start before WAN/DNS is usable; it retries authentication
until network access becomes available. Provisioning and commissioning do not
place human private keys on the DUT.

## SSHD and network policy configuration

### DMZNS SSHD

- Allows public-key certificates and LDAP/PAM password authentication.
- Uses `pam_sss` for LDAP and `pam_systemd` to create the local session
  runtime directory.
- Allows only: `host-admin`, `auditor`, `ot-admin`, `ot-operator`, and
  `dmz-admin` groups.
- Trusts only the DMZNS user CA.
- Disables agent forwarding, TCP forwarding, X11 forwarding, tunnels, and
  user-controlled environment injection.

### Host and OTNS SSHD

- Require public-key/certificate authentication only.
- Disable password and keyboard-interactive authentication.
- Trust only their own user CA.
- Map device-bound principals to local User 1 accounts.
- Host accepts `hostadmin` and `auditor`; OTNS accepts `otadmin` and
  `otoperator`.

### ITNS SSHD

- Supports LDAP/PAM `itadmin01` and certificate `itadmin` first-hop login.
- Trusts only the ITNS user CA.
- Allows only the `it-admin` group.

### Network controls

- Host SSHD listens only on the DMZ conduit address `172.31.0.1:22`.
- OTNS is reachable only through its permitted DMZ conduit path.
- Workstation/LAN access to Host port 22 and legacy OT port 2210 is blocked.
- DMZNS is a controlled transit point, not a credential-forwarding proxy.

## Operational security properties

- LDAP changes are dynamic and do not require a firmware rebuild.
- Offline access remains available when WAN/LDAP is unavailable, using local
  User 1 plus externally issued certificate material.
- Host and OT second hops remain certificate-only in every case.
- Each plane has independent CA trust, limiting certificate replay scope.
- Each DUT accepts only its own device-bound principals and hostnames.
- Runtime target credentials are short-lived, session-scoped, and removed
  from DMZNS after use.
- A 24-hour certificate TTL is operationally convenient but increases private
  key replay exposure; shorter TTLs are preferable where feasible.

## Related implementation references

- `docs/otit-dual-dmz-first-hop-plan.md`
- `docs/otit-second-jump-external-kms-plan.md`
- `docs/kms/plane-specific-ssh-ca-api-plan.md`
- `docs/provisioning/provisioned-commission-trigger-and-user1-home-plan.md`
