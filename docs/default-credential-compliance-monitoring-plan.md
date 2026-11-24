# Continuous credential usage and initial password change monitoring

Status: proposal; implementation, coverage inventory and DUT validation are pending.
This develops the usage, initial-password lifecycle and default public-identity
portions of the broader
[credential monitoring design](credential-compliance-monitoring-design.md).

## Goal and scope

Monitor password, file-backed and TPM-backed credential operations and
authentication outcomes regardless of default status. For per-device initial
passwords, report whether the first password change has completed. Separately
detect configured known factory-default certificate and public-key identities. Cover Host, IT, DMZ and OT local accounts and WebUI
accounts first, and extend coverage to file-backed and TPM-backed identities.
Inventory other active services and their credential authorities
before claiming coverage; LDAP, external systems and opaque password stores need
their own supported interfaces. An uninspectable authority is unknown, not compliant.

## Proposed design

1. Maintain a versioned, root-controlled policy inventory of plane, service,
   authority, account, whether an initial password change is required, and the
   approved authoritative lifecycle-status source. Resolve names using the owning
   plane's context, not fixed numeric UID. Keep known factory-default public
   identities in a separate authenticated inventory with product/image/phase
   applicability. Policy and monitor state contain no initial password candidates
   or baseline password hashes.
2. Run bounded read-only checks at boot and periodically (initial proposal: hourly),
   plus after known password, configuration, provisioning, reset and zone lifecycle
   events. A periodic full reconciliation covers missed notifications. Define a
   maximum scan duration, retry/backoff and freshness threshold; missing or stopped
   required planes and failed sources produce unknown and health alerts.
3. For each applicable local account, read an authoritative persistent status
   bound to its plane, authority, account and provisioning generation. Initial
   provisioning, factory reset or reprovisioning of an initial password sets
   `change_required` for the new generation. The password-owning component sets
   `change_completed` only after a successful password update; failed, cancelled
   or interrupted operations must not falsely mark completion. Define consistent
   update and crash-recovery behavior before implementation. Preserve status
   across reboot and ordinary OTA; independently managed accounts in different
   planes have independent state. Missing, stale, inconsistent or untrusted state,
   including legacy devices without trusted migration evidence, is `unknown`.
   The monitor does not retain initial passwords or hash copies, compare password
   candidates with shadow, or attempt live logins. Authentication owners retain
   their normal password hashes as needed. Collect account lock/expiry and
   per-path login exposure separately; none alone proves a completed change.
4. WebUI and other non-shadow authorities follow the same lifecycle contract
   through an owner-provided read-only status interface. Verify whether accounts
   share an authority before mapping completion across interfaces; a WebUI change
   must not mark an independently managed OS or other plane account complete.
   The existing WebUI `Default_PWD` result does not by itself establish first-change
   completion. Do not infer completion from a login, a visited password-change
   page or a cleared expiry flag. An unavailable authority reports `unknown`.
5. The Host collects and checks every zone source it can access reliably through
   an approved interface. Add a plane-owned adapter only for a specific source
   proven inaccessible or unreliable from the Host but available inside that
   plane. A zone may need no adapter. Any necessary adapter returns bounded,
   non-secret results over an authenticated, access-controlled interface; verify
   namespace identity and lifecycle behavior. The Host emits state changes,
   recovery, bounded reminders and health events to its journal and existing
   rsyslog path. Verify queueing, delivery and loss reporting.
6. Maintain an authenticated, versioned inventory of known factory-default
   certificate and public-key fingerprints and their product, image and phase
   applicability. Check the identity configured for each service, including public
   identities exposed through supported TPM or broker interfaces. A match identifies
   a configured default identity, not successful use, private-key possession or TPM
   provenance; establish those separately where trusted evidence exists. An unmatched
   fingerprint is not proof of a unique or non-default key. Factory-default TPM PINs
   and other opaque secrets need an authoritative read-only status from their owner;
   otherwise report unknown. Do not try PINs or extract private keys. Evaluate
   offline bootstrap and commissioned identity under their distinct phase policies.
7. Inventory all credential consumers and their available event sources per plane.
   Capture successful and failed password authentication, file-key access and
   TPM signing operations, and authentication outcomes where the owning service
   provides trustworthy evidence, for both default and non-default credentials.
   Mark missing, unsupported and stale sources as coverage gaps. Correlate only
   when reliable identifiers exist: file access or a successful TPM sign alone
   does not establish successful authentication. Do not record entered passwords,
   key contents, PINs or signing payloads.

## Host and zone responsibility

The Host owns inventory, scheduling, initial-password status and other credential
compliance checks,
Linux Audit collection, Host TPM broker events, collection of authentication
events available from the Host, correlation, forwarding and monitoring health.
Host journal collection does not by itself cover zone journals: investigate a
safe Host-accessible journal interface first. Verify attribution across mounts,
namespaces and zone restarts, and report gaps where collection is not reliable.

Zone-specific code is conditional, not a default requirement. For each proposed
task, record the source, why an approved Host interface cannot obtain it reliably,
what the zone can establish, and the smallest non-secret result interface. An
example is an authority that exposes a necessary read-only status only through a
zone-local interface, but this remains hypothetical until verified. Authentication
events are collected by the Host wherever possible; any required source-side
instrumentation belongs to its owning service and does not justify a general
zone checker. No task is currently proven to require a checker in any zone.

The DUT exposed the three merged zone `/etc/shadow` paths to Host root. Verify
live mount resolution, race handling, zone lifecycle and SELinux enforcing access
before relying on those paths. File visibility alone does not prove safe or
complete monitoring.

## Result semantics

For each applicable authority/account, expose `change_required`,
`change_completed` or `unknown`, separately from `login_enabled`,
`login_disabled` or `unknown` per path. Policy may mark an initial-change
requirement `not_applicable` only with an explicit account/authority rationale;
unavailable evidence is always `unknown`.

| State | Meaning |
| --- | --- |
| `change_required` | The current initial-password provisioning generation has not completed its required password update. |
| `change_completed` | The password owner authoritatively recorded a successful update for that account and generation. |
| `unknown` | Required status is missing, stale, inconsistent, unsupported or not trustworthy. |

Completion proves a lifecycle step, not the current password value, password
strength or absence of a later change back to the initial password. Such change-back
detection is outside this password compliance check. Keep factory-default public
identity findings separate; do not reuse password lifecycle states for them.
Authoritative authentication events remain separate from lifecycle status and
must not infer default password use from either status or a generic login.

Events include device, plane, authority, account, check or event time, policy
version, event type, operation, outcome, authentication method, credential type,
initial-change state and provisioning generation for lifecycle status,
evidence source and error category when known. Identify unavailable fields as
unknown. Preserve individual usage events separately from deduplicated compliance
alerts and report any collection loss or aggregation. Never emit password candidates,
password hashes, shadow records, tokens or other secret values. Restrict local
state and policy modifications; bound output, rate and retention. Monitoring must
not reset credentials, alter expiry or block authentication. Separate bootstrap and
commissioned TPM phases and never infer factory credentials from bootstrap state.

Use `credential.initial_password_change_state` for lifecycle state changes,
recovery and bounded reminders. A completed-state event is not an authentication
event. Protect state writes so only the authorized provisioning/password owners
can update them; the Host monitor reads status through its approved interface.

## Feasibility and implementation plan

The current DUT has auditd and rsyslog active and SELinux permissive; this alone
does not prove event delivery, zone coverage or access under enforcing mode. The
existing unique initial password plan in the UCT-IQ9075 repository
describes per-device provisioning and independent subsequent plane changes. WebUI
login code recognizes `Default_PWD`; its authoritative periodic inspection
interface, authoritative first-change records, password-update integration and
all other supported credential stores remain to be verified.

1. Inventory active authorities, initial-password provisioning and update paths,
   reset/upgrade behavior, authentication paths, zone lifecycle and current events
   without exposing credentials. Verify authoritative persistent status, generation
   binding, recovery, safe APIs, performance and SELinux labels/AVCs. Mark
   unsupported authorities unknown and settle interfaces before implementation.
2. After approval, add Host-owned collection and aggregation under the owning
   `meta-wnc` recipes, with explicit dependencies, bounded timers, policy, state
   and least-privilege SELinux policy. Add a zone-owned adapter only after the
   Host-accessibility test above proves it necessary. Exact files depend on the
   inventory and must be finalized before code changes. Add owner-generated
   authentication evidence only where the actual outcome can be proven.
3. Add repeatable host tests under `tests/host/` and, as needed, a DUT suite under
   `tests/dut/default-credential-compliance/` with a README linking this plan.
   Test change-required/completed/unknown, successful/failed/cancelled/interrupted
   updates, reset and reprovisioning generations, independent plane/authority
   accounts, reboot/OTA persistence, legacy/missing/stale/tampered state,
   locked/expired/disabled accounts, unknown authorities, stale and missing
   planes, rotations, restarts, event loss,
   redaction, known-default and changed file/TPM identities, unavailable TPM,
   unsupported PIN status, phase transitions, and authentication
   success/rejection separately from first-change completion. Exercise non-default password authentication,
   file-key and TPM operations, authentication outcomes and source loss. Use synthetic
   fixtures, never production credentials. Link completed tests here.
4. Stage and exercise safely on the DUT before any build, inspect service health,
   logging and AVCs, and verify the required permissions in enforcing mode. Verify
   SIEM receipt and outage recovery where available; record observed test output.
   Only then run the authorized image build. A missing DUT validation or required
   test artifact blocks the build.

## Side Effects & Caveats

- Initial-change status requires trusted provisioning and password-update
  integration and protected persistent records. It does not require retained
  initial passwords, baseline hash copies or offline password verification.
- Hourly scans leave a status-reporting window; event notifications reduce but
  cannot eliminate it. Completion does not detect a later change back to the
  initial password and does not prove successful authentication.
- Zone unavailability, unsupported stores, stale policy, unverified forwarding and
  unknown authentication paths are visible coverage gaps, never passes.
- SELinux is currently permissive; required enforcing rules cannot be specified
  safely until implementation-specific AVCs and labels are observed.
- The initial interval, retention, eligible services and event transport are
  design assumptions requiring operational and DUT validation.
- Host access to authoritative zone status must be constrained and validated
  under SELinux enforcing and zone lifecycle changes. Shadow visibility alone
  cannot establish first-change completion.
