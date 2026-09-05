# Addendum: SIEM / Security Log Ingestion & Production-Line Provisioning

**Status:** proposal draft — documentation only, no code/recipe/config change
**Date:** 2026-09-05
**Supplements:** [`01-kickoff-request-for-help.md`](01-kickoff-request-for-help.md) §4 (gap table) and
[`02-joint-architecture-review.md`](02-joint-architecture-review.md) §1.2/§2 (architecture)

This addendum covers two cloud dependencies not detailed in the base kickoff/architecture docs:
(1) where security/audit logs go once they leave the device, and (2) the manufacturing-line service
that issues each device's permanent identity before it ever reaches this codebase. Both are
evidence-backed from what's actually shipped or actually tested — not a greenfield brainstorm.

## 1. SIEM / security log ingestion

### 1.1 What's built on-device

The device has a real, non-trivial log-security pipeline (`layers/meta-wnc/recipes-extended/rsyslog/`):

- **PII/secret masking** — a regex template strips `password`, `secret`, `DeviceSecret`, `PPPoE_PWD`,
  `psk`, `token`, `key` field values to `[HIDDEN]` before any log line is written or forwarded
  (`rdk_log_mon.conf.in`).
- **Per-line integrity** — every forwarded log line gets an HMAC-SHA256 signature (`mmhash` module,
  key from `/etc/ccsp/cfgmgmt/rsyslog_hmac.key`), so tampering with a line in transit or on the
  collector side is detectable.
- **Local resilient buffering** — an `omfwd` disk-backed retry queue (`LinkedList`, configurable max
  size, `QueueSaveOnShutdown`) so a network outage doesn't drop audit events, with a discard-at-high-
  watermark policy to bound disk usage.
- **Separate audit stream** — `/rdklogs/audit/*.log` (config-management + security events) is
  monitored and tagged `RDK-AUDIT` distinctly from general application logs (`RDK-BUSINESS`), with a
  90-day retention policy (`RDK_LOG_AUDIT_RETAIN_DAYS`) vs. 21 days for business logs.
- **Firewall/IDS event classification** — a separate ruleset (`30-firewall-classify.conf`) splits
  `fw_accept`/`fw_drop`/`fw_event` kernel and `CcspZoneFirewallSsp` records into their own log files
  under `/var/log/firewall/`.
- **sshd auth events** routed to a dedicated `/var/log/auth.log` (`10-sshd-auth.conf`).
- **CrowdSec** (host intrusion-detection/response agent) is built and installed
  (`layers/meta-wnc/recipes-security/crowdsec/`), including upstream notification plugins for
  `slack`, `http`, `email`, `sentinel` (Microsoft Sentinel), and `splunk` — but **no
  `/etc/crowdsec/config.yaml`, acquisition config (which logs it parses), scenario/hub selection, or
  notification-plugin wiring exists anywhere in this repo.** The binary and service unit ship;
  nothing tells it what to watch or where to send a decision.

### 1.2 What's missing — the actual gap

**The TLS forwarding target is deliberately not shipped in firmware**, per the config template's own
comment:

> `# TLS forwarding to central log server`
> `# Target and cert paths are configured at deployment time in /etc/rsyslog.d/rdk_log_target.conf`
> `# (not shipped here to avoid hardcoding server IP in firmware)`

The build-time default even forwards to `127.0.0.1:6514` — a loopback placeholder. **There is no SIEM,
log-aggregation, or collector endpoint defined anywhere in this codebase**, consistent with the
"Log aggregation" row already flagged Not Met in
[`../cloud-services/required-cloud-services-gap-assessment.md`](../cloud-services/required-cloud-services-gap-assessment.md)
("flat log file + manual `/api/logs?tail=N` pull... the Vault-token root cause this session was only
found by manually pulling 2000 log lines").

This is exactly the shape of problem a SIEM (Wazuh or otherwise) solves, and the device side is
already built to hand it a clean, masked, integrity-signed, TLS-authenticated stream — **the pipeline
has a plug waiting; there's just nothing plugged into it.**

### 1.3 The ask

1. Stand up (or point at an existing) SIEM ingestion endpoint — Wazuh is one reasonable candidate
   given its open architecture and existing syslog/TLS input support, but the device side is agnostic
   to the specific product: it just needs a `Target`/`Port`/CA cert to fill in
   `/etc/rsyslog.d/rdk_log_target.conf` and expects x509 client-auth (`StreamDriver.AuthMode="x509"`).
2. Decide who issues and rotates the log-forwarding client certificate (`log_ca.pem` /
   `/etc/ccsp/cfgmgmt/rsyslog_hmac.key`) — this is a natural extension of the existing Vault PKI
   relationship (§2 of the kickoff doc), not a new PKI.
3. Wire CrowdSec's acquisition config to actually read the audit/firewall log streams already being
   produced, and decide its notification/bouncer target — feeding decisions into the same SIEM
   avoids operating two disconnected security-event pipelines.
4. Confirm retention/compliance requirements (CR 6.1/6.2 — flagged unverified per the same caveat as
   the base docs) so SIEM-side retention policy matches or exceeds the device's own
   90-day audit-log retention default.

## 2. Production-line provisioning service

### 2.1 What's assumed, and where it lives

Every device's permanent cryptographic identity — its **IDevID** (TPM-resident SRK-wrapped private
key + certificate) — is created **once, at manufacturing time, by a process entirely outside this
repo.** `device-commission.py`'s own module docstring is explicit about this:

> "Both key and cert are provisioned once at manufacturing time (not by this script) and are
> read-only here."

The device-side commissioning flow (`device-commission.service`) only ever *consumes* that IDevID —
it authenticates to a dedicated **provisioning broker**, `provision.csyang.org:8443` (deliberately a
separate hostname from the operational broker `mqtt-server.csyang.org` — see
`tests/dut/provisioning-lifecycle/README.md`), presents the manufacturing-issued IDevID over mTLS,
and exchanges it for a Vault AppRole `role_id`/`secret_id` pair that becomes the device's working
identity for the rest of its life.

**No manufacturing/production-line tooling — the thing that actually generates the IDevID keypair,
issues the certificate, records the device's serial-to-identity mapping, and registers that identity
with the provisioning broker's trust store — exists anywhere in this repo.** Three design docs are
referenced by name in `device-commission.py`'s own docstring as the source of truth for this process
(`docs/kms/reset-recovery-dual-identity-plan.md`, `docs/kms/provision-server-commission-endpoint-plan.md`,
`docs/kms/device-field-provisioning-plan.md`) — **none of the three exist in this repository.** This
mirrors a pattern already flagged elsewhere in this repo's docs (broken references to
non-existent provisioning plan docs, per `commission-flow-vault-approle-wait-fix.md`'s own Context
section) — the production-line provisioning design was never checked into this codebase, or lives
somewhere else entirely.

### 2.2 Confirmed live gap: the provisioning broker rejects real commission attempts

This isn't a hypothetical gap — a live DUT test (2026-07-30,
`tests/dut/device-commission/README.md` §"Live commission round-trip against
`provision.csyang.org:8443`") attempted a real network commission and found:

- DNS resolves; a raw TLS handshake against the broker succeeds with a valid Let's Encrypt cert —
  the broker does **not** enforce client-certificate validation at the TLS layer.
- The device-side mTLS mechanism itself is confirmed entirely correct: `TPM2EngineSSLContext`
  completed a full mTLS handshake using a disposable test IDevID and sent a well-formed MQTT CONNECT.
- **The broker closed the connection immediately with no CONNACK** — pointing at rejection at the
  MQTT/application layer (untrusted CA and/or an unregistered `device_id`), not a client bug.
- The test's own conclusion: *"the broker's trust configuration (which CAs it accepts, how a
  `device_id` maps to a Vault AppRole) and the Vault `pki_idevid` mount/AppRole prerequisites are
  owned by Vault/broker administration, not this codebase. A real end-to-end commission requires a
  manufacturing-enrolled IDevID whose CA the broker actually trusts."*

In plain terms: **the device firmware's half of first-boot commissioning is built, tested, and
correct. The production-line half — issuing a real IDevID and telling the provisioning broker to
trust its CA — does not exist yet, or exists somewhere SVS/manufacturing-ops owns that this repo has
no visibility into.** Every device shipped today cannot complete real field commissioning until this
is resolved.

### 2.3 A related, smaller finding

`tests/dut/provisioning-lifecycle/README.md` also notes `/var/persist/idevid` was found `0777` on
the DUT it tested against — broader than intended, though separately flagged as "not fixed here."
Worth folding into whatever manufacturing-line provisioning fix work happens, since the IDevID
private key file lives under that directory.

### 2.4 The ask

1. **Locate the actual production-line provisioning tooling** — if it exists outside this repo
   (a manufacturing-station script, an HSM-backed batch issuance tool, a vendor programming station),
   WNC needs to know it exists and how it maps device serials → IDevID certs → the broker's trust
   store, even if WNC never operates it directly.
2. **Fix the broker-side trust gap** confirmed by the 2026-07-30 test — register whatever CA signs
   manufacturing-issued IDevID certs with `provision.csyang.org`'s accepted-CA list, and confirm the
   `device_id`-to-AppRole mapping logic the broker uses.
3. **Recover or rewrite the three missing design docs** (`docs/kms/reset-recovery-dual-identity-plan.md`,
   `docs/kms/provision-server-commission-endpoint-plan.md`, `docs/kms/device-field-provisioning-plan.md`)
   so the manufacturing-enrollment process has one canonical description both teams can point to —
   right now the only description of what manufacturing is supposed to do lives in code comments and
   test-README asides.
4. Confirm whether `provision.csyang.org` is a production-line-only service (used once per device,
   at first boot) or also serves post-reset recommissioning in the field — `device-commission.py`
   handles both cases identically today, so this affects whether SVS needs to keep the provisioning
   broker reachable from the field indefinitely, not just on the factory floor.

## Side Effects & Caveats

- This document changes no code, recipe, config, or running service.
- The CrowdSec, rsyslog, and device-commission findings above are all read from source/config
  already in this repo, or from dated test-run READMEs recording live DUT results — none are
  speculative.
- The three "missing" `docs/kms/*.md` files are confirmed absent by direct path check in this repo
  at the time of writing; they may exist in a different repo or wiki this session has no access to —
  worth confirming with whoever wrote `device-commission.py` before assuming they need to be
  recreated from scratch.
- The broker-rejection finding (§2.2) used a **disposable test IDevID**, not a real
  manufacturing-issued one — it confirms the broker rejects an untrusted identity (expected
  behavior), not that a genuine manufacturing-issued IDevID would also fail. The real gap is that no
  one on the WNC side can currently test the positive case, since no manufacturing-issued IDevID
  trust relationship exists to test against.
