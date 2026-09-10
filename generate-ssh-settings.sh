#!/usr/bin/env bash
set -euo pipefail
umask 077

# This script uses the existing Vault CLI login/session. It writes only the
# requested settings to temp.env; the internal mount names and token lifetime
# are not emitted.
readonly OUTPUT_FILE="temp.env"
readonly TOKEN_TTL="720h"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

command -v vault >/dev/null 2>&1 || die "vault CLI is required"
vault token lookup >/dev/null 2>&1 || die "authenticate first with: vault login"

[[ ! -e "$OUTPUT_FILE" ]] || die "$OUTPUT_FILE already exists; move it before rerunning"

# Fixed plane-to-mount mapping. These names are not written to temp.env.
readonly USER_MOUNT_HOST="ssh_user_host"
readonly USER_MOUNT_OTNS="ssh_user_otns"
readonly USER_MOUNT_DMZNS="ssh_user_dmzns"
readonly USER_MOUNT_ITNS="ssh_user_itns"

readonly HOST_MOUNT_HOST="ssh_host_host"
readonly HOST_MOUNT_OTNS="ssh_host_otns"
readonly HOST_MOUNT_DMZNS="ssh_host_dmzns"
readonly HOST_MOUNT_ITNS="ssh_host_itns"

# Existing Vault role names. Change these constants only if the configured
# Vault role names differ.
readonly VAULT_SSH_USER_ROLE_HOST_ADMIN="host-admin-login"
readonly VAULT_SSH_USER_ROLE_AUDITOR="auditor-login"
readonly VAULT_SSH_USER_ROLE_OT_ADMIN="ot-admin-login"
readonly VAULT_SSH_USER_ROLE_OT_OPERATOR="ot-operator-login"
readonly VAULT_SSH_USER_ROLE_DMZ_ADMIN="dmz-admin-login"
readonly VAULT_SSH_USER_ROLE_IT_ADMIN="it-admin-login"

readonly VAULT_SSH_HOST_ROLE_HOST="host-cert-host"
readonly VAULT_SSH_HOST_ROLE_OTNS="host-cert-otns"
readonly VAULT_SSH_HOST_ROLE_DMZNS="host-cert-dmzns"
readonly VAULT_SSH_HOST_ROLE_ITNS="host-cert-itns"

check_ca() {
    local mount="$1"
    vault read -field=public_key "$mount/config/ca" >/dev/null \
        || die "CA is missing or inaccessible: $mount"
}

check_role() {
    local mount="$1"
    local role="$2"
    vault read "$mount/roles/$role" >/dev/null \
        || die "Vault role is missing: $mount/roles/$role"
}

issue_token() {
    local policy="$1"
    vault token create \
        -field=token \
        -orphan \
        -no-default-policy \
        -renewable=false \
        -ttl="$TOKEN_TTL" \
        -policy="$policy"
}

write_sign_policy() {
    local policy="$1"
    local mount="$2"
    local role="$3"

    vault policy write "$policy" - >/dev/null <<EOF
path "$mount/sign/$role" {
  capabilities = ["create", "update"]
}
EOF
}

for mount in \
    "$USER_MOUNT_HOST" \
    "$USER_MOUNT_OTNS" \
    "$USER_MOUNT_DMZNS" \
    "$USER_MOUNT_ITNS" \
    "$HOST_MOUNT_HOST" \
    "$HOST_MOUNT_OTNS" \
    "$HOST_MOUNT_DMZNS" \
    "$HOST_MOUNT_ITNS"
do
    check_ca "$mount"
done

check_role "$USER_MOUNT_HOST" "$VAULT_SSH_USER_ROLE_HOST_ADMIN"
check_role "$USER_MOUNT_HOST" "$VAULT_SSH_USER_ROLE_AUDITOR"
check_role "$USER_MOUNT_OTNS" "$VAULT_SSH_USER_ROLE_OT_ADMIN"
check_role "$USER_MOUNT_OTNS" "$VAULT_SSH_USER_ROLE_OT_OPERATOR"
check_role "$USER_MOUNT_DMZNS" "$VAULT_SSH_USER_ROLE_DMZ_ADMIN"
check_role "$USER_MOUNT_ITNS" "$VAULT_SSH_USER_ROLE_IT_ADMIN"

check_role "$HOST_MOUNT_HOST" "$VAULT_SSH_HOST_ROLE_HOST"
check_role "$HOST_MOUNT_OTNS" "$VAULT_SSH_HOST_ROLE_OTNS"
check_role "$HOST_MOUNT_DMZNS" "$VAULT_SSH_HOST_ROLE_DMZNS"
check_role "$HOST_MOUNT_ITNS" "$VAULT_SSH_HOST_ROLE_ITNS"

vault policy write ssh-ca-read-all - >/dev/null <<EOF
path "$USER_MOUNT_HOST/config/ca" {
  capabilities = ["read"]
}
path "$USER_MOUNT_OTNS/config/ca" {
  capabilities = ["read"]
}
path "$USER_MOUNT_DMZNS/config/ca" {
  capabilities = ["read"]
}
path "$USER_MOUNT_ITNS/config/ca" {
  capabilities = ["read"]
}
path "$HOST_MOUNT_HOST/config/ca" {
  capabilities = ["read"]
}
path "$HOST_MOUNT_OTNS/config/ca" {
  capabilities = ["read"]
}
path "$HOST_MOUNT_DMZNS/config/ca" {
  capabilities = ["read"]
}
path "$HOST_MOUNT_ITNS/config/ca" {
  capabilities = ["read"]
}
EOF

VAULT_SSH_CA_READ_TOKEN="$(issue_token ssh-ca-read-all)"

write_sign_policy ssh-sign-user-host-admin \
    "$USER_MOUNT_HOST" "$VAULT_SSH_USER_ROLE_HOST_ADMIN"
VAULT_SSH_USER_TOKEN_HOST_ADMIN="$(issue_token ssh-sign-user-host-admin)"

write_sign_policy ssh-sign-user-auditor \
    "$USER_MOUNT_HOST" "$VAULT_SSH_USER_ROLE_AUDITOR"
VAULT_SSH_USER_TOKEN_AUDITOR="$(issue_token ssh-sign-user-auditor)"

write_sign_policy ssh-sign-user-ot-admin \
    "$USER_MOUNT_OTNS" "$VAULT_SSH_USER_ROLE_OT_ADMIN"
VAULT_SSH_USER_TOKEN_OT_ADMIN="$(issue_token ssh-sign-user-ot-admin)"

write_sign_policy ssh-sign-user-ot-operator \
    "$USER_MOUNT_OTNS" "$VAULT_SSH_USER_ROLE_OT_OPERATOR"
VAULT_SSH_USER_TOKEN_OT_OPERATOR="$(issue_token ssh-sign-user-ot-operator)"

write_sign_policy ssh-sign-user-dmz-admin \
    "$USER_MOUNT_DMZNS" "$VAULT_SSH_USER_ROLE_DMZ_ADMIN"
VAULT_SSH_USER_TOKEN_DMZ_ADMIN="$(issue_token ssh-sign-user-dmz-admin)"

write_sign_policy ssh-sign-user-it-admin \
    "$USER_MOUNT_ITNS" "$VAULT_SSH_USER_ROLE_IT_ADMIN"
VAULT_SSH_USER_TOKEN_IT_ADMIN="$(issue_token ssh-sign-user-it-admin)"

write_sign_policy ssh-sign-host-host \
    "$HOST_MOUNT_HOST" "$VAULT_SSH_HOST_ROLE_HOST"
VAULT_SSH_HOST_TOKEN_HOST="$(issue_token ssh-sign-host-host)"

write_sign_policy ssh-sign-host-otns \
    "$HOST_MOUNT_OTNS" "$VAULT_SSH_HOST_ROLE_OTNS"
VAULT_SSH_HOST_TOKEN_OTNS="$(issue_token ssh-sign-host-otns)"

write_sign_policy ssh-sign-host-dmzns \
    "$HOST_MOUNT_DMZNS" "$VAULT_SSH_HOST_ROLE_DMZNS"
VAULT_SSH_HOST_TOKEN_DMZNS="$(issue_token ssh-sign-host-dmzns)"

write_sign_policy ssh-sign-host-itns \
    "$HOST_MOUNT_ITNS" "$VAULT_SSH_HOST_ROLE_ITNS"
VAULT_SSH_HOST_TOKEN_ITNS="$(issue_token ssh-sign-host-itns)"

TEMP_FILE="$(mktemp "${OUTPUT_FILE}.XXXXXX")"
trap 'rm -f "$TEMP_FILE"' EXIT

{
    printf 'VAULT_SSH_CA_READ_TOKEN=%s\n' "$VAULT_SSH_CA_READ_TOKEN"

    printf 'VAULT_SSH_USER_ROLE_HOST_ADMIN=%s\n' "$VAULT_SSH_USER_ROLE_HOST_ADMIN"
    printf 'VAULT_SSH_USER_TOKEN_HOST_ADMIN=%s\n' "$VAULT_SSH_USER_TOKEN_HOST_ADMIN"
    printf 'VAULT_SSH_USER_ROLE_AUDITOR=%s\n' "$VAULT_SSH_USER_ROLE_AUDITOR"
    printf 'VAULT_SSH_USER_TOKEN_AUDITOR=%s\n' "$VAULT_SSH_USER_TOKEN_AUDITOR"

    printf 'VAULT_SSH_USER_ROLE_OT_ADMIN=%s\n' "$VAULT_SSH_USER_ROLE_OT_ADMIN"
    printf 'VAULT_SSH_USER_TOKEN_OT_ADMIN=%s\n' "$VAULT_SSH_USER_TOKEN_OT_ADMIN"
    printf 'VAULT_SSH_USER_ROLE_OT_OPERATOR=%s\n' "$VAULT_SSH_USER_ROLE_OT_OPERATOR"
    printf 'VAULT_SSH_USER_TOKEN_OT_OPERATOR=%s\n' "$VAULT_SSH_USER_TOKEN_OT_OPERATOR"

    printf 'VAULT_SSH_USER_ROLE_DMZ_ADMIN=%s\n' "$VAULT_SSH_USER_ROLE_DMZ_ADMIN"
    printf 'VAULT_SSH_USER_TOKEN_DMZ_ADMIN=%s\n' "$VAULT_SSH_USER_TOKEN_DMZ_ADMIN"
    printf 'VAULT_SSH_USER_ROLE_IT_ADMIN=%s\n' "$VAULT_SSH_USER_ROLE_IT_ADMIN"
    printf 'VAULT_SSH_USER_TOKEN_IT_ADMIN=%s\n' "$VAULT_SSH_USER_TOKEN_IT_ADMIN"

    printf 'VAULT_SSH_HOST_ROLE_HOST=%s\n' "$VAULT_SSH_HOST_ROLE_HOST"
    printf 'VAULT_SSH_HOST_TOKEN_HOST=%s\n' "$VAULT_SSH_HOST_TOKEN_HOST"
    printf 'VAULT_SSH_HOST_ROLE_OTNS=%s\n' "$VAULT_SSH_HOST_ROLE_OTNS"
    printf 'VAULT_SSH_HOST_TOKEN_OTNS=%s\n' "$VAULT_SSH_HOST_TOKEN_OTNS"
    printf 'VAULT_SSH_HOST_ROLE_DMZNS=%s\n' "$VAULT_SSH_HOST_ROLE_DMZNS"
    printf 'VAULT_SSH_HOST_TOKEN_DMZNS=%s\n' "$VAULT_SSH_HOST_TOKEN_DMZNS"
    printf 'VAULT_SSH_HOST_ROLE_ITNS=%s\n' "$VAULT_SSH_HOST_ROLE_ITNS"
    printf 'VAULT_SSH_HOST_TOKEN_ITNS=%s\n' "$VAULT_SSH_HOST_TOKEN_ITNS"
} >"$TEMP_FILE"

chmod 600 "$TEMP_FILE"
mv "$TEMP_FILE" "$OUTPUT_FILE"
trap - EXIT

echo "Created $OUTPUT_FILE with exactly 21 settings."

