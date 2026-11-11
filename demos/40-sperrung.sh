#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Sperrung: keine neuen Tickets, Signaturfähigkeit endet spätestens mit dem letzten Ticket
# Revocation: no new tickets; signing ends with the last ticket at the latest
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
TTL=${1:-20}
title "$(t Sperrung Revocation)"
pause_min_interval
$AG renew --ttl "$TTL"
step "$(t 'Administrator sperrt das System' 'Administrator revokes the host')"
admin revoke && echo "  $(t gesperrt revoked): $(jq_host)"
pause_min_interval
step "$(t 'Agent versucht Erneuerung' 'Agent tries to renew')"
expect_fail $AG renew
echo x > "$W/r.txt"
step "$(t 'Das letzte Ticket gilt noch – signieren klappt bis zum Ablauf' 'The last ticket is still valid – signing works until it expires')"
$AG sign "$W/r.txt" -o "$W/r.sig"
step "$(t 'Warte bis zum Ablauf …' 'Waiting for expiry …')"; sleep "$TTL"
expect_fail $AG sign "$W/r.txt" -o "$W/r.sig"
step "$(t Entsperren Reinstate)"
admin unrevoke && echo "  $(t entsperrt reinstated)"
siem_tail 4
