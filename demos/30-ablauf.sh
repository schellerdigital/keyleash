#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Eigenschaft 2: ohne Erneuerung endet die Signaturfähigkeit von selbst
# Property 2: without renewal, the ability to sign ends on its own
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
TTL=${1:-15}
title "$(t "Ablauf: Ticket mit ${TTL}s Laufzeit" "Expiry: ticket with a ${TTL}s lifetime")"
pause_min_interval
$AG renew --ttl "$TTL"
echo "Test" > "$W/a.txt"
step "$(t 'Sofort signieren' 'Sign immediately')"
$AG sign "$W/a.txt" -o "$W/a.sig"
step "$(t "Warte $((TTL+3))s ohne Erneuerung …" "Waiting $((TTL+3))s without renewal …")"
sleep $((TTL+3))
$AG status
step "$(t 'Erneut signieren' 'Sign again')"
expect_fail $AG sign "$W/a.txt" -o "$W/a.sig"
note "$(t 'Das TPM selbst verweigert: PolicyCounterTimer gegen die TPM-Uhr. Keine Gegenstelle musste etwas prüfen.' 'The TPM itself refuses: PolicyCounterTimer against the TPM clock. No relying party had to check anything.')"
