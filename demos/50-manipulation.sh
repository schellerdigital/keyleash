#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Abweichender Boot-Zustand: simuliert über das Debug-PCR 16
# Deviating boot state: simulated via debug PCR 16
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
grep -q '16' <<<"$KEYLEASH_PCRS" || { echo "$(t 'PCR 16 ist nicht in KEYLEASH_PCRS – Demo nicht möglich' 'PCR 16 is not in KEYLEASH_PCRS – demo not possible')"; exit 1; }
title "$(t 'Manipulierter Boot-Zustand' 'Tampered boot state')"
pause_min_interval
$AG renew
echo x > "$W/m.txt"
step "$(t 'Simulierte Manipulation: PCR 16 wird erweitert' 'Simulated tampering: PCR 16 is extended')"
tpm2_pcrextend 16:sha256=$(echo -n "manipulation" | sha256sum | cut -c1-64)
step "$(t 'Signieren mit dem noch gültigen Ticket' 'Signing with the still valid ticket')"
expect_fail $AG sign "$W/m.txt" -o "$W/m.sig"
note "$(t 'Das Ticket ist an den gemessenen Zustand gebunden (PolicyPCR) – sofort wirkungslos.' 'The ticket is bound to the measured state (PolicyPCR) – useless immediately.')"
pause_min_interval
step "$(t 'Neues Ticket anfordern' 'Request a new ticket')"
expect_fail $AG renew
step "$(t 'Zustand zurücksetzen (PCR 16 ist rücksetzbar) und erneut anfordern' 'Reset the state (PCR 16 is resettable) and request again')"
tpm2_pcrreset 16
pause_min_interval
$AG renew
siem_tail 3
