#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Signaturzählung: auffällige Signaturmengen und neue Zwecke erkennen
# (Antwort auf das Signaturorakel: kompromittierte, aber legitime Signaturumgebung)
#   65-signaturen.sh [BURST]   BURST = Zahl der Signaturen im Ausreißer (Standard 15)
# Signature counting: detect anomalous volumes and new purposes (answer to the signing oracle)
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
BURST=${1:-15}
echo "$(t Testdokument "Test document")" > "$W/s.txt"
P_NORMAL=$(t beleg receipt); P_NEW=$(t nachtbuild nightly-build)
sign_n() {  # Anzahl Zweck
  for _ in $(seq "$1"); do
    $AG sign "$W/s.txt" -o "$W/s.sig" --purpose "$2" >"$W/sign.out" 2>&1 || { echo "  ${R}✘ $(t 'Signieren fehlgeschlagen' 'Signing failed'):${N} $(tail -1 "$W/sign.out")"; return 1; }
  done
  echo "  $1 × $(t signiert signed) ($(t Zweck purpose): $2)"
}
title "$(t 'Signaturzählung: Lernphase' 'Signature counting: learning phase')"
note "$(t 'Referenz löschen und neu lernen (Server: sigreset)' 'Clear the baseline and learn again (server: sigreset)')"
admin sigreset
pause_min_interval; $AG renew >/dev/null && echo "  $(t 'Ticket erneuert, bisherige Zählung gemeldet' 'Ticket renewed, previous count reported')"
for i in 1 2 3; do
  sign_n 2 "$P_NORMAL" || exit 1
  pause_min_interval; $AG renew
done
title "$(t "Ausreißer: $BURST Signaturen mit neuem Zweck ($P_NEW)" "Outlier: $BURST signatures with a new purpose ($P_NEW)")"
note "$(t 'So sähe es aus, wenn ein Angreifer die legitime Signaturumgebung nutzt' 'This is what it looks like when an attacker uses the legitimate signing environment')"
sign_n "$BURST" "$P_NEW"
pause_min_interval; $AG renew
siem_tail 3

P_SPLIT=$(t export export)
title "$(t "Aufgeteilte Serie: 2 × 6 Signaturen mit neuem Zweck ($P_SPLIT)" "Split burst: 2 × 6 signatures with a new purpose ($P_SPLIT)")"
note "$(t 'Jede Erneuerung bleibt unter der Grenze pro Erneuerung – die Summe im Zeitfenster nicht' 'Each renewal stays under the per-renewal limit – the sum within the time window does not')"
sign_n 6 "$P_SPLIT" || exit 1
pause_min_interval; $AG renew
sign_n 6 "$P_SPLIT" || exit 1
pause_min_interval; $AG renew
siem_tail 2
note "$(t 'Grenze: Die Zählung meldet der Agent selbst. Gegen root auf dem System hilft sie nicht; für wertvolle Zwecke gilt die Freigabe (67-freigabe.sh).' 'Limit: the agent reports the count itself. It does not help against root on the system; valuable purposes need an approval (67-freigabe.sh).')"
note "$(t 'Standard: nur Alarm. Mit KEYLEASH_SIG_DENY=1 am Server wird das Ticket verweigert;' 'Default: alert only. With KEYLEASH_SIG_DENY=1 on the server the ticket is denied;')"
note "$(t 'freigeben danach mit:' 'release it afterwards with:') tools/server.sh sigreset $(jq_host)"
