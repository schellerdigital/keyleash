#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Neustart-Grenze: Ticket gilt nur für N Neustarts (resetCount im TPM)
# Reboot limit: a ticket is valid for N reboots only (resetCount in the TPM)
source "$(dirname "$0")/common.sh"
ensure_enrolled
title "$(t 'Neustart-Grenze' 'Reboot limit') (KEYLEASH_MAX_RESETS=$KEYLEASH_MAX_RESETS)"
echo x > "$W/n.txt"
if [ "$KEYLEASH_TPM" = swtpm ]; then
  ensure_server; pause_min_interval; $AG renew --ttl 3600
  for i in $(seq 1 $((KEYLEASH_MAX_RESETS+1))); do
    step "$(t 'Simulierter Neustart' 'Simulated reboot') $i"
    "$LAB/tools/swtpm-start.sh" reboot >/dev/null
    $AG status
    if [ "$i" -le "$KEYLEASH_MAX_RESETS" ]; then $AG sign "$W/n.txt" -o "$W/n.sig"
    else expect_fail $AG sign "$W/n.txt" -o "$W/n.sig"; fi
  done
  note "$(t 'Die TPM-Uhr läuft nur mit Strom und kann nach einem Neustart zurückliegen.' 'The TPM clock only runs while powered and can be behind after a reboot.')"
  note "$(t 'Ohne die Neustart-Grenze ließe sich die Laufzeit so strecken.' 'Without the reboot limit, the lifetime could be stretched that way.')"
  exit 0
fi
case "${1:-}" in
  ""|--neu)
    if [ -f "$W/reboot-ticket.json" ] && [ "${1:-}" != --neu ]; then
      echo "${Y}$(t 'Es gibt schon ein gesichertes Test-Ticket. Nach einem Neustart:' 'A saved test ticket already exists. After a reboot:')  $0 pruefen${N}"
      echo "${Y}$(t 'Neues Test-Ticket (setzt den Test zurück):' 'New test ticket (resets the test):')  $0 --neu${N}"; exit 1
    fi
    # Der Server deckelt die Laufzeit auf KEYLEASH_TTL (600 s). Für den Test kurz
    # mit 1 h Höchstlaufzeit starten und danach wieder stoppen, damit nichts erneuert.
    "$LAB/tools/server.sh" stop >/dev/null; sleep 1
    server_running && { echo "${R}$(t 'Ein Server läuft noch (tools/server.sh vorne?) – dort mit Strg+C beenden und neu starten.' 'A server is still running (tools/server.sh vorne?) – stop it there with Ctrl+C and start again.')${N}"; exit 1; }
    KEYLEASH_TTL=3600 nohup python3 "$LAB/server/authz_server.py" >> "$LAB/state/server.log" 2>&1 &
    echo $! > "$LAB/state/server.pid"
    for _ in $(seq 20); do server_running && break; sleep 0.3; done
    pause_min_interval; $AG renew --ttl 3600; rc=$?
    "$LAB/tools/server.sh" stop >/dev/null
    [ $rc = 0 ] || exit 1
    cp "$ST/ticket.json" "$W/reboot-ticket.json"
    $AG status
    note "$(t 'Ticket mit 1 h Laufzeit gesichert, Server gestoppt (kein Erneuern möglich).' 'Ticket with a 1 h lifetime saved, server stopped (no renewal possible).')"
    note "$(t 'Bitte das System neu starten und danach ausführen:' 'Please reboot the system and then run:')  $0 pruefen"
    note "$(t "Nach jedem Neustart erneut prüfen. Nach $((KEYLEASH_MAX_RESETS+1)) Neustarts muss das TPM verweigern." "Check again after every reboot. After $((KEYLEASH_MAX_RESETS+1)) reboots the TPM must refuse.")" ;;
  pruefen|check)
    [ -f "$W/reboot-ticket.json" ] || { echo "$(t 'erst ohne Argument starten' 'run without an argument first')"; exit 1; }
    cp "$W/reboot-ticket.json" "$ST/ticket.json"
    $AG status
    $AG sign "$W/n.txt" -o "$W/n.sig" || note "→ $(t 'TPM verweigert (Grenze oder Ablauf erreicht)' 'TPM refuses (limit or expiry reached)')" ;;
esac
