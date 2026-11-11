#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# TPM-Uhr als Sensor: Stromausfall (safe = NO), Snapshot/Klon (Rücksprung), angehaltene VM (Gangabweichung)
# TPM clock as a sensor: power loss (safe = NO), snapshot/clone (rollback), paused VM (clock drift)
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
echo x > "$W/u.txt"
upd=$(tpm2_getcap properties-fixed 2>/dev/null | grep -A1 TPM2_PT_CLOCK_UPDATE | grep -oP 'raw: \K\S+')
title "$(t 'TPM-Uhr als Sensor' 'TPM clock as a sensor')"
note "$(t "Das TPM sichert seine Uhr alle $((upd)) ms. Fällt der Strom aus, startet die Uhr beim letzten gesicherten Stand und meldet safe = NO." "The TPM persists its clock every $((upd)) ms. After a power loss the clock restarts at the last persisted value and reports safe = NO.")"
note "$(t 'Jedes Ticket verlangt safe = YES. Sonst ließe sich die Laufzeit durch wiederholtes Stromabschalten strecken.' 'Every ticket requires safe = YES. Otherwise the lifetime could be stretched by cutting power repeatedly.')"

if [ "$KEYLEASH_TPM" != swtpm ]; then
  $AG status
  note "$(t 'Stromausfall, Snapshot und Klon lassen sich nur mit dem Software-TPM gefahrlos simulieren (KEYLEASH_TPM=swtpm).' 'Power loss, snapshot and clone can only be simulated safely with the software TPM (KEYLEASH_TPM=swtpm).')"
  exit 0
fi
SW=$LAB/state/swtpm

# --- 1. Stromausfall ---------------------------------------------------------
title "$(t '1. Stromausfall: Uhr fällt zurück' '1. Power loss: the clock falls back')"
pause_min_interval; $AG renew; pause_min_interval
step "$(t 'Strom weg: Software-TPM hart beenden, ohne TPM2_Shutdown' 'Power cut: kill the software TPM hard, without TPM2_Shutdown')"
kill -9 "$(cat "$SW/swtpm.pid")" "$(cat "$SW/abrmd.pid")" 2>/dev/null; sleep 1
rm -f "$SW"/{swtpm,abrmd}.pid
"$LAB/tools/swtpm-start.sh" >/dev/null
# Ein harter Stromausfall zählt das TPM als möglichen Angriff (DA-Zähler +1). Im Lab sofort zurücksetzen,
# im Betrieb ist das eine bewusste Entscheidung des Lockout-Berechtigten.
tpm2_dictionarylockout -c >/dev/null 2>&1 || true
# Das Software-TPM sichert seine Uhr nach wenigen Sekunden wieder, daher zügig hintereinander.
step "$(t 'Signieren mit dem alten Ticket' 'Signing with the old ticket')"
if $AG sign "$W/u.txt" -o "$W/u.sig" >"$W/out" 2>&1; then
  note "$(t "Uhr war schon wieder gesichert (Software-TPM: alle $((upd)) ms), das alte Ticket gilt wieder." "Clock was already persisted again (software TPM: every $((upd)) ms), the old ticket is valid again.")"
else
  echo "  ${G}✔ $(t 'wie erwartet verweigert' 'refused as expected'):${N} $(tail -1 "$W/out" | sed 's/^ *//')"
fi
step "$(t 'Erneuern, solange die Uhr unsicher ist' 'Renew while the clock is unsafe')"
$AG renew
$AG status
if python3 -c "import json,sys;sys.exit(0 if json.load(open('$ST/ticket.json')).get('pin_resets') else 1)"; then
  note "$(t 'Server: Ticket nur für diesen Systemstart (resetCount exakt), Meldung im SIEM.' 'Server: ticket for this boot only (exact resetCount), event in the SIEM.')"
  $AG sign "$W/u.txt" -o "$W/u.sig"
  step "$(t 'Neustart mit diesem Ticket' 'Reboot with this ticket')"
  "$LAB/tools/swtpm-start.sh" reboot >/dev/null
  expect_fail $AG sign "$W/u.txt" -o "$W/u.sig"
  note "$(t 'Ein Neustart könnte die Uhr erneut zurückwerfen, darum gilt dieses Ticket nicht darüber hinaus.' 'A reboot could throw the clock back again, so this ticket does not survive it.')"
else
  note "$(t 'Die Uhr war beim Erneuern schon wieder gesichert, das Ticket ist ein normales.' 'The clock was already persisted again at renewal, so this is a normal ticket.')"
fi
siem_tail 3

# --- 2. Snapshot / Klon ------------------------------------------------------
title "$(t '2. Snapshot oder Klon: älterer TPM-Zustand meldet sich' '2. Snapshot or clone: an older TPM state reports in')"
step "$(t 'Snapshot des TPM-Zustands (wie VM-Snapshot oder kopierter vTPM)' 'Snapshot of the TPM state (like a VM snapshot or a copied vTPM)')"
DBUS_SESSION_BUS_ADDRESS=unix:path=$SW/dbus.sock tpm2_shutdown -c 2>/dev/null || true
cp -a "$SW/tpm" "$W/tpm-snapshot"
"$LAB/tools/swtpm-start.sh" >/dev/null
pause_min_interval; $AG renew
step "$(t 'Original läuft weiter: Neustart und Erneuern' 'The original keeps running: reboot and renew')"
"$LAB/tools/swtpm-start.sh" reboot >/dev/null
pause_min_interval; $AG renew
step "$(t 'Der Snapshot (Klon) startet und fragt an' 'The snapshot (clone) starts and asks for a ticket')"
"$LAB/tools/swtpm-start.sh" stop >/dev/null
rm -rf "$SW/tpm.orig"; mv "$SW/tpm" "$SW/tpm.orig"; cp -a "$W/tpm-snapshot" "$SW/tpm"
"$LAB/tools/swtpm-start.sh" >/dev/null
pause_min_interval
expect_fail $AG renew
note "$(t 'resetCount liegt unter dem zuletzt gesehenen Wert: zweiter, älterer TPM-Zustand. Alarm, kein Ticket.' 'resetCount is below the last value seen: a second, older TPM state. Alert, no ticket.')"
step "$(t 'Original wiederherstellen' 'Restore the original')"
"$LAB/tools/swtpm-start.sh" stop >/dev/null
rm -rf "$SW/tpm"; mv "$SW/tpm.orig" "$SW/tpm"; rm -rf "$W/tpm-snapshot"
"$LAB/tools/swtpm-start.sh" >/dev/null
siem_tail 2

# --- 3. Angehaltene VM -------------------------------------------------------
title "$(t '3. Gangabweichung: TPM-Uhr und Serveruhr laufen auseinander' '3. Drift: TPM clock and server clock diverge')"
pause_min_interval; $AG renew
step "$(t 'Simulation: Zeitpunkt der letzten Erneuerung am Server um 120 s vordatieren' 'Simulation: move the last renewal on the server 120 s into the past')"
note "$(t 'Das entspricht einer VM, die 120 s angehalten war: Die Welt lief weiter, die TPM-Uhr nicht.' 'This equals a VM that was paused for 120 s: the world moved on, the TPM clock did not.')"
"$LAB/tools/server.sh" stop >/dev/null; sleep 1
python3 - "$LAB/state/server/hosts.json" "$(jq_host)" <<'P'
import json, sys
p, host = sys.argv[1], sys.argv[2]
h = json.load(open(p)); h[host]["last"]["ts"] -= 120
json.dump(h, open(p, "w"), indent=2)
P
ensure_server
$AG renew
note "$(t 'Nur Warnung, keine Verweigerung: Auch Live-Migration oder Ruhezustand können das auslösen. Der Kontext entscheidet im SIEM.' 'Warning only, no refusal: live migration or suspend can trigger it too. The context decides in the SIEM.')"
siem_tail 2
