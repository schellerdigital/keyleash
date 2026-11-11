#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Software-TPM mit Resource-Manager starten (Modus KEYLEASH_TPM=swtpm).
#   swtpm-start.sh          starten
#   swtpm-start.sh reboot   Neustart simulieren (TPM-Reset: resetCount +1, PCRs zurückgesetzt)
#   swtpm-start.sh stop     beenden
set -euo pipefail
LAB=$(cd "$(dirname "$0")/.." && pwd)
source "$LAB/lib/i18n.sh"
export PATH="$PATH:/usr/sbin:/sbin"   # Debian: tpm2-abrmd liegt in /usr/sbin / lives in /usr/sbin
ST=$LAB/state/swtpm; mkdir -p "$ST/tpm"
BUS=unix:path=$ST/dbus.sock

stop_all() {
  # Ordnungsgemäß herunterfahren, sonst zählt das TPM einen möglichen Angriff (DA-Zähler)
  if [ -f "$ST/swtpm.pid" ] && kill -0 "$(cat "$ST/swtpm.pid")" 2>/dev/null; then
    DBUS_SESSION_BUS_ADDRESS=$BUS TPM2TOOLS_TCTI=tabrmd:bus_type=session tpm2_shutdown -c 2>/dev/null || true
  fi
  [ -f "$ST/abrmd.pid" ] && kill "$(cat "$ST/abrmd.pid")" 2>/dev/null || true
  [ -f "$ST/swtpm.pid" ] && kill "$(cat "$ST/swtpm.pid")" 2>/dev/null || true
  sleep 1; rm -f "$ST"/{abrmd,swtpm}.pid
}

start_tpm() {
  local fresh=0; [ -n "$(ls -A "$ST/tpm" 2>/dev/null)" ] || fresh=1
  swtpm socket --tpmstate dir="$ST/tpm" --tpm2 --server type=tcp,port=2321 \
        --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear \
        --pid file="$ST/swtpm.pid" --daemon
  sleep 0.5
  [ -S "$ST/dbus.sock" ] || { dbus-daemon --session --address="$BUS" --fork --print-pid > "$ST/dbus.pid"; sleep 0.3; }
  DBUS_SESSION_BUS_ADDRESS=$BUS nohup tpm2-abrmd --session --allow-root --tcti=swtpm:port=2321 \
        --flush-all > "$ST/abrmd.log" 2>&1 & echo $! > "$ST/abrmd.pid"
  sleep 1
  if [ $fresh = 1 ]; then
    # Neues Software-TPM: Schutz gegen Fehlversuche wie bei Hardware-TPMs (Intel PTT: 32 Versuche).
    # swtpm erlaubt ab Werk nur 3; ältere Versionen zählen auch abgelehnte Policies mit.
    DBUS_SESSION_BUS_ADDRESS=$BUS TPM2TOOLS_TCTI=tabrmd:bus_type=session \
      tpm2_dictionarylockout --setup-parameters --max-tries=32 --recovery-time=600 --lockout-recovery-time=600 >/dev/null 2>&1 || true
  fi
}

case "${1:-start}" in
  start)  stop_all; start_tpm; echo "$(t 'swtpm läuft. Für die Shell:' 'swtpm is running. For your shell:')  export DBUS_SESSION_BUS_ADDRESS=$BUS" ;;
  reboot) # wie beim echten Reboot: stop_all sendet TPM2_Shutdown
          stop_all; start_tpm; echo "$(t 'Software-TPM neu gestartet (simulierter Reboot).' 'Software TPM restarted (simulated reboot).')" ;;
  stop)   stop_all; [ -f "$ST/dbus.pid" ] && kill "$(cat "$ST/dbus.pid")" 2>/dev/null; rm -f "$ST"/dbus.{pid,sock}; echo "$(t gestoppt. stopped.)" ;;
esac
