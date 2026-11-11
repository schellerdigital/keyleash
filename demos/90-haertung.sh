#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Härtung Stufe 1 vorführen (nach sudo harden/harden.sh)
# Demonstrate hardening level 1 (after sudo harden/harden.sh)
source "$(dirname "$0")/common.sh"
CL="python3 $LAB/harden/signer-client.py"
P_OK=$(t beleg receipt)
title "$(t 'Härtung Stufe 1: Prozess-Isolation' 'Hardening level 1: process isolation')"
systemctl is-active --quiet keyleash-signer || { echo "${R}$(t 'Dienst läuft nicht – zuerst:' 'Service not running – first:') sudo harden/harden.sh${N}"; exit 1; }

step "$(t 'Status des Signaturdienstes' 'Signing service status')"
# Nach einem Neustart braucht der Dienst ein paar Sekunden, bis sein Socket antwortet
for _ in $(seq 15); do $CL status > "$W/signer-status.json" 2>/dev/null && break; sleep 1; done
python3 -c "import json;json.load(open('$W/signer-status.json'))" 2>/dev/null || {
  echo "  ${R}✘ $(t 'Signaturdienst antwortet nicht – journalctl -u keyleash-signer prüfen' 'Signing service does not respond – check journalctl -u keyleash-signer')${N}"; exit 1; }
sed 's/^/  /' "$W/signer-status.json"
PID=$(python3 -c "import json;print(json.load(open('$W/signer-status.json'))['pid'])")
ADDR=$(python3 -c "import json;print(json.load(open('$W/signer-status.json'))['secret_addr'])")

step "$(t "Erlaubter Zweck: Beleg signieren lassen, Gegenstelle prüft" "Allowed purpose: have a receipt signed, relying party verifies")"
echo "$(t Beleg Receipt) $(date -Is)" > "$W/doc.txt"
$CL sign "$P_OK" "$W/doc.txt" -o "$W/doc-signer.sig" && \
  verify/verify.sh "$W/doc.txt" "$W/doc-signer.sig" /etc/keyleash/signer-cert.pem /etc/keyleash/ca.pem

step "$(t 'Nicht erlaubter Zweck – der geschützte Prozess entscheidet' 'Purpose not allowed – the protected process decides')"
expect_fail $CL sign "$(t beliebig arbitrary)" "$W/doc.txt" -o "$W/x.sig"

step "$(t 'Als normaler Benutzer an Schlüssel oder Geheimnis?' 'Reach the key or secret as a normal user?')"
expect_fail ls /var/lib/keyleash
expect_fail cat /proc/$PID/environ

step "$(t 'Als root den Prozessspeicher mit dem Geheimnis lesen' 'As root, read the process memory holding the secret') (/proc/$PID/mem @ $ADDR)"
note "$(t 'sudo-Passwort wird abgefragt' 'sudo will ask for your password')"
sudo python3 - "$PID" "$ADDR" "$KEYLEASH_LANG" <<'P'
import sys
en = sys.argv[3].startswith("en")
T = lambda de, eng: eng if en else de
pid, addr = int(sys.argv[1]), int(sys.argv[2], 16)
try:
    with open(f"/proc/{pid}/mem", "rb") as f:
        f.seek(addr); data = f.read(16)
    print(f"  \033[31m✘ {T('gelesen', 'read')}: {data!r}  ({T('memfd_secret nicht aktiv?', 'memfd_secret not active?')})\033[0m")
except PermissionError:
    print(T("  ✔ verweigert (EPERM): ptrace_scope=3 bzw. AppArmor blockiert den Zugriff",
            "  ✔ refused (EPERM): ptrace_scope=3 or AppArmor blocks the access"))
except OSError as e:
    print(T(f"  ✔ verweigert ({e.strerror}): Seite liegt in memfd_secret, nicht in der Kernel-Abbildung",
            f"  ✔ refused ({e.strerror}): the page lives in memfd_secret, not in the kernel mapping"))
P
step "$(t 'Kernel-Einstellungen' 'Kernel settings')"
echo "  ptrace_scope = $(cat /proc/sys/kernel/yama/ptrace_scope)  ($(t '3 = kein ptrace, auch nicht für root' '3 = no ptrace, not even for root'))"
echo "  AppArmor     = $(cat /proc/$PID/attr/current 2>/dev/null || t unbekannt unknown)"
note "$(t 'Grenze der Stufe 1: root kann /var/lib/keyleash/key.auth lesen und selbst signieren,' 'Limit of level 1: root can read /var/lib/keyleash/key.auth and sign by itself')"
note "$(t 'solange ein Ticket gilt. Dagegen hilft erst Stufe 2 (TEE).' 'while a ticket is valid. Only level 2 (TEE) closes that.')"
step "$(t 'systemd-Bewertung' 'systemd assessment')"
systemd-analyze security keyleash-signer 2>/dev/null | tail -1 | sed 's/^/  /'
