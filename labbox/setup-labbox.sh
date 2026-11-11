#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Richtet labbox-1 als geschützte Maschine ein (läuft AUF der VM, als normaler Benutzer mit sudo).
# Sets up labbox-1 as the protected machine (runs ON the VM, as a normal user with sudo).
#
#   bash setup-labbox.sh --server http://GMKBOX:8740 --data http://GMKBOX:8741 [--lang de|en] [--ttl 30]
#
# 1. keyleash installieren (Rolle agent; fehlende Pakete per dnf/apt, ohne TPM: Software-TPM)
# 2. Maschinenidentität beim keyleash-Server provisionieren (Schlüssel im TPM)
# 3. Dienste: keyleash-agent (erneuert Tickets), keyleash-dashboard (geschützte Anwendung, Port 8080)
set -euo pipefail
SERVER=""; DATA=""; LANG_SEL=de; TTL=30; INST="$HOME/keyleash-install.sh"
while [ $# -gt 0 ]; do case "$1" in
  --server) SERVER=$2; shift 2;; --data) DATA=$2; shift 2;; --lang) LANG_SEL=$2; shift 2;;
  --ttl) TTL=$2; shift 2;; --installer) INST=$2; shift 2;;
  *) echo "?? $1"; exit 2;; esac; done
[ -n "$SERVER" ] && [ -n "$DATA" ] || { echo "--server und --data angeben / give --server and --data"; exit 2; }
t() { [ "$LANG_SEL" = en ] && printf '%s' "$2" || printf '%s' "$1"; }
step() { echo; echo "▶ $*"; }
LAB=$HOME/keyleash-lab; USR=$(id -un)

step "$(t 'keyleash installieren (Rolle agent)' 'Installing keyleash (role agent)')"
bash "$INST" --rolle agent --server "$SERVER" --lang "$LANG_SEL" --ja
grep -q '^KEYLEASH_DATA_URL=' "$LAB/keyleash.env" && sed -i "s#^KEYLEASH_DATA_URL=.*#KEYLEASH_DATA_URL=$DATA#" "$LAB/keyleash.env" \
  || echo "KEYLEASH_DATA_URL=$DATA" >> "$LAB/keyleash.env"
MODE=$(sed -n 's/^KEYLEASH_TPM=\([a-z]*\).*/\1/p' "$LAB/keyleash.env")
echo "  TPM: $MODE"

ENVS="Environment=KEYLEASH_LANG=$LANG_SEL"
DEPS=""
if [ "$MODE" = swtpm ]; then
  step "$(t 'Dienst für das Software-TPM' 'Service for the software TPM')"
  sudo tee /etc/systemd/system/keyleash-swtpm.service >/dev/null <<EOF
[Unit]
Description=keyleash Software-TPM (Demo, kein Hardware-TPM in dieser VM)
[Service]
Type=oneshot
RemainAfterExit=yes
User=$USR
Environment=KEYLEASH_TPM=swtpm
ExecStart=/usr/bin/bash $LAB/tools/swtpm-start.sh start
ExecStop=/usr/bin/bash $LAB/tools/swtpm-start.sh stop
[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  if ! sudo systemctl enable --now keyleash-swtpm.service; then
    echo "  ✘ keyleash-swtpm $(t 'startet nicht. Diagnose:' 'does not start. Diagnosis:')"
    sudo journalctl -u keyleash-swtpm -n 25 --no-pager | sed 's/^/    /'
    echo "    SELinux: $(getenforce 2>/dev/null || echo -)"
    sudo ausearch -m avc -ts recent 2>/dev/null | grep -E 'swtpm|abrmd|dbus' | tail -n 5 | sed 's/^/    /'
    exit 1
  fi
  ENVS="$ENVS
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=$LAB/state/swtpm/dbus.sock"
  DEPS="Requires=keyleash-swtpm.service
After=keyleash-swtpm.service"
  export DBUS_SESSION_BUS_ADDRESS=unix:path=$LAB/state/swtpm/dbus.sock
fi

step "$(t 'Maschinenidentität provisionieren' 'Enrolling the machine identity')"
if [ -f "$LAB/state/agent/agent.json" ]; then echo "  $(t 'bereits provisioniert' 'already enrolled')"
else
  # Gruppe tss gilt erst nach neuer Anmeldung; sg setzt sie für diesen Aufruf
  if [ "$MODE" = hw ] && ! id -nG | tr ' ' '\n' | grep -qx tss; then sg tss -c "python3 $LAB/agent/agent.py enroll"
  else python3 "$LAB/agent/agent.py" enroll; fi
fi

step "$(t 'Dienste einrichten' 'Setting up services')"
GRP=""; [ "$MODE" = hw ] && GRP="SupplementaryGroups=tss"
sudo tee /etc/systemd/system/keyleash-agent.service >/dev/null <<EOF
[Unit]
Description=keyleash Agent: erneuert Tickets der Maschinenidentität (TTL ${TTL}s)
After=network-online.target
Wants=network-online.target
$DEPS
[Service]
User=$USR
$GRP
WorkingDirectory=$LAB
$ENVS
ExecStart=/usr/bin/python3 $LAB/agent/agent.py loop --ttl $TTL
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
sudo tee /etc/systemd/system/keyleash-dashboard.service >/dev/null <<EOF
[Unit]
Description=keyleash Dashboard: geschützte Anwendung (Daten nur mit Maschinenidentität)
After=keyleash-agent.service
$DEPS
[Service]
User=$USR
$GRP
WorkingDirectory=$LAB
$ENVS
ExecStart=/usr/bin/python3 $LAB/labbox/dashboard.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now keyleash-agent.service keyleash-dashboard.service
sudo systemctl restart keyleash-agent.service keyleash-dashboard.service

if command -v firewall-cmd >/dev/null && sudo firewall-cmd --state >/dev/null 2>&1; then
  step "$(t 'Firewall: Port 8080 öffnen' 'Firewall: opening port 8080')"
  sudo firewall-cmd --permanent --add-port=8080/tcp >/dev/null && sudo firewall-cmd --reload >/dev/null
fi

step "$(t 'Prüfen' 'Checking')"
for i in $(seq 1 20); do
  h=$(curl -s http://127.0.0.1:8080/health || true)
  case "$h" in *'"ok": true'*) echo "  ✔ $(t 'Dashboard bekommt Daten (Anmeldung mit Maschinenidentität erfolgreich)' 'dashboard receives data (sign-in with machine identity succeeded)')"; break;; esac
  sleep 3
done
case "$h" in *'"ok": true'*) ;; *) echo "  ✘ $h"; echo "  journalctl -u keyleash-agent -u keyleash-dashboard -n 30";; esac
IP=$(hostname -I | awk '{print $1}')
echo; echo "$(t 'Fertig. Dashboard:' 'Done. Dashboard:') http://$IP:8080"
