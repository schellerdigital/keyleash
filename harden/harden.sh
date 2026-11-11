#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Härtung Stufe 1 einrichten: Signaturdienst als eigener Benutzer, systemd-Isolation,
# AppArmor, Geheimnis in memfd_secret. Aufruf aus dem Lab-Verzeichnis:
#
#   sudo harden/harden.sh [--ptrace-lock] [--ptrace-lock-dauerhaft] [--tss-entziehen] [--ohne-apparmor]
#
#   --ptrace-lock            kernel.yama.ptrace_scope=3 sofort setzen.
#                            ACHTUNG: bis zum nächsten Neustart nicht rücknehmbar,
#                            kein Debugger (gdb, strace -p) mehr auf dem ganzen System.
#   --ptrace-lock-dauerhaft  zusätzlich in /etc/sysctl.d eintragen
#   --tss-entziehen          deinen Benutzer aus der Gruppe tss nehmen: danach hat nur
#                            noch der Dienst Zugriff auf /dev/tpmrm0 (Lab-Demos dann per sudo)
#   --ohne-apparmor          AppArmor-Profil nicht laden
#
# Rückbau: sudo harden/unharden.sh
set -euo pipefail
source "$(dirname "$0")/../lib/i18n.sh"
LAB=$(cd "$(dirname "$0")/.." && pwd)
PTRACE=0 PTRACE_PERSIST=0 DROP_TSS=0 APPARMOR=1
for a in "$@"; do case $a in
  --ptrace-lock) PTRACE=1 ;; --ptrace-lock-dauerhaft) PTRACE=1 PTRACE_PERSIST=1 ;;
  --tss-entziehen) DROP_TSS=1 ;; --ohne-apparmor) APPARMOR=0 ;;
  *) echo "$(t 'unbekannte Option' 'unknown option'): $a"; exit 2 ;; esac; done

[ "$(id -u)" = 0 ] || { echo "$(t 'bitte mit sudo ausführen' 'please run with sudo')"; exit 1; }
USR=${SUDO_USER:-}
[ -c /dev/tpmrm0 ] || { echo "$(t '/dev/tpmrm0 fehlt – Härtung nur mit echtem TPM' '/dev/tpmrm0 missing – hardening needs a real TPM device')"; exit 1; }
SERVER=$(grep -oP '^KEYLEASH_SERVER=\K\S+' "$LAB/keyleash.env")
curl -sf "$SERVER/authz" >/dev/null || { echo "$(t "Autorisierungsserver $SERVER nicht erreichbar – zuerst:" "Authorisation server $SERVER unreachable – first:") tools/server.sh start"; exit 1; }

echo "▶ $(t 'Benutzer und Gruppen' 'Users and groups')"
getent group keyleash-clients >/dev/null || groupadd --system keyleash-clients
id keyleash >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/keyleash \
  --shell /usr/sbin/nologin --comment "keyleash Signaturdienst" keyleash
usermod -aG tss,keyleash-clients keyleash
[ -n "$USR" ] && usermod -aG keyleash-clients "$USR" && echo "  $USR -> keyleash-clients ($(t 'neu anmelden!' 'log in again!'))"

echo "▶ $(t 'Code nach /opt/keyleash (root-eigen, für Benutzer nicht änderbar)' 'Code to /opt/keyleash (owned by root, not writable for users)')"
rm -rf /opt/keyleash; mkdir -p /opt/keyleash
( cd "$LAB" && tar --exclude=./state -cf - . ) | tar -C /opt/keyleash -xf -
sed -i 's/^KEYLEASH_TPM=.*/KEYLEASH_TPM=hw/' /opt/keyleash/keyleash.env
chown -R root:root /opt/keyleash; chmod -R u=rwX,go=rX /opt/keyleash
chmod 0755 /opt/keyleash/*.sh /opt/keyleash/*/*.sh /opt/keyleash/*/*.py
mkdir -p /etc/keyleash
[ -f /etc/keyleash/signer.env ] || cp "$LAB/harden/signer.env.example" /etc/keyleash/signer.env

echo "▶ $(t 'Eigene Identität für den Dienst provisionieren' 'Enrolling a separate identity for the service') ($(hostname)-signer)"
install -d -o keyleash -g keyleash -m 0700 /var/lib/keyleash
if [ ! -f /var/lib/keyleash/agent.json ]; then
  sudo -u keyleash env KEYLEASH_TPM=hw KEYLEASH_ENV=/opt/keyleash/keyleash.env \
    KEYLEASH_AGENT_STATE=/var/lib/keyleash KEYLEASH_HOST_ID="$(hostname)-signer" \
    python3 -I /opt/keyleash/agent/agent.py enroll
fi
chmod 0400 /var/lib/keyleash/key.auth
install -m 0644 /var/lib/keyleash/cert.pem /etc/keyleash/signer-cert.pem
install -m 0644 /var/lib/keyleash/ca.pem /etc/keyleash/ca.pem

if [ $APPARMOR = 1 ] && command -v apparmor_parser >/dev/null && aa-enabled -q 2>/dev/null; then
  echo "▶ $(t 'AppArmor-Profil laden' 'Loading the AppArmor profile')"
  install -m 0644 "$LAB/harden/apparmor-keyleash-signer" /etc/apparmor.d/keyleash-signer
  if ! apparmor_parser -r /etc/apparmor.d/keyleash-signer; then
    echo "  ! $(t 'Profil ließ sich nicht laden – Dienst läuft ohne AppArmor (siehe README)' 'Profile could not be loaded – service runs without AppArmor (see README)')"
    rm -f /etc/apparmor.d/keyleash-signer
  fi
else
  echo "▶ $(t 'AppArmor übersprungen' 'AppArmor skipped')"
fi

echo "▶ $(t systemd-Dienst 'systemd service')"
install -m 0644 "$LAB/harden/keyleash-signer.service" /etc/systemd/system/keyleash-signer.service
systemctl daemon-reload
systemctl enable --now keyleash-signer.service
sleep 3
systemctl --no-pager --lines=5 status keyleash-signer.service || true

if [ $PTRACE = 1 ]; then
  echo "▶ ptrace_scope=3 ($(t 'bis zum Neustart unumkehrbar' 'irreversible until the next reboot'))"
  sysctl -w kernel.yama.ptrace_scope=3
  [ $PTRACE_PERSIST = 1 ] && echo "kernel.yama.ptrace_scope = 3" > /etc/sysctl.d/60-keyleash-ptrace.conf
fi
if [ $DROP_TSS = 1 ] && [ -n "$USR" ]; then
  echo "▶ $(t "$USR aus Gruppe tss entfernen" "Removing $USR from group tss")"
  gpasswd -d "$USR" tss || true
fi

echo
echo "$(t 'Fertig. Prüfen mit:' 'Done. Check with:') systemd-analyze security keyleash-signer   $(t und and)   demos/90-haertung.sh"
echo "($(t "Nach Gruppenänderungen einmal ab- und wieder anmelden oder 'newgrp keyleash-clients'." "After group changes, log out and in once or run 'newgrp keyleash-clients'."))"
