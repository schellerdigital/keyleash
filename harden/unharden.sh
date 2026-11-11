#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Härtung Stufe 1 vollständig zurückbauen.  Aufruf: sudo harden/unharden.sh
set -uo pipefail
source "$(dirname "$0")/../lib/i18n.sh"
[ "$(id -u)" = 0 ] || { echo "$(t 'bitte mit sudo ausführen' 'please run with sudo')"; exit 1; }
LAB=$(cd "$(dirname "$0")/.." && pwd)
systemctl disable --now keyleash-signer.service 2>/dev/null
rm -f /etc/systemd/system/keyleash-signer.service; systemctl daemon-reload
if [ -f /etc/apparmor.d/keyleash-signer ]; then
  apparmor_parser -R /etc/apparmor.d/keyleash-signer 2>/dev/null; rm -f /etc/apparmor.d/keyleash-signer; fi
SERVER=$(grep -oP '^KEYLEASH_SERVER=\K\S+' "$LAB/keyleash.env")
curl -sf -X POST -H 'Content-Type: application/json' -d "{\"host\":\"$(hostname)-signer\"}" "$SERVER/admin/forget" >/dev/null \
  && echo "$(t Identität Identity) $(hostname)-signer $(t 'beim Server entfernt' 'removed from the server')"
rm -rf /opt/keyleash /var/lib/keyleash /etc/keyleash /run/keyleash
userdel keyleash 2>/dev/null; groupdel keyleash 2>/dev/null; groupdel keyleash-clients 2>/dev/null
if [ -f /etc/sysctl.d/60-keyleash-ptrace.conf ]; then
  rm -f /etc/sysctl.d/60-keyleash-ptrace.conf
  echo "$(t 'ptrace_scope-Eintrag entfernt (wirkt nach dem nächsten Neustart)' 'ptrace_scope entry removed (takes effect after the next reboot)')"; fi
[ -n "${SUDO_USER:-}" ] && ! id -nG "$SUDO_USER" | grep -qw tss && \
  echo "$(t "Hinweis: $SUDO_USER ist nicht in der Gruppe tss. Wieder hinzufügen:" "Note: $SUDO_USER is not in group tss. Add again with:") sudo usermod -aG tss $SUDO_USER"
echo "$(t 'Härtung zurückgebaut. (Der Maschinenschlüssel lag nur als Blob in /var/lib/keyleash – im TPM bleibt nichts zurück.)' 'Hardening removed. (The machine key was only a blob in /var/lib/keyleash – nothing remains in the TPM.)')"
