#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Einmalige Einrichtung auf gmkbox (Linux Mint 22 / Ubuntu 24.04).
#   sudo ./setup.sh            Pakete, Gruppe tss, Prüfung von /dev/tpmrm0
#   sudo ./setup.sh --swtpm    zusätzlich Software-TPM zum gefahrlosen Ausprobieren
set -euo pipefail
source "$(dirname "$0")/lib/i18n.sh"
[ "$(id -u)" = 0 ] || { echo "$(t 'bitte mit sudo ausführen' 'please run with sudo')"; exit 1; }
USR=${SUDO_USER:-}
PKGS="tpm2-tools python3 python3-cryptography openssl curl"
[ "${1:-}" = --swtpm ] && PKGS="$PKGS swtpm swtpm-tools tpm2-abrmd libtss2-tcti-tabrmd0 libtss2-tcti-swtpm0t64 dbus"

echo "▶ $(t Pakete Packages): $PKGS"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y $PKGS
if systemctl list-unit-files tpm2-abrmd.service >/dev/null 2>&1; then
  # Der systemweite abrmd würde mit dem Kernel-Resource-Manager konkurrieren;
  # das Lab nutzt /dev/tpmrm0 direkt und abrmd nur pro Sitzung für swtpm.
  systemctl disable --now tpm2-abrmd.service 2>/dev/null || true
fi

echo "▶ $(t TPM-Gerät 'TPM device')"
if [ ! -c /dev/tpmrm0 ] && [ "${1:-}" = --swtpm ]; then
  echo "  $(t 'kein /dev/tpmrm0 – das Lab läuft im Software-TPM-Modus.' 'no /dev/tpmrm0 – the lab runs in software TPM mode.')"
  echo "  $(t 'In keyleash.env: KEYLEASH_TPM=swtpm, dann:' 'In keyleash.env: KEYLEASH_TPM=swtpm, then:') tools/swtpm-start.sh"
  echo "$(t 'Fertig. Weiter mit: tools/swtpm-start.sh und demos/00-pruefen.sh' 'Done. Next: tools/swtpm-start.sh and demos/00-pruefen.sh')"
  exit 0
fi
if [ ! -c /dev/tpmrm0 ]; then
  echo "  ✘ $(t '/dev/tpmrm0 fehlt. TPM/fTPM/PTT im BIOS aktivieren (meist unter Security/Trusted Computing).' '/dev/tpmrm0 missing. Enable TPM/fTPM/PTT in the BIOS (usually under Security/Trusted Computing).')"
  echo "    $(t 'Ohne Hardware-TPM: sudo ./setup.sh --swtpm und KEYLEASH_TPM=swtpm in keyleash.env' 'Without a hardware TPM: sudo ./setup.sh --swtpm and KEYLEASH_TPM=swtpm in keyleash.env')"
  exit 1
fi
ls -l /dev/tpmrm0
GRP=$(stat -c %G /dev/tpmrm0)
if [ "$GRP" != tss ]; then
  echo "  $(t "/dev/tpmrm0 gehört Gruppe '$GRP' – lege udev-Regel für tss an" "/dev/tpmrm0 belongs to group '$GRP' – creating a udev rule for tss")"
  getent group tss >/dev/null || groupadd --system tss
  echo 'KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"' > /etc/udev/rules.d/60-keyleash-tpm.rules
  udevadm control --reload && udevadm trigger --name-match=tpmrm0
fi
if [ -n "$USR" ]; then
  usermod -aG tss "$USR"
  echo "  $(t "$USR ist in Gruppe tss. Einmal ab- und wieder anmelden (oder: newgrp tss)." "$USR is in group tss. Log out and in once (or: newgrp tss).")"
fi

echo "▶ $(t 'Kurztest (nur lesend)' 'Quick test (read-only)')"
TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_getcap properties-fixed | grep -A2 -E 'MANUFACTURER|FAMILY_INDICATOR' | grep value | sed 's/^/  /'
TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_readclock | sed 's/^/  /'
echo "$(t 'Fertig. Weiter mit:' 'Done. Next:') demos/00-pruefen.sh"
