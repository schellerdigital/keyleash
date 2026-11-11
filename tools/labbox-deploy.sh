#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Demo „geschützte Anwendung“: richtet labbox-1 von gmkbox aus ein (läuft auf gmkbox).
# Demo "protected application": sets up labbox-1 from gmkbox (runs on gmkbox).
#
#   bash tools/labbox-deploy.sh BENUTZER@VM-ADRESSE       einrichten / set up (wird gemerkt / remembered)
#   bash tools/labbox-deploy.sh status                     Dienste und Dashboard prüfen
#   bash tools/labbox-deploy.sh sperren|entsperren         labbox-1 sperren / entsperren (revoke)
#
# gmkbox:   keyleash-Server (Port 8740) + Daten-Schnittstelle (Port 8741, nur mit Maschinenidentität)
# labbox-1: keyleash-Agent mit Schlüssel im TPM + Dashboard (Port 8080) als geschützte Anwendung
set -uo pipefail
LAB=$(cd "$(dirname "$0")/.." && pwd); cd "$LAB"
source "$LAB/lib/i18n.sh"
TARGET=${KEYLEASH_LABBOX:-$(cat state/labbox.target 2>/dev/null)}   # Ziel der VM, beim ersten Einrichten gemerkt
VMHOST=$(cat state/labbox.host 2>/dev/null || echo labbox-1)   # Hostname der VM, beim Einrichten gemerkt / VM hostname, recorded at setup
case "${1:-}" in
  sperren|revoke)
    curl -sf -X POST -H 'Content-Type: application/json' -d "{\"host\":\"$VMHOST\"}" http://127.0.0.1:8740/admin/revoke && echo
    echo "$(t 'Gesperrt. Das letzte Ticket läuft aus (höchstens 30 s), dann signiert das TPM auf labbox-1 nicht mehr und das Dashboard wird rot.' 'Revoked. The last ticket runs out (30 s at most), then the TPM on labbox-1 stops signing and the dashboard turns red.')"
    exit 0 ;;
  entsperren|unrevoke)
    curl -sf -X POST -H 'Content-Type: application/json' -d "{\"host\":\"$VMHOST\"}" http://127.0.0.1:8740/admin/unrevoke && echo
    echo "$(t 'Entsperrt. Mit dem nächsten Ticket (unter 30 s) bekommt das Dashboard wieder Daten.' 'Unrevoked. With the next ticket (under 30 s) the dashboard gets data again.')"
    exit 0 ;;
  status)
    ssh "${2:-$TARGET}" 'systemctl --no-pager --lines=3 status keyleash-agent keyleash-dashboard 2>/dev/null | grep -E "●|Active|ticket|Ticket"; curl -s http://127.0.0.1:8080/health; echo'
    exit 0 ;;
  "") ;;
  *) TARGET=$1 ;;
esac
[ -n "$TARGET" ] || { echo "  $(t 'Ziel angeben:' 'Give the target:') bash tools/labbox-deploy.sh $(t BENUTZER@VM-ADRESSE USER@VM-ADDRESS)"; exit 1; }
mkdir -p state; echo "$TARGET" > state/labbox.target
VMIP=${TARGET#*@}

echo "▶ $(t 'Netz' 'Network')"
GMKIP=$(ip route get "$VMIP" 2>/dev/null | grep -oP 'src \K\S+')
[ -n "$GMKIP" ] || { echo "  ✘ $(t "keine Route zu $VMIP" "no route to $VMIP")"; exit 1; }
echo "  gmkbox → $VMIP $(t über via) $GMKIP"

echo "▶ $(t 'keyleash-Server auf gmkbox für die VM erreichbar machen' 'Making the keyleash server on gmkbox reachable for the VM')"
# Der Lab-Server spricht HTTP ohne TLS: nur im internen VM-Netz verwenden
sed -i 's#^KEYLEASH_LISTEN=[^ ]*#KEYLEASH_LISTEN=0.0.0.0:8740#' keyleash.env
grep -q "^KEYLEASH_LISTEN=0.0.0.0" keyleash.env || echo "KEYLEASH_LISTEN=0.0.0.0:8740" >> keyleash.env
tools/server.sh stop >/dev/null 2>&1; sleep 1; tools/server.sh start
if [ -f state/data_api.pid ] && kill -0 "$(cat state/data_api.pid)" 2>/dev/null; then kill "$(cat state/data_api.pid)"; sleep 1; fi
nohup python3 server/data_api.py >> state/data_api.log 2>&1 & echo $! > state/data_api.pid
sleep 1; curl -sf http://127.0.0.1:8741/challenge >/dev/null && echo "  ✔ $(t 'Daten-Schnittstelle läuft' 'data API running') (http://$GMKIP:8741, Log: state/data_api.log)"
if command -v ufw >/dev/null && sudo -n ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "  ! $(t 'ufw ist aktiv – bitte freigeben:' 'ufw is active – please allow:') sudo ufw allow from ${VMIP%.*}.0/24 to any port 8740:8741 proto tcp"
fi

echo "▶ $(t 'Installationsdatei bauen' 'Building the installer')"
bash tools/build-installer.sh >/dev/null && echo "  ✔ dist/keyleash-install.sh"

echo "▶ $(t "SSH zu $TARGET" "SSH to $TARGET")"
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new "$TARGET" true 2>/dev/null; then
  [ -f ~/.ssh/id_ed25519.pub ] || ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 -q
  echo "  $(t 'Einmalig das Passwort von labbox-1 eingeben (danach Anmeldung per Schlüssel):' 'Enter the labbox-1 password once (key-based login afterwards):')"
  ssh-copy-id -o StrictHostKeyChecking=accept-new "$TARGET" >/dev/null || exit 1
fi
ssh "$TARGET" hostname > state/labbox.host 2>/dev/null && echo "  ✔ $(t Hostname hostname): $(cat state/labbox.host)"
scp -q dist/keyleash-install.sh labbox/setup-labbox.sh "$TARGET:" && echo "  ✔ $(t kopiert copied)"

echo "▶ $(t 'labbox-1 einrichten (sudo-Passwort von labbox-1, falls gefragt)' 'Setting up labbox-1 (labbox-1 sudo password if asked)')"
ssh -t "$TARGET" "bash setup-labbox.sh --server http://$GMKIP:8740 --data http://$GMKIP:8741 --lang $KEYLEASH_LANG --ttl 30"

echo
echo "$(t 'Dashboard im Browser auf gmkbox:' 'Dashboard in the browser on gmkbox:') http://$VMIP:8080"
echo "$(t 'Vorführung:' 'Demo:')  bash tools/labbox-deploy.sh sperren   →  $(t 'in unter einer Minute rot' 'red in under a minute')"
echo "            bash tools/labbox-deploy.sh entsperren"
