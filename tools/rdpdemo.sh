#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# RDP-Demo: Der RDP-Server (xrdp) hat keinen Netzwerk-Port, nur einen lokalen Socket. Erreichbar ist er
# ausschließlich durch den SSH-Tunnel aus der Admin-Demo – also nur mit einem Kurzzeit-Zertifikat von
# keyleash. Bei einer Sperre reißt der Tunnel ab, und ein Sperr-Hook meldet die RDP-Sitzung ab (sonst
# bliebe sie getrennt bestehen und ließe sich wieder aufnehmen).
# RDP demo: the RDP server (xrdp) has no network port, only a local socket. It can be reached only through
# the SSH tunnel of the admin demo – i.e. only with a short-lived certificate from keyleash. On revocation
# the tunnel breaks and a revoke hook logs the RDP session off (otherwise it would remain disconnected and
# could be resumed).
#
#   bash tools/rdpdemo.sh setup|start|stop|status|remove
#   bash tools/rdpdemo.sh hook revoke|unrevoke HOST     (über state/hooks.d)
#
# Voraussetzung: bash tools/admindemo.sh setup. Getestet auf Ubuntu/Debian (Pakete xrdp, xorgxrdp,
# xvfb, socat, FreeRDP). setup legt den lokalen Benutzer kl-rdp mit Zufallspasswort an (state/rdpdemo/pw) und
# eine sudo-Regel, die nur „pkill -KILL -u kl-rdp“ erlaubt. Ein System-xrdp, das setup selbst installiert
# hat, wird abgeschaltet: diese Demo startet eine eigene Instanz ohne Netzwerk-Port.
set -uo pipefail
LAB=$(cd "$(dirname "$0")/.." && pwd); cd "$LAB"
source "$LAB/demos/common.sh" >/dev/null 2>&1 || true
cd "$LAB"
RD=$LAB/state/rdpdemo; mkdir -p "$RD"
RUSER=kl-rdp
SOCK=$RD/xrdp.sock
SUDOERS=/etc/sudoers.d/keyleash-rdpdemo
export PATH="$PATH:/usr/sbin:/sbin"
ok()   { echo "  ${G:-}✔${N:-} $*"; }
warn() { echo "  ${Y:-}!${N:-} $*"; }
die()  { echo "  ${R:-}✘ $*${N:-}" >&2; exit 1; }
PKILL=$(command -v pkill || echo /usr/bin/pkill)
# Nur die eigene Demo-Instanz zählt (erkennbar an der Konfiguration in state/rdpdemo).
# Ein System-xrdp, über das jemand per RDP angemeldet ist, wird nie angefasst.
demo_pids() { pgrep -f -- "-c $RD/(xrdp|sesman)\.ini" 2>/dev/null; }
running() { pgrep -f -- "-c $RD/xrdp\.ini" >/dev/null && pgrep -f -- "-c $RD/sesman\.ini" >/dev/null; }
system_xrdp() { pgrep -x xrdp 2>/dev/null | while read -r p; do grep -qF "$RD/" "/proc/$p/cmdline" 2>/dev/null || echo "$p"; done | grep -q .; }
sessions() { local n; n=$(pgrep -u "$RUSER" -c 2>/dev/null); echo "${n:-0}"; }

setup() {
  [ -f state/admindemo/sshd_config ] || die "$(t 'zuerst' 'first'): bash tools/admindemo.sh setup"
  echo "▶ $(t 'RDP-Pakete' 'RDP packages')"
  local fresh=0
  if ! command -v xrdp >/dev/null || ! command -v xvfb-run >/dev/null || ! command -v socat >/dev/null || ! { command -v xfreerdp3 || command -v xfreerdp; } >/dev/null; then
    command -v xrdp >/dev/null || fresh=1
    if command -v apt-get >/dev/null; then
      local fr=freerdp3-x11; apt-cache show freerdp3-x11 >/dev/null 2>&1 || fr=freerdp2-x11
      sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq xrdp xorgxrdp xvfb socat "$fr" >/dev/null || die apt
    else
      sudo dnf install -y -q xrdp xorgxrdp xorg-x11-server-Xvfb socat freerdp >/dev/null || die "dnf (xrdp: EPEL?)"
    fi
  fi
  if [ $fresh = 1 ] && command -v systemctl >/dev/null && systemctl list-unit-files xrdp.service >/dev/null 2>&1; then
    sudo systemctl disable --now xrdp xrdp-sesman >/dev/null 2>&1 || true
    ok "$(t 'System-xrdp abgeschaltet (lauschte sonst im Netz auf 3389)' 'system xrdp disabled (it would listen on 3389 on the network)')"
  fi
  if command -v systemctl >/dev/null && systemctl is-active -q xrdp 2>/dev/null; then
    die "$(t 'Ein System-xrdp läuft bereits (Port 3389). Erst stoppen: sudo systemctl stop xrdp xrdp-sesman' 'A system xrdp is already running (port 3389). Stop it first: sudo systemctl stop xrdp xrdp-sesman')"
  fi
  ok "$(xrdp --version 2>/dev/null | head -1)"

  echo "▶ $(t 'RDP-Benutzer und Sperr-Regel' 'RDP user and revoke rule')"
  id "$RUSER" >/dev/null 2>&1 || sudo useradd -m -s /bin/bash "$RUSER" || die useradd
  if [ ! -s "$RD/pw" ]; then
    (umask 077; openssl rand -hex 16 > "$RD/pw")
    printf '%s:%s\n' "$RUSER" "$(cat "$RD/pw")" | sudo chpasswd || die chpasswd
  fi
  printf '#!/bin/sh\n# keyleash RDP-Demo: Sitzung ohne Desktop, läuft bis zur Abmeldung\nexec sleep infinity\n' \
    | sudo tee "/home/$RUSER/startwm.sh" >/dev/null && sudo chmod 755 "/home/$RUSER/startwm.sh"
  echo "$(id -un) ALL=(root) NOPASSWD: $PKILL -KILL -u $RUSER" > "$RD/sudoers"
  sudo visudo -cqf "$RD/sudoers" || die visudo
  sudo install -m 440 -o root "$RD/sudoers" "$SUDOERS" && rm -f "$RD/sudoers"
  ok "$(t "Benutzer $RUSER, sudo nur für: pkill -KILL -u $RUSER" "user $RUSER, sudo only for: pkill -KILL -u $RUSER")"

  echo "▶ $(t 'xrdp ohne Netzwerk-Port' 'xrdp without a network port')"
  cp /etc/xrdp/xrdp.ini "$RD/xrdp.ini"; cp /etc/xrdp/sesman.ini "$RD/sesman.ini"
  sed -i "s#^port=3389#port=unix://.$SOCK#" "$RD/xrdp.ini"
  grep -q "^port=unix://.$SOCK" "$RD/xrdp.ini" || die "xrdp.ini: port"
  # Gateway ohne Weiterleitungen; ältere Admin-Demo-Konfiguration nachrüsten
  if ! grep -q DisableForwarding state/admindemo/sshd_config; then
    bash tools/admindemo.sh setup >/dev/null || die "admindemo setup"
    [ -f state/admindemo/sshd.pid ] && kill "$(cat state/admindemo/sshd.pid)" 2>/dev/null; sleep 1
  fi
  bash tools/admindemo.sh start >/dev/null
  register_hook 70-rdpdemo bash "$LAB/tools/rdpdemo.sh" hook
  ok "$(t 'Sperr-Hook: meldet RDP-Sitzungen von' 'revoke hook: logs off RDP sessions of') $RUSER $(t ab '')"
  start
  echo; echo "  $(t 'Vorführung' 'Demo'): demos/87-rdp.sh"
}

start() {
  [ -f "$RD/xrdp.ini" ] || die "$(t 'zuerst' 'first'): bash tools/rdpdemo.sh setup"
  if ! running && system_xrdp; then
    die "$(t 'Auf diesem Rechner läuft ein System-xrdp (z. B. dein eigener RDP-Zugang). Beide teilen sich die PID-Datei, deshalb startet die Demo hier nicht. Demo 87 auf labbox-1 oder einem Rechner ohne xrdp-Dienst ausführen.' 'A system xrdp runs on this machine (e.g. your own RDP access). Both share the PID file, so the demo does not start here. Run demo 87 on labbox-1 or a machine without an xrdp service.')"
  fi
  if ! running; then
    sudo xrdp-sesman -c "$RD/sesman.ini" || die xrdp-sesman
    sudo xrdp -c "$RD/xrdp.ini" || die xrdp
    for _ in $(seq 20); do [ -S "$SOCK" ] && break; sleep 0.2; done
  fi
  [ -S "$SOCK" ] || die "$(t 'kein Socket' 'no socket'): $SOCK"
  sudo chgrp "$(id -gn)" "$SOCK" && sudo chmod 660 "$SOCK"
  ok "xrdp: $SOCK ($(t 'kein Netzwerk-Port' 'no network port'))"
}

stop() {
  sudo -n "$PKILL" -KILL -u "$RUSER" 2>/dev/null || true
  # kein „xrdp -k“: das liest die gemeinsame PID-Datei und träfe ein System-xrdp
  local p; p=$(demo_pids | tr '\n' ' ')
  [ -n "${p// /}" ] && sudo kill $p 2>/dev/null
  sleep 1; p=$(demo_pids | tr '\n' ' '); [ -n "${p// /}" ] && sudo kill -KILL $p 2>/dev/null
  ok "$(t gestoppt stopped)"
}

hook() {   # hook revoke|unrevoke HOST
  local action=${1:-} host=${2:-}
  [ -f "$ST/agent.json" ] && [ "$host" = "$(jq_host)" ] || { echo "$(t 'nicht betroffen' 'not affected'): $host"; return 0; }
  case "$action" in
    revoke)
      local n; n=$(pgrep -u "$RUSER" -x Xorg -c 2>/dev/null); n=${n:-0}
      sudo -n "$PKILL" -KILL -u "$RUSER" 2>/dev/null; local rc=$?
      [ $rc -le 1 ] || { echo "$(t 'Abmelden fehlgeschlagen (sudo-Regel?)' 'logoff failed (sudo rule?)')"; exit 1; }
      echo "$(t "$n RDP-Sitzung(en) von $RUSER abgemeldet" "$n RDP session(s) of $RUSER logged off")" ;;
    unrevoke) echo "$(t 'RDP: nichts zu tun' 'RDP: nothing to do')" ;;
    *) echo "hook revoke|unrevoke HOST"; exit 2 ;;
  esac
}

remove() {
  stop >/dev/null
  unregister_hook 70-rdpdemo
  sudo rm -f "$SUDOERS"
  id "$RUSER" >/dev/null 2>&1 && sudo userdel -r "$RUSER" 2>/dev/null
  rm -rf "$RD"
  ok "$(t 'RDP-Demo entfernt (Pakete bleiben installiert)' 'RDP demo removed (packages stay installed)')"
}

case "${1:-status}" in
  setup) setup ;; start) start ;; stop) stop ;; remove) remove ;;
  hook) shift; hook "$@" ;;
  status) running && echo "xrdp: $(t läuft running) ($SOCK)" || echo "xrdp: $(t aus stopped)"
          echo "$(t 'Prozesse von' 'processes of') $RUSER: $(sessions)" ;;
  *) sed -n 3,20p "$0" ;;
esac
