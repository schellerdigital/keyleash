#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# RDP nur über den keyleash-Tunnel: Der RDP-Server hat keinen Netzwerk-Port. Der Admin erreicht ihn nur
# durch einen SSH-Tunnel mit Kurzzeit-Zertifikat vom Arbeitsplatz. Die Sperre trennt den Tunnel und
# meldet die RDP-Sitzung ab.
# RDP only through the keyleash tunnel: the RDP server has no network port. The admin reaches it only
# through an SSH tunnel with a short-lived certificate from the workstation. Revocation cuts the tunnel
# and logs the RDP session off.
# Voraussetzung / prerequisite: bash tools/admindemo.sh setup && bash tools/rdpdemo.sh setup
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
RD=$LAB/state/rdpdemo; SOCK=$RD/xrdp.sock; RUSER=kl-rdp
LPORT=${KEYLEASH_RDP_LOCAL_PORT:-13389}
title "$(t 'RDP nur über den keyleash-Tunnel (xrdp)' 'RDP only through the keyleash tunnel (xrdp)')"
[ -f "$RD/xrdp.ini" ] || { note "$(t 'Zuerst einrichten:' 'Set it up first:') bash tools/admindemo.sh setup && bash tools/rdpdemo.sh setup"; exit 1; }
bash tools/admindemo.sh start | sed 's/^/  /'
bash tools/rdpdemo.sh start | sed 's/^/  /'
FR=$(command -v xfreerdp3 || command -v xfreerdp)
now() { python3 -c 'import time;print(time.time())'; }
since() { python3 -c "import time;print(f'{time.time()-$1:.1f}')"; }
xorg() { local n; n=$(pgrep -u "$RUSER" -x Xorg -c 2>/dev/null); echo "${n:-0}"; }
TUN=""; CLI=""
gone() { [ -n "${1:-}" ] && kill -- -"$1" 2>/dev/null; true; }   # ganze Prozessgruppe beenden
cleanup() { gone "$CLI"; gone "$TUN"; }
trap cleanup EXIT
gw() { local n; n=$(pgrep -P "$(cat state/admindemo/sshd.pid)" -c 2>/dev/null); echo "${n:-0}"; }   # Gateway-Sitzungen
open_tunnel() {   # lokaler Port 127.0.0.1:LPORT; jede Verbindung = eine SSH-Sitzung mit Kurzzeit-Zertifikat
  if python3 -c "import socket;s=socket.socket();s.settimeout(0.3);s.connect(('127.0.0.1',$LPORT))" 2>/dev/null; then
    echo "  ${R}✘ $(t "Port $LPORT ist schon belegt (KEYLEASH_RDP_LOCAL_PORT=…)" "port $LPORT is already in use (KEYLEASH_RDP_LOCAL_PORT=…)")${N}"; exit 1; fi
  setsid bash tools/admindemo.sh tunnel "$LPORT" "$SOCK" > "$W/tunnel.log" 2>&1 &
  TUN=$!
  for _ in $(seq 40); do
    kill -0 $TUN 2>/dev/null || return 1
    python3 -c "import socket;s=socket.socket();s.settimeout(0.3);s.connect(('127.0.0.1',$LPORT))" 2>/dev/null && return 0
    sleep 0.2
  done; return 1
}
rdp() {   # RDP-Client ohne Bildschirm (Xvfb); FreeRDP 3 liest Passwort aus Datei (nicht in der Prozessliste)
  if "$FR" /help 2>&1 | grep -q args-from; then
    (umask 077; printf '/v:127.0.0.1:%s\n/cert:ignore\n/log-level:ERROR\n/u:%s\n/p:%s\n' "$LPORT" "$RUSER" "$(cat "$RD/pw")" > "$RD/client.args")
    setsid env -u https_proxy -u HTTPS_PROXY -u http_proxy -u HTTP_PROXY -u all_proxy -u ALL_PROXY xvfb-run -a "$FR" /args-from:file:"$RD/client.args" > "$W/rdp.log" 2>&1 &
  else
    setsid env -u https_proxy -u HTTPS_PROXY -u http_proxy -u HTTP_PROXY -u all_proxy -u ALL_PROXY xvfb-run -a "$FR" /v:127.0.0.1:"$LPORT" /cert:ignore /log-level:ERROR /u:"$RUSER" /p:"$(cat "$RD/pw")" > "$W/rdp.log" 2>&1 &
  fi
  CLI=$!
}
wait_xorg() { for _ in $(seq "${2:-60}"); do [ "$(xorg)" "$1" 0 ] && return 0; sleep 0.25; done; return 1; }

step "$(t 'Der RDP-Server hat keinen Netzwerk-Port' 'The RDP server has no network port')"
echo "  xrdp: $(ss -lxn 2>/dev/null | grep -o "$SOCK" | head -1 || echo "$SOCK")"
if command -v ss >/dev/null && ss -ltnp 2>/dev/null | grep -q '"xrdp"'; then echo "  ${R}✘ $(t 'xrdp lauscht im Netz' 'xrdp listens on the network')${N}"
else echo "  ${G}✔${N} $(t 'kein TCP-Port von xrdp – auch nicht 3389' 'no TCP port from xrdp – not even 3389')"; fi
expect_fail python3 -c "import socket;socket.create_connection(('127.0.0.1',3389),2)"
note "$(t 'Ein Passwort allein nützt nichts: ohne Tunnel gibt es nichts, wo man es eingeben könnte. Unter Windows entspricht das einer Firewall-Regel, die 3389 nur vom Gateway zulässt.' 'A password alone is useless: without the tunnel there is nowhere to enter it. On Windows this corresponds to a firewall rule that allows 3389 only from the gateway.')"

step "$(t 'Admin öffnet den Tunnel mit dem Kurzzeit-Zertifikat und meldet sich per RDP an' 'Admin opens the tunnel with the short-lived certificate and signs in via RDP')"
for _ in $(seq 15); do open_tunnel && break; gone "$TUN"; TUN=""; sleep 1; done
[ -n "$TUN" ] && echo "  ${G}✔${N} $(t 'Tunnel' 'Tunnel') 127.0.0.1:$LPORT → xrdp ($(t 'Zertifikat' 'certificate') $(ssh-keygen -L -f state/admindemo/cert/current/id_ed25519-cert.pub | grep -o 'Key ID: .*'))" \
  || { echo "  ${R}✘ $(t 'Tunnel' 'tunnel'): $(cat "$W/tunnel.log")${N}"; exit 1; }
rdp
if wait_xorg -gt 80; then echo "  ${G}✔${N} $(t "RDP-Sitzung von $RUSER läuft (Xorg-Sitzung auf dem Server)" "RDP session of $RUSER running (Xorg session on the server)")"
else echo "  ${R}✘ $(t 'keine RDP-Sitzung' 'no RDP session')${N}"; tail -5 "$W/rdp.log"; exit 1; fi

step "$(t 'Verdacht: Administrator sperrt den Arbeitsplatz' 'Suspicion: the administrator revokes the workstation')"
T0=$(now)
R=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"host\":\"$(jq_host)\"}" "$KEYLEASH_SERVER/admin/revoke")
echo "  $(t gesperrt revoked): $(jq_host)"
echo "  $(t 'Sperr-Hook' 'Revoke hook'): $(python3 -c "import json,sys;h=json.loads(sys.argv[1]).get('hook') or {};print(h.get('output','–').replace(chr(10),' | '), f\"({h.get('ms','?')} ms)\")" "$R")"
for _ in $(seq 50); do [ "$(gw)" = 0 ] && break; sleep 0.1; done
[ "$(gw)" = 0 ] && echo "  ${G}✔${N} $(t "Gateway-Sitzung getrennt nach $(since "$T0") s" "gateway session cut after $(since "$T0") s")" || echo "  ${R}✘ $(t 'Gateway-Sitzung steht noch' 'gateway session still up')${N}"
if wait_xorg -eq 50; then echo "  ${G}✔${N} $(t "RDP-Sitzung abgemeldet nach $(since "$T0") s – nicht nur getrennt" "RDP session logged off after $(since "$T0") s – not just disconnected")"
else echo "  ${R}✘ $(t 'RDP-Sitzung läuft noch' 'RDP session still running')${N}"; fi
for _ in $(seq 30); do kill -0 $CLI 2>/dev/null || break; sleep 0.2; done
gone "$CLI"; gone "$TUN"; CLI=""; TUN=""

step "$(t 'Neuer Tunnel?' 'New tunnel?')"
expect_fail bash tools/admindemo.sh tunnel "$LPORT" "$SOCK"
note "$(t 'Das Zertifikat ist widerrufen, ein neues stellt keyleash nicht aus. Ohne Tunnel kein RDP.' 'The certificate is revoked and keyleash issues no new one. No tunnel, no RDP.')"

step "$(t 'Entsperren: neues Zertifikat (≤ 10 s), Tunnel und RDP gehen wieder' 'Reinstate: new certificate (≤ 10 s), tunnel and RDP work again')"
OLD=$(readlink state/admindemo/cert/current)
admin unrevoke && echo "  $(t entsperrt reinstated)"
for _ in $(seq 40); do [ "$(readlink state/admindemo/cert/current)" != "$OLD" ] && break; sleep 1; done
for _ in $(seq 10); do open_tunnel && break; gone "$TUN"; TUN=""; sleep 1; done
rdp
if wait_xorg -gt 80; then echo "  ${G}✔${N} $(t 'RDP-Sitzung wieder da' 'RDP session back')"; else echo "  ${R}✘ $(t 'keine RDP-Sitzung' 'no RDP session')${N}"; fi
gone "$CLI"; gone "$TUN"; CLI=""; TUN=""
sudo -n "$(command -v pkill)" -KILL -u "$RUSER" 2>/dev/null || true
note "$(t 'Unter Windows übernimmt dieselbe Rolle ein Hook mit „logoff“ bzw. „Invoke-RDUserLogoff“; den Tunnel stellt ein SSH- oder RD-Gateway.' 'On Windows the same role is played by a hook running “logoff” or “Invoke-RDUserLogoff”; an SSH or RD gateway provides the tunnel.')"
siem_tail 4
