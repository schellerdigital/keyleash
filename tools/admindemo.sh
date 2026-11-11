#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Demo „Privilegierte Konten an Admin-Arbeitsplätze binden“: Ein SSH-Server lässt Admins nur mit
# einem SSH-Zertifikat für wenige Minuten herein, das der keyleash-Server ausstellt – nur für einen
# Arbeitsplatz mit gültigem TPM-Ticket. Bei einer Sperre widerruft ein Hook das Zertifikat sofort
# (KRL) und beendet laufende Admin-Sitzungen.
# Demo "bind privileged accounts to admin workstations": an SSH server admits admins only with an
# SSH certificate valid for a few minutes, issued by the keyleash server only to a workstation with a
# valid TPM ticket. On revocation a hook revokes the certificate at once (KRL) and ends admin sessions.
#
#   bash tools/admindemo.sh setup|start|stop|status|remove
#   bash tools/admindemo.sh ssh [BEFEHL]     als Admin vom Arbeitsplatz anmelden
#   bash tools/admindemo.sh tunnel PORT SOCKET   lokaler Port → SSH-Sitzung → Socket auf dem Ziel (RDP-Demo)
#   bash tools/admindemo.sh hook revoke|unrevoke HOST   (ruft der keyleash-Server über state/hooks.d auf)
#
# Der SSH-Server läuft ohne root auf 127.0.0.1:2222 (KEYLEASH_ADMIN_SSH_PORT) und nimmt nur
# Zertifikate mit Prinzipal keyleash-admin an; keine Passwörter, keine authorized_keys.
set -uo pipefail
LAB=$(cd "$(dirname "$0")/.." && pwd); cd "$LAB"
source "$LAB/demos/common.sh" >/dev/null 2>&1 || true
cd "$LAB"
AD=$LAB/state/admindemo; mkdir -p "$AD"
PORT=${KEYLEASH_ADMIN_SSH_PORT:-2222}
LIFE=${KEYLEASH_ADMIN_CERT_LIFETIME:-120}
CERT=$AD/cert
export PATH="$PATH:/usr/sbin:/sbin"
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
ok()   { echo "  ${G:-}✔${N:-} $*"; }
warn() { echo "  ${Y:-}!${N:-} $*"; }
die()  { echo "  ${R:-}✘ $*${N:-}" >&2; exit 1; }
alive() { [ -f "$AD/$1.pid" ] && kill -0 "$(cat "$AD/$1.pid")" 2>/dev/null; }

SERIALS=$LAB/state/server/ssh-serials.tsv
krl() {   # krl [HOST…]: Widerrufsliste neu schreiben – gesperrte Hosts plus Altzertifikate in old.serials
  local now; now=$(date +%s)
  touch "$AD/old.serials"
  awk -v now="$now" '$2 > now' "$AD/old.serials" > "$AD/old.tmp"; mv "$AD/old.tmp" "$AD/old.serials"
  { printf '%s\n' "$@" | sed '/^$/d; s/^/id: /'; awk '{print "serial: " $1}' "$AD/old.serials"; } > "$AD/krl.spec"
  ssh-keygen -q -k -f "$AD/krl.new" -s "$AD/ssh_ca.pub" "$AD/krl.spec" 2>/dev/null && mv "$AD/krl.new" "$AD/krl"
}
keep_old() {   # keep_old HOST: noch gültige Zertifikate von HOST (vor der Entsperrung) weiter widerrufen
  [ -f "$SERIALS" ] || return 0
  local since; since=$(cat "$AD/revoked.$1" 2>/dev/null || date +%s.%N)
  awk -F'\t' -v h="$1" -v now="$(date +%s)" -v t="$since" '$1 == h && $3 > now && $4 <= t {print $2 " " $3}' "$SERIALS" >> "$AD/old.serials"
  rm -f "$AD/revoked.$1"
}

setup() {
  echo "▶ $(t 'SSH-Werkzeuge' 'SSH tools')"
  if [ ! -x "$SSHD" ] || ! command -v ssh >/dev/null || ! command -v ssh-keygen >/dev/null; then
    if command -v apt-get >/dev/null; then sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server openssh-client >/dev/null || die apt
    else sudo dnf install -y -q openssh-server openssh-clients >/dev/null || die dnf; fi
    SSHD=$(command -v sshd || echo /usr/sbin/sshd)
  fi
  ok "$("$SSHD" -V 2>&1 | head -1 || ssh -V 2>&1)"
  ensure_server; ensure_enrolled
  curl -sf "$KEYLEASH_SERVER/authz" | python3 -c 'import json,sys;print(json.load(sys.stdin)["ssh_ca"],end="")' > "$AD/ssh_ca.pub"
  [ -s "$AD/ssh_ca.pub" ] || die "$(t 'Server liefert keine SSH-CA (ssh-keygen auf dem Server?)' 'server provides no SSH CA (ssh-keygen on the server?)')"
  [ -f "$AD/hostkey" ] || ssh-keygen -q -t ed25519 -N "" -C keyleash-admindemo -f "$AD/hostkey"
  echo keyleash-admin > "$AD/principals"
  krl
  cat > "$AD/sshd_config" <<EOF
# keyleash Admin-Demo: nur Kurzzeit-Zertifikate der keyleash-SSH-CA
Port $PORT
ListenAddress 127.0.0.1
HostKey $AD/hostkey
PidFile $AD/sshd.pid
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile none
TrustedUserCAKeys $AD/ssh_ca.pub
AuthorizedPrincipalsFile $AD/principals
RevokedKeys $AD/krl
# keine Weiterleitungen; die RDP-Demo verbindet über eine normale Sitzung (socat)
DisableForwarding yes
LogLevel VERBOSE
EOF
  ok "$(t 'SSH-CA des keyleash-Servers, Prinzipal keyleash-admin, Widerrufsliste' 'keyleash server SSH CA, principal keyleash-admin, revocation list')"
  register_hook 60-admindemo bash "$LAB/tools/admindemo.sh" hook
  ok "$(t 'Sperr-Hook: widerruft das Zertifikat und beendet Admin-Sitzungen' 'revoke hook: revokes the certificate and ends admin sessions')"
  start
  echo; echo "  $(t 'Vorführung' 'Demo'): demos/86-admin-arbeitsplatz.sh"
}

start() {
  ensure_server; ensure_enrolled
  [ -f "$AD/sshd_config" ] || die "$(t 'zuerst' 'first'): bash tools/admindemo.sh setup"
  ensure_agent_loop
  if ! alive certs; then
    nohup python3 agent/agent.py shortcert admin --ssh --dir "$CERT" --lifetime "$LIFE" --loop >> "$AD/certs.log" 2>&1 &
    echo $! > "$AD/certs.pid"
  fi
  for _ in $(seq 30); do [ -f "$CERT/current/id_ed25519-cert.pub" ] && break; sleep 1; done
  [ -f "$CERT/current/id_ed25519-cert.pub" ] || warn "$(t 'noch kein SSH-Zertifikat – siehe' 'no SSH certificate yet – see') state/admindemo/certs.log"
  if ! alive sshd; then "$SSHD" -f "$AD/sshd_config" -E "$AD/sshd.log" || die "sshd"; sleep 1; fi
  ok "$(t 'SSH-Server' 'SSH server') 127.0.0.1:$PORT, $(t 'Zertifikate' 'certificates') $LIFE s"
}

stop() {
  alive sshd && kill "$(cat "$AD/sshd.pid")"; rm -f "$AD/sshd.pid"
  alive certs && kill "$(cat "$AD/certs.pid")"; rm -f "$AD/certs.pid"
  stop_agent_loop_unless "$LAB/state/webdemo/php.pid"
  ok "$(t gestoppt stopped)"
}

sshcmd() {   # Anmeldung mit dem aktuellen Zertifikat (oder ADMIN_KEYDIR=…)
  local k=${ADMIN_KEYDIR:-$CERT/current}
  ssh -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      -o IdentitiesOnly=yes -o ConnectTimeout=5 -i "$k/id_ed25519" -o CertificateFile="$k/id_ed25519-cert.pub" \
      "$(id -un)@127.0.0.1" "$@"
}

tunnel() {   # tunnel LOKALER_PORT ZIEL_SOCKET: jede Verbindung auf den Port wird zu einer eigenen
             # SSH-Sitzung mit dem aktuellen Zertifikat, die auf den Socket durchreicht (socat, Vordergrund)
  sshcmd true >/dev/null 2>&1 || { echo "$(t 'Gateway verweigert die Anmeldung' 'gateway refuses the sign-in')" >&2; return 1; }
  exec socat TCP-LISTEN:"$1",bind=127.0.0.1,reuseaddr,fork \
    EXEC:"bash $LAB/tools/admindemo.sh ssh socat STDIO UNIX-CONNECT\:$2",nofork
}

hook() {   # hook revoke|unrevoke HOST
  local action=${1:-} host=${2:-}
  [ -f "$ST/agent.json" ] && [ "$host" = "$(jq_host)" ] || { echo "$(t 'nicht betroffen' 'not affected'): $host"; return 0; }
  case "$action" in
    revoke)
      date +%s.%N > "$AD/revoked.$host"
      krl "$host" || exit 1
      local n=0 p
      if alive sshd; then for p in $(pgrep -P "$(cat "$AD/sshd.pid")"); do kill "$p" 2>/dev/null && n=$((n+1)); done; fi
      echo "$(t "Zertifikate von $host widerrufen, $n Admin-Sitzung(en) beendet" "certificates of $host revoked, $n admin session(s) ended")" ;;
    unrevoke)
      keep_old "$host"; krl || exit 1
      echo "$(t "Widerruf für $host aufgehoben, $(wc -l < "$AD/old.serials") alte(s) Zertifikat(e) bleiben widerrufen" "revocation of $host lifted, $(wc -l < "$AD/old.serials") old certificate(s) stay revoked")" ;;
    *) echo "hook revoke|unrevoke HOST"; exit 2 ;;
  esac
}

remove() {
  stop >/dev/null
  unregister_hook 60-admindemo
  rm -rf "$AD"
  ok "$(t 'Admin-Demo entfernt' 'admin demo removed')"
}

case "${1:-status}" in
  setup) setup ;; start) start ;; stop) stop ;; remove) remove ;;
  ssh) shift; sshcmd "$@" ;;
  tunnel) shift; tunnel "$@" ;;
  hook) shift; hook "$@" ;;
  status) alive sshd && echo "sshd: $(t läuft running) (127.0.0.1:$PORT)" || echo "sshd: $(t aus stopped)"
          alive certs && echo "$(t Zertifikate certificates): $(tail -n1 "$AD/certs.log" 2>/dev/null)" || echo "$(t Zertifikate certificates): $(t aus stopped)" ;;
  *) sed -n 3,18p "$0" ;;
esac
