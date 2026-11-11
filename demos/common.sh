# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Gemeinsame Funktionen für die Demo-Skripte (wird per "source" geladen)
set -uo pipefail
LAB=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$LAB"
# keyleash.env laden; bereits gesetzte Variablen (z. B. KEYLEASH_TPM=swtpm ./demo) haben Vorrang
while IFS='=' read -r k v; do
  [ -z "${!k+x}" ] && export "$k=$v"
done < <(grep -E '^[A-Z_]+=' keyleash.env | sed 's/[[:space:]]*#.*$//; s/[[:space:]]*$//')
export KEYLEASH_TPM=${KEYLEASH_TPM:-hw}
source "$LAB/lib/i18n.sh"
if [ "$KEYLEASH_TPM" = swtpm ]; then
  export DBUS_SESSION_BUS_ADDRESS=unix:path=$LAB/state/swtpm/dbus.sock
  export TPM2TOOLS_TCTI=tabrmd:bus_type=session
else
  export TPM2TOOLS_TCTI=device:/dev/tpmrm0
fi
AG="python3 $LAB/agent/agent.py"
ST=$LAB/state/agent
W=$LAB/state/demo; mkdir -p "$W"

if [ -t 1 ]; then B=$'\e[1m'; C=$'\e[36m'; Y=$'\e[33m'; G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'
else B= C= Y= G= R= N=; fi

title() { echo; echo "${B}━━ $* ━━${N}"; }
step()  { echo; echo "${C}▶ $*${N}"; }
note()  { echo "  ${Y}$*${N}"; }
expect_fail() {  # Befehl, der scheitern MUSS
  if "$@" >"$W/out" 2>&1; then echo "  ${R}✘ $(t 'UNERWARTET: hat funktioniert' 'UNEXPECTED: it worked')${N}"; return 1
  else echo "  ${G}✔ $(t 'wie erwartet verweigert' 'refused as expected'):${N} $( { grep -E 'tpm:|verweigert|denied|refused' "$W/out" || cat "$W/out"; } | tail -1 | sed 's/^ *//')"; fi
}

server_running() { curl -sf "$KEYLEASH_SERVER/authz" >/dev/null 2>&1; }
ensure_server() {
  server_running && return
  note "$(t 'Starte Autorisierungsserver im Hintergrund' 'Starting the authorisation server in the background') (Log: state/server.log)"
  nohup python3 "$LAB/server/authz_server.py" >> "$LAB/state/server.log" 2>&1 &
  echo $! > "$LAB/state/server.pid"
  for _ in $(seq 20); do server_running && return; sleep 0.3; done
  echo "${R}$(t 'Server startet nicht, siehe' 'Server does not start, see') state/server.log${N}"; exit 1
}
ensure_enrolled() {
  [ -f "$ST/agent.json" ] || { echo "${R}$(t 'Noch nicht provisioniert: zuerst' 'Not enrolled yet: first run') demos/10-provisionieren.sh${N}"; exit 1; }
}
admin() { curl -sf -X POST -H 'Content-Type: application/json' -d "{\"host\":\"$(jq_host)\"}" "$KEYLEASH_SERVER/admin/$1" >/dev/null; }
jq_host() { python3 -c "import json;print(json.load(open('$ST/agent.json'))['host'])"; }
siem_tail() { tail -n "${1:-3}" "$LAB/state/server/siem.jsonl" | python3 "$LAB/tools/siem-report.py" --lines; }
pause_min_interval() { sleep "$(python3 -c "print(float('${KEYLEASH_MIN_INTERVAL:-5}')+1)")"; }

# Gemeinsamer Agent-Loop für die Dauer-Demos (Webserver, Admin-Arbeitsplatz): genau einer, sonst
# kämen sich zwei Erneuerungen in die Quere (Alarm anfrage_zu_haeufig_parallel).
AGENT_LOOP_PID=$LAB/state/agentloop.pid
agent_loop_alive() { [ -f "$AGENT_LOOP_PID" ] && kill -0 "$(cat "$AGENT_LOOP_PID")" 2>/dev/null; }
ensure_agent_loop() {
  agent_loop_alive && return
  nohup python3 "$LAB/agent/agent.py" loop >> "$LAB/state/agentloop.log" 2>&1 &
  echo $! > "$AGENT_LOOP_PID"; sleep 2
}
stop_agent_loop_unless() {   # stop_agent_loop_unless PIDDATEI…: nur stoppen, wenn keine andere Demo läuft
  local f; for f in "$@"; do [ -f "$f" ] && kill -0 "$(cat "$f")" 2>/dev/null && return; done
  agent_loop_alive && kill "$(cat "$AGENT_LOOP_PID")"; rm -f "$AGENT_LOOP_PID"
}
# Sperr-Hook registrieren: register_hook NAME BEFEHL… (Server liest KEYLEASH_REVOKE_HOOK beim Start)
register_hook() {
  local name=$1; shift
  mkdir -p "$LAB/state/hooks.d"
  printf '#!/usr/bin/env bash\nexec %s "$@"\n' "$*" > "$LAB/state/hooks.d/$name"; chmod +x "$LAB/state/hooks.d/$name"
  if ! grep -q '^KEYLEASH_REVOKE_HOOK=tools/revoke-hooks.sh' "$LAB/keyleash.env"; then
    sed -i '/^# Sperr-Hook der Webdemo/d; /^KEYLEASH_REVOKE_HOOK=/d' "$LAB/keyleash.env"
    printf '\n# Sperr-Hooks der Demos (state/hooks.d/)\nKEYLEASH_REVOKE_HOOK=tools/revoke-hooks.sh\n' >> "$LAB/keyleash.env"
    "$LAB/tools/server.sh" stop >/dev/null 2>&1; sleep 1
  fi
  export KEYLEASH_REVOKE_HOOK=tools/revoke-hooks.sh   # sonst erbte ein neu gestarteter Server den alten Wert
  ensure_server
}
unregister_hook() {
  rm -f "$LAB/state/hooks.d/$1"
  if [ -z "$(ls -A "$LAB/state/hooks.d" 2>/dev/null)" ]; then
    sed -i '/^# Sperr-Hooks der Demos/d; /^KEYLEASH_REVOKE_HOOK=tools\/revoke-hooks.sh/d' "$LAB/keyleash.env"
    "$LAB/tools/server.sh" stop >/dev/null 2>&1; unset KEYLEASH_REVOKE_HOOK
  fi
}
