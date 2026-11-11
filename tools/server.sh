#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Autorisierungsserver verwalten: start | vorne | stop | status | log | siem | hosts | revoke HOST | unrevoke HOST | rebaseline HOST | sigreset HOST | forget HOST
# Manage the authorisation server: start | vorne (foreground) | stop | status | log | siem | hosts | revoke HOST | unrevoke HOST | rebaseline HOST | sigreset HOST | forget HOST
LAB=$(cd "$(dirname "$0")/.." && pwd); cd "$LAB"; mkdir -p state
source "$LAB/lib/i18n.sh"
URL=$(grep -oP '^KEYLEASH_SERVER=\K\S+' keyleash.env)
running() { curl -sf "$URL/authz" >/dev/null 2>&1; }
adm() { curl -sf -X POST -H 'Content-Type: application/json' -d "{\"host\":\"$2\"}" "$URL/admin/$1" && echo; }
case "${1:-status}" in
  start) running && { echo "$(t 'läuft bereits' 'already running')"; exit 0; }
         nohup python3 server/authz_server.py >> state/server.log 2>&1 & echo $! > state/server.pid
         for _ in $(seq 20); do running && break; sleep 0.5; done   # mit NetHSM dauert der Start etwas
         running && echo "$(t gestartet started) ($URL), Log: state/server.log" || { echo "$(t 'Start fehlgeschlagen:' 'Start failed:')"; tail state/server.log; } ;;
  vorne|foreground) exec python3 server/authz_server.py ;;   # im Vordergrund / in the foreground
  stop)  [ -f state/server.pid ] && kill "$(cat state/server.pid)" 2>/dev/null; rm -f state/server.pid; echo "$(t gestoppt stopped)" ;;
  status) running && echo "$(t läuft running) ($URL)" || echo "$(t 'läuft nicht' 'not running')" ;;
  log)   tail -f state/server.log ;;
  siem)  tail -f state/server/siem.jsonl | python3 tools/siem-report.py --lines ;;
  hosts) curl -sf "$URL/admin/hosts" | python3 -m json.tool ;;
  revoke|unrevoke|rebaseline|sigreset|forget) adm "$1" "$2" ;;
  *) [ "${KEYLEASH_LANG:0:2}" = en ] && sed -n 4p "$0" || sed -n 3p "$0" ;;
esac
