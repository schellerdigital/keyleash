#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Kurzfassung für ein Video (60–90 s): wenige Szenen, knappe Ausgabe ohne
# TPM-Befehle, Fehlercodes, Pfade oder Rechnernamen.
# Short version for a video: few scenes, terse output without TPM commands,
# error codes, paths or host names.
#
#   demos/reel.sh prep        Vorbereitung (eigener Server auf Port 8742, eigener Zustand)
#   demos/reel.sh 1 … 7       einzelne Szenen (6: Signaturmenge, 7: ohne TPM / NetHSM)
#   demos/reel.sh siem        Alarme der Aufnahme
#   demos/reel.sh all         alles am Stück (zum Üben, ohne Video)
#   demos/reel.sh clean       Aufnahme-Server stoppen, Zustand löschen
#
# Getrennt vom normalen Lab: Zustand in state/reel/, Server auf Port 8742,
# Systemname "build-server-01". Das echte Lab und seine Schlüssel bleiben unberührt.
LAB=$(cd "$(dirname "$0")/.." && pwd)
RS=$LAB/state/reel
export KEYLEASH_STATE=$RS
export KEYLEASH_SERVER=http://127.0.0.1:8742 KEYLEASH_LISTEN=127.0.0.1:8742
export KEYLEASH_HOST_ID=${KEYLEASH_REEL_HOST:-build-server-01}
export KEYLEASH_MIN_INTERVAL=1 KEYLEASH_GRACE=3
export KEYLEASH_APPROVAL=release=$RS/approver/release_pub.pem
export KEYLEASH_REVOKE_HOOK=""          # Sperr-Hooks des echten Labs nie aus der Aufnahme auslösen
export KEYLEASH_REMOTE_HOST=${KEYLEASH_REEL_REMOTE_HOST:-cloud-vm-01}
export KEYLEASH_SIG_DENY=0
source "$(dirname "$0")/common.sh"
W=$RS/work; mkdir -p "$W"
# Python mit dem Modul cryptography wählen. In der vhs-Shell kann "python3" ein
# anderes sein als im normalen Terminal (PATH, pyenv, conda …).
PY=""
for c in python3 /usr/bin/python3; do
  command -v "$c" >/dev/null 2>&1 && "$c" -c "import cryptography" 2>/dev/null && { PY=$(command -v "$c"); break; }
done
AG="$PY $LAB/agent/agent.py"
AP="$PY $LAB/tools/approve.py"
RC="$PY $LAB/agent/remote.py"
NETHSM=$([ "${KEYLEASH_KEYSTORE:-$(grep -oP '^KEYLEASH_KEYSTORE=\K\w+' "$LAB/keyleash.env" 2>/dev/null)}" = nethsm ] && echo 1)
SIEM=$RS/server/siem.jsonl
ERRLOG=$RS/errors.log

# ---------- Darstellung -----------------------------------------------------
scene() { echo; echo "${B}${C}── $1 ──${N}"; }
say()   { echo "  $*"; }
good()  { echo "  ${G}✔${N} $*"; }
deny()  { echo "  ${R}✘${N} $*"; }
later() { echo; echo "  ${Y}… $*${N}"; }

# Grund einer Ablehnung in Klartext (ohne Befehle und Codes)
reason() {
  local f=$1
  if   grep -q "ticket_signature\|ticket signature\|Ticket-Signatur\|policy check failed\|not available for selected entity" "$f"; then t 'kein gültiges Ticket' 'no valid ticket'
  elif grep -q "Ablaufzeit\|expiry" "$f"; then t 'Ticket abgelaufen' 'ticket expired'
  elif grep -q "Neustart-Grenze\|reboot limit" "$f"; then t 'Neustart-Grenze erreicht' 'reboot limit reached'
  elif grep -q "Boot-Zustand\|boot state" "$f"; then t 'Systemzustand verändert' 'system state has changed'
  elif grep -q "PolicySigned\|requires an approval\|verlangt eine Freigabe" "$f"; then t 'keine gültige Freigabe' 'no valid approval'
  elif grep -q "remote_sender\|remote_absender" "$f"; then t 'falsche Absenderadresse' 'wrong sender address'
  elif grep -q "remote_limit\|remote_menge" "$f"; then t 'Mengengrenze erreicht' 'volume limit reached'
  elif grep -q "revoked\|gesperrt" "$f"; then t 'System gesperrt' 'host revoked'
  elif grep -q "tampering\|manipulation" "$f"; then t 'Systemzustand weicht ab' 'system state deviates'
  else t 'verweigert' 'refused'; fi
}
must_fail() {  # [--why GRUND] Text  Befehl…
  local why=""; [ "$1" = --why ] && { why=$2; shift 2; }
  local what=$1; shift
  if "$@" >"$W/out" 2>&1; then deny "$(t 'UNERWARTET erfolgreich' 'UNEXPECTEDLY succeeded'): $what"; return 1; fi
  deny "$what – $(t 'vom TPM verweigert' 'refused by the TPM'): ${why:-$(reason "$W/out")}"
}
must_fail_server() {
  local what=$1; shift
  if "$@" >"$W/out" 2>&1; then deny "$(t 'UNERWARTET erfolgreich' 'UNEXPECTEDLY succeeded'): $what"; return 1; fi
  deny "$what – $(t 'Server lehnt ab' 'server refuses'): $(reason "$W/out")"
}
# Fehler nie mit Pfaden oder Tracebacks auf den Bildschirm – nur ins Log
quiet() { "$@" >"$W/out" 2>&1 || { { echo "== $*"; cat "$W/out"; } >> "$ERRLOG"; deny "$(t 'unerwarteter Fehler (state/reel/errors.log)' 'unexpected error (state/reel/errors.log)')"; return 1; }; }
need_ready() {
  [ -f "$RS/.ready" ] && server_up && return 0
  echo "  $(t 'Aufnahme nicht vorbereitet – zuerst: demos/reel.sh prep' 'recording not prepared – first: demos/reel.sh prep')"; exit 1
}
siem_last() {  # letzte Alarme/Warnungen knapp
  [ -f "$SIEM" ] || return 0
  "$PY" - "$SIEM" "${1:-1}" <<'P'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
recs = [r for r in recs if r.get("severity") == "alarm"]
tty = sys.stdout.isatty()
for r in recs[-int(sys.argv[2]):]:
    why = r.get("reason") or r.get("grund") or ""
    head = "\033[31mSIEM ALERT\033[0m" if tty else "SIEM ALERT"
    print(f"  {head} {r['event']}" + (f"  ({why})" if why else ""))
P
}

server_up() { curl -sf "$KEYLEASH_SERVER/authz" >/dev/null 2>&1; }
start_server() {
  server_up && return
  nohup "$PY" "$LAB/server/authz_server.py" >> "$RS/server.log" 2>&1 &
  echo $! > "$RS/server.pid"
  for _ in $(seq 30); do server_up && return; sleep 0.3; done
  echo "server does not start, see $RS/server.log"; exit 1
}
renew() { sleep 1.2; $AG renew "$@" >"$W/out" 2>&1; }

# ---------- Szenen ----------------------------------------------------------
prep() {
  rm -f "$RS/.ready"
  [ -n "$PY" ] || { echo "no python3 with the 'cryptography' module found (sudo apt install python3-cryptography)" >&2; exit 1; }
  mkdir -p "$RS"; : > "$ERRLOG"
  start_server
  [ -f "$RS/agent/agent.json" ] || quiet $AG enroll || { cat "$ERRLOG" >&2; exit 1; }
  quiet $AP init release || { cat "$ERRLOG" >&2; exit 1; }
  [ -d "$RS/agent/purpose-release" ] || quiet $AG enroll-purpose release || { cat "$ERRLOG" >&2; exit 1; }
  tpm2_pcrreset 16 >/dev/null 2>&1
  echo "Quarterly report" > "$W/report.txt"
  echo "Release 2.0.0" > "$W/release.tar"; cp "$W/release.tar" "$W/release-copy.tar"
  renew || { cat "$W/out" >&2; exit 1; }
  quiet $RC init --host "$KEYLEASH_REMOTE_HOST" || { cat "$ERRLOG" >&2; exit 1; }
  "$PY" "$LAB/tools/remote-setup.py" add "$KEYLEASH_REMOTE_HOST" --purpose deploy \
    --client-pub "$RS/remote-client/client_pub.pem" --ip 127.0.0.1 >"$W/out" 2>&1 \
    || { cat "$W/out" >&2; echo "NetHSM: einmal interaktiv ausführen (Admin-Passwort) oder KEYLEASH_NETHSM_ADMIN_PASS setzen" >&2; exit 1; }
  echo "Deploy 4.1" > "$W/deploy.tar"
  touch "$RS/.ready"
  echo "ready (python: $PY)"
}

s1() {
  need_ready
  scene "$(t '1 · Normalbetrieb' '1 · Normal operation')"
  say "$(t 'Der Schlüssel liegt im TPM. Signieren geht nur mit einem kurzlebigen Ticket.' 'The key lives in the TPM. Signing only works with a short-lived ticket.')"
  renew && good "$(t 'Ticket erhalten – gültig 10 Minuten' 'ticket issued – valid for 10 minutes')"
  quiet $AG sign "$W/report.txt" -o "$W/report.sig" && good "$(t 'Dokument signiert' 'document signed')"
  verify/verify.sh "$W/report.txt" "$W/report.sig" "$RS/agent/cert.pem" "$RS/agent/ca.pem" >/dev/null \
    && good "$(t 'Gegenstelle prüft wie bisher: Signatur gültig' 'relying party verifies as usual: signature valid')"
}

s2() {
  need_ready
  scene "$(t '2 · Angreifer mit Schlüsseldatei und Geheimnis' '2 · Attacker with the key file and its secret')"
  say "$(t 'Er versucht, am Ticket vorbei zu signieren.' 'They try to sign without a ticket.')"
  local auth; auth=$(cat "$RS/agent/key.auth")
  try_pw() {
    tpm2_createprimary -C o -G rsa -c "$W/p.ctx" >/dev/null &&
    tpm2_load -C "$W/p.ctx" -u "$RS/agent/key.pub" -r "$RS/agent/key.priv" -c "$W/k.ctx" >/dev/null &&
    echo -n "hex:$auth" | tpm2_sign -c "$W/k.ctx" -p file:- -g sha256 -o "$W/x.sig" "$W/report.txt"
  }
  must_fail "$(t 'Signatur ohne Ticket' 'signature without ticket')" try_pw
  say "$(t 'Kopieren hilft nicht: Der Schlüssel kann das TPM nie verlassen.' 'Copying does not help: the key can never leave the TPM.')"
}

s3() {
  need_ready
  scene "$(t '3 · Keine Erneuerung' '3 · No renewal')"
  renew --ttl 5 && good "$(t 'Ticket mit 5 Sekunden Laufzeit' 'ticket with a 5-second lifetime')"
  quiet $AG sign "$W/report.txt" -o "$W/report.sig" && good "$(t 'signiert' 'signed')"
  later "$(t '8 Sekunden später, ohne Erneuerung' '8 seconds later, no renewal')"
  sleep 8
  must_fail "$(t 'Signatur' 'signature')" $AG sign "$W/report.txt" -o "$W/report.sig"
  say "$(t 'Die Identität endet von selbst. Keine Sperrliste, kein Rollout.' 'The identity ends on its own. No revocation list, no rollout.')"
}

s4() {
  need_ready
  scene "$(t '4 · Manipuliertes System' '4 · Tampered system')"
  renew && good "$(t 'gültiges Ticket' 'valid ticket')"
  tpm2_pcrextend 16:sha256=$(echo -n "tamper" | sha256sum | cut -c1-64) >/dev/null
  say "$(t 'Der gemessene Systemzustand ändert sich …' 'The measured system state changes …')"
  must_fail --why "$(t 'Zustand geändert' 'state changed')" \
    "$(t 'Signatur mit dem vorigen Ticket' 'signing with the earlier ticket')" $AG sign "$W/report.txt" -o "$W/report.sig"
  must_fail_server "$(t 'neues Ticket' 'new ticket')" renew
  siem_last 1
  tpm2_pcrreset 16 >/dev/null 2>&1
}

s5() {
  need_ready
  scene "$(t '5 · Release-Signatur nur mit zweitem System' '5 · Release signing needs a second system')"
  renew
  quiet $AG request "$W/release.tar" --purpose release -o "$W/release.req"
  quiet $AP approve "$W/release.req" --file "$W/release-copy.tar" --yes -o "$W/release.ok" \
    && good "$(t 'zweites System prüft eigene Kopie, gibt Release 2.0.0 frei' 'second system checks its own copy, approves release 2.0.0')"
  cp "$W/release.tar" "$W/release-backdoor.tar"; echo "backdoor" >> "$W/release-backdoor.tar"
  must_fail "$(t 'dieselbe Freigabe für manipulierten Build' 'same approval on a tampered build')" \
    $AG sign "$W/release-backdoor.tar" -o "$W/x.sig" --purpose release --approval "$W/release.ok"
  quiet $AG sign "$W/release.tar" -o "$W/release.sig" --purpose release --approval "$W/release.ok" \
    && good "$(t 'Release 2.0.0 signiert – Freigabe gilt nur für genau diese Datei' 'release 2.0.0 signed – the approval covers exactly this file')"
  say "$(t 'Ohne Freigabe kann auch root auf dem Build-Server nicht signieren.' 'Without approval, not even root on the build server can sign.')"
}

s6() {
  need_ready
  scene "$(t '6 · Auffällige Signaturmenge' '6 · Unusual signing volume')"
  say "$(t 'Ein Angreifer nutzt die echte Signaturumgebung – in kleinen Portionen.' 'An attacker uses the real signing environment – in small portions.')"
  local i
  for i in 1 2; do
    for _ in 1 2 3 4 5 6; do quiet $AG sign "$W/report.txt" -o "$W/x.sig" --purpose export || return 1; done
    renew && good "$(t "6 Signaturen für einen neuen Zweck, Ticket erneuert" "6 signatures for a new purpose, ticket renewed")"
  done
  say "$(t 'Jede Portion für sich unauffällig – die Summe in der Stunde nicht.' 'Each portion looks harmless – the hourly total does not.')"
  siem_last 1
}

s7() {
  need_ready
  scene "$(t '7 · Ohne TPM: Cloud-Server mit Signaturdienst' '7 · Without a TPM: cloud server with a signing service')"
  if [ -n "$NETHSM" ]; then say "$(t 'Der Schlüssel liegt im NetHSM, auf der VM nur ein Anmeldeschlüssel.' 'The key lives in the NetHSM, the VM only holds a sign-in key.')"
  else say "$(t 'Der Schlüssel liegt beim keyleash-Server, auf der VM nur ein Anmeldeschlüssel.' 'The key stays with the keyleash server, the VM only holds a sign-in key.')"; fi
  quiet $RC sign "$W/deploy.tar" --purpose deploy -o "$W/deploy.sig" && good "$(t 'Deployment signiert' 'deployment signed')"
  rm -rf "$W/stolen"; cp -r "$RS/remote-client" "$W/stolen"
  must_fail_server "$(t 'gestohlener Anmeldeschlüssel, anderer Rechner' 'stolen sign-in key, other machine')" \
    $RC sign "$W/deploy.tar" --purpose deploy -o "$W/x.sig" --dir "$W/stolen" --source 127.0.0.2
  curl -sf -X POST -H 'Content-Type: application/json' -d "{\"host\":\"$KEYLEASH_REMOTE_HOST\"}" "$KEYLEASH_SERVER/admin/revoke" >/dev/null
  say "$(t 'Administrator sperrt die VM …' 'The administrator revokes the VM …')"
  must_fail_server "$(t 'nächste Signatur' 'next signature')" $RC sign "$W/deploy.tar" --purpose deploy -o "$W/x.sig"
  curl -sf -X POST -H 'Content-Type: application/json' -d "{\"host\":\"$KEYLEASH_REMOTE_HOST\"}" "$KEYLEASH_SERVER/admin/unrevoke" >/dev/null
  say "$(t 'Sofort – kein Ticket, das erst ablaufen muss.' 'Immediately – no ticket that has to expire first.')"
}

siem() {
  need_ready
  scene "$(t 'Alles landet im SIEM' 'Everything lands in the SIEM')"
  siem_last 4
}

clean() {
  [ -f "$RS/server.pid" ] && kill "$(cat "$RS/server.pid")" 2>/dev/null
  tpm2_pcrreset 16 >/dev/null 2>&1
  rm -rf "$RS"; echo "$(t 'Aufnahme-Zustand gelöscht' 'recording state removed')"
}

case "${1:-all}" in
  prep) prep ;; 1) s1 ;; 2) s2 ;; 3) s3 ;; 4) s4 ;; 5) s5 ;; 6) s6 ;; 7) s7 ;; siem) siem ;; clean) clean ;;
  all) prep >/dev/null && s1 && s2 && s3 && s4 && s5 && s6 && s7 && siem ;;
  *) sed -n 8,13p "$0" ;;
esac
