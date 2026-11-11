#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# E-Mail-Zugangsdaten für das Lab erfassen: mail-setup.sh [--datei PFAD] [--test] [--zeigen] [--loeschen]
#   ohne Option  fragt Server, Port, Verschlüsselung, Benutzer, Passwort, Absender, Empfänger ab
#   --datei P    Zieldatei (Standard: keyleash.mail.env im Lab-Verzeichnis)
#   --test       nach dem Speichern (oder allein) eine Testmail senden
#   --zeigen     gespeicherte Werte anzeigen, Passwort maskiert
#   --loeschen   Zieldatei entfernen
# Vorhandene Werte werden als Vorgabe angeboten; Enter übernimmt sie.
# Die Datei bekommt Rechte 600 und gehört nicht in einen Export (siehe .gitignore).
#
# Store e-mail credentials for the lab: mail-setup.sh [--file PATH] [--test] [--show] [--delete]
#   (German option names --datei/--zeigen/--loeschen work as well; security 'none' = 'keine')
set -euo pipefail
LAB=$(cd "$(dirname "$0")/.." && pwd)
source "$LAB/lib/i18n.sh"
FILE="$LAB/keyleash.mail.env"; DO_TEST=0; MODE=erfassen
while [ $# -gt 0 ]; do
  case "$1" in
    --datei|--file) FILE=$2; shift ;;
    --test) DO_TEST=1; [ "$MODE" = erfassen ] && [ -f "$FILE" ] && MODE=nurtest ;;
    --zeigen|--show) MODE=zeigen ;;
    --loeschen|--delete) MODE=loeschen ;;
    -h|--help) if [ "${KEYLEASH_LANG:0:2}" = en ]; then sed -n '12,13p' "$0"; else sed -n '3,10p' "$0"; fi | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "$(t 'unbekannte Option' 'unknown option'): $1" >&2; exit 2 ;;
  esac; shift
done

load() { [ -f "$FILE" ] && { set -a; . "$FILE"; set +a; } || true; }

send_test() {
  load
  [ -n "${KEYLEASH_MAIL_HOST:-}" ] || { echo "$(t 'keine Zugangsdaten in' 'no credentials in') $FILE" >&2; exit 1; }
  python3 - <<'PY'
import os, smtplib, ssl, socket
from email.message import EmailMessage
e = os.environ
host, port, sec = e["KEYLEASH_MAIL_HOST"], int(e["KEYLEASH_MAIL_PORT"]), e["KEYLEASH_MAIL_SECURITY"]
m = EmailMessage()
m["From"], m["To"] = e["KEYLEASH_MAIL_FROM"], e["KEYLEASH_MAIL_TO"]
EN_ = e.get("KEYLEASH_LANG", "de").startswith("en")
m["Subject"] = (f"keyleash lab: test mail from {socket.gethostname()}" if EN_
                else f"keyleash Lab: Testmail von {socket.gethostname()}")
m.set_content("The e-mail credentials of the keyleash lab work." if EN_
              else "Die E-Mail-Zugangsdaten des keyleash Labs funktionieren.")
ctx = ssl.create_default_context()
try:
    if sec == "ssl":
        s = smtplib.SMTP_SSL(host, port, context=ctx, timeout=20)
    else:
        s = smtplib.SMTP(host, port, timeout=20)
        if sec == "starttls":
            s.starttls(context=ctx)
    with s:
        if e.get("KEYLEASH_MAIL_USER"):
            s.login(e["KEYLEASH_MAIL_USER"], e.get("KEYLEASH_MAIL_PASS", ""))
        s.send_message(m)
    print(f"Test mail sent to {m['To']}" if EN_ else f"Testmail an {m['To']} gesendet")
except Exception as x:
    raise SystemExit(("Test mail failed" if EN_ else "Testmail fehlgeschlagen") + f": {type(x).__name__}: {x}")
PY
}

# Wert für eine Shell-Datei in einfache Anführungszeichen setzen
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

ask() {  # ask VAR "Frage" [geheim]
  local var=$1 prompt=$2 secret=${3:-} cur=${!1:-} val
  if [ -n "$secret" ]; then
    local hint=""; [ -n "$cur" ] && hint=" [$(t 'gespeichert, Enter behält es' 'stored, Enter keeps it')]"
    read -rsp "$prompt$hint: " val; echo
  else
    read -rp "$prompt${cur:+ [$cur]}: " val
  fi
  printf -v "$var" '%s' "${val:-$cur}"
}

case "$MODE" in
  zeigen)
    [ -f "$FILE" ] || { echo "$FILE $(t 'existiert nicht' 'does not exist')"; exit 1; }
    sed -E "s/^(KEYLEASH_MAIL_PASS=).*/\1'********'/" "$FILE"; exit 0 ;;
  loeschen)
    rm -f "$FILE" && echo "$FILE $(t entfernt removed)"; exit 0 ;;
  nurtest)
    send_test; exit 0 ;;
esac

[ -t 0 ] || { echo "$(t 'bitte interaktiv im Terminal aufrufen' 'please run interactively in a terminal')" >&2; exit 1; }
load
: "${KEYLEASH_MAIL_PORT:=587}" "${KEYLEASH_MAIL_SECURITY:=starttls}"
echo "$(t 'E-Mail-Zugangsdaten für das keyleash Lab' 'E-mail credentials for the keyleash lab')  →  $FILE"
ask KEYLEASH_MAIL_HOST "$(t SMTP-Server 'SMTP server')"
while :; do
  [ "${KEYLEASH_LANG:0:2}" = en ] && [ "$KEYLEASH_MAIL_SECURITY" = keine ] && KEYLEASH_MAIL_SECURITY=none
  ask KEYLEASH_MAIL_SECURITY "$(t 'Verschlüsselung (starttls | ssl | keine)' 'Encryption (starttls | ssl | none)')"
  [ "$KEYLEASH_MAIL_SECURITY" = none ] && KEYLEASH_MAIL_SECURITY=keine
  case "$KEYLEASH_MAIL_SECURITY" in starttls|ssl|keine) break ;; *) KEYLEASH_MAIL_SECURITY= ; echo "  $(t 'bitte starttls, ssl oder keine' 'please enter starttls, ssl or none')" ;; esac
done
[ "$KEYLEASH_MAIL_SECURITY" = ssl ] && [ "$KEYLEASH_MAIL_PORT" = 587 ] && KEYLEASH_MAIL_PORT=465
while :; do
  ask KEYLEASH_MAIL_PORT "Port"
  [[ "$KEYLEASH_MAIL_PORT" =~ ^[0-9]+$ ]] && [ "$KEYLEASH_MAIL_PORT" -le 65535 ] && break
  KEYLEASH_MAIL_PORT=; echo "  $(t 'bitte eine Portnummer' 'please enter a port number')"
done
ask KEYLEASH_MAIL_USER "$(t 'Benutzername (leer = ohne Anmeldung)' 'User name (empty = no login)')"
if [ -n "$KEYLEASH_MAIL_USER" ]; then
  while :; do
    old=${KEYLEASH_MAIL_PASS:-}
    ask KEYLEASH_MAIL_PASS "$(t Passwort Password)" geheim
    [ "$KEYLEASH_MAIL_PASS" = "$old" ] && [ -n "$old" ] && break
    read -rsp "$(t 'Passwort wiederholen' 'Repeat password'): " again; echo
    [ "$again" = "$KEYLEASH_MAIL_PASS" ] && [ -n "$again" ] && break
    KEYLEASH_MAIL_PASS=$old; echo "  $(t 'Eingaben stimmen nicht überein oder sind leer' 'Entries do not match or are empty')"
  done
else
  KEYLEASH_MAIL_PASS=
fi
[ -z "${KEYLEASH_MAIL_FROM:-}" ] && [[ "$KEYLEASH_MAIL_USER" == *@* ]] && KEYLEASH_MAIL_FROM=$KEYLEASH_MAIL_USER
ask KEYLEASH_MAIL_FROM "$(t Absender Sender)"
ask KEYLEASH_MAIL_TO "$(t 'Empfänger (mehrere mit Komma)' 'Recipients (comma-separated)')"
for v in KEYLEASH_MAIL_HOST KEYLEASH_MAIL_FROM KEYLEASH_MAIL_TO; do
  [ -n "${!v}" ] || { echo "$v $(t 'fehlt, nichts gespeichert' 'missing, nothing saved')" >&2; exit 1; }
done

umask 077
tmp=$(mktemp "$FILE.XXXXXX")
{
  echo "# keyleash Lab – E-Mail-Zugangsdaten, erzeugt von tools/mail-setup.sh am $(date '+%F %T')"
  echo "# Enthält ein Passwort: nicht weitergeben, nicht exportieren."
  for v in HOST PORT SECURITY USER PASS FROM TO; do
    n=KEYLEASH_MAIL_$v; echo "$n=$(q "${!n}")"
  done
} > "$tmp"
chmod 600 "$tmp"; mv -f "$tmp" "$FILE"
echo "$(t gespeichert saved): $FILE ($(t 'nur lesbar für' 'readable only by') $(id -un))"

if [ "$DO_TEST" = 1 ]; then send_test
else read -rp "$(t 'Testmail senden? [j/N]' 'Send a test mail? [y/N]') " a; [[ "$a" =~ ^[jJyY] ]] && send_test || true; fi
