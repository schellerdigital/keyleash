#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# keyleash Lab – Installationsdatei / installer   (Version @VERSION@)
#
#   bash keyleash-install.sh [Optionen]
#
#   --rolle lab|agent|server   lab    = Server und Agent auf einer Maschine (Standard)
#   --role  …                  agent  = nur Agent (TPM-Maschine), braucht --server
#                              server = nur Autorisierungsserver (kein TPM nötig)
#   --ziel DIR / --dir DIR     Zielordner (Standard: ~/keyleash-lab)
#   --server URL               Adresse des Servers für den Agenten, z. B. http://10.0.0.5:8740
#   --listen ADR:PORT          Adresse, auf der der Server lauscht (Standard 127.0.0.1:8740)
#   --swtpm                    Software-TPM mitinstallieren (ohne Hardware-TPM: automatisch)
#   --lang de|en               Sprache der Ausgabe und des Labs
#   --ja / --yes               keine Rückfragen
#   --pruefen / --check        nur prüfen, was fehlt; nichts ändern
#   --trockenlauf / --dry-run  zeigen, was getan würde
#   --hilfe / --help
#
# Unterstützt: Debian, Ubuntu, Linux Mint (apt); Fedora, RHEL, Rocky, AlmaLinux (dnf).
# Root-Rechte nur für Pakete, Gruppe tss und udev-Regel; dafür wird sudo verwendet.
set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"   # Debian: tpm2-abrmd u. a. in /usr/sbin, für normale Benutzer nicht im PATH

VERSION="@VERSION@"
PAYLOAD_SHA256="@SHA256@"

HELP=0; ROLE=lab; DEST=""; SERVER_URL=""; LISTEN=""; WANT_SWTPM=0; YES=0; CHECK_ONLY=0; DRY=0; LANG_GIVEN=0; SWTPM_GIVEN=0
LANG_SEL="${KEYLEASH_LANG:-de}"
while [ $# -gt 0 ]; do
  case "$1" in
    --rolle|--role) ROLE="${2:?}"; shift 2 ;;
    --ziel|--dir) DEST="${2:?}"; shift 2 ;;
    --server) SERVER_URL="${2:?}"; shift 2 ;;
    --listen) LISTEN="${2:?}"; shift 2 ;;
    --swtpm) WANT_SWTPM=1; SWTPM_GIVEN=1; shift ;;
    --lang) LANG_SEL="${2:?}"; LANG_GIVEN=1; shift 2 ;;
    --ja|--yes|-y) YES=1; shift ;;
    --pruefen|--check) CHECK_ONLY=1; shift ;;
    --trockenlauf|--dry-run) DRY=1; shift ;;
    --hilfe|--help|-h) HELP=1; shift ;;
    *) echo "unbekannte Option / unknown option: $1" >&2; exit 2 ;;
  esac
done
LANG_SEL=${LANG_SEL:0:2}; [ "$LANG_SEL" = en ] || LANG_SEL=de
t() { if [ "$LANG_SEL" = en ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
if [ $HELP = 1 ]; then
  if [ "$LANG_SEL" = en ]; then cat <<'HLP'
keyleash lab – installer

  bash keyleash-install.sh [options]

  --role lab|agent|server    lab    = server and agent on one machine (default)
                             agent  = agent only (TPM machine), needs --server
                             server = authorisation server only (no TPM needed)
  --dir DIR                  target directory (default: ~/keyleash-lab)
  --server URL               server address for the agent, e.g. http://10.0.0.5:8740
  --listen ADDR:PORT         address the server listens on (default 127.0.0.1:8740)
  --swtpm                    also install the software TPM (automatic without a hardware TPM)
  --lang de|en               language of output and lab
  --yes                      no questions
  --check                    only check what is missing; change nothing
  --dry-run                  show what would be done
  --help

Supported: Debian, Ubuntu, Linux Mint (apt); Fedora, RHEL, Rocky, AlmaLinux (dnf).
Root rights only for packages, the tss group and a udev rule; sudo is used for that.
HLP
  else sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; fi
  exit 0
fi

if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else B= G= Y= R= N=; fi
step() { echo; echo "${B}▶ $*${N}"; }
ok()   { echo "  ${G}✔${N} $*"; }
warn() { echo "  ${Y}!${N} $*"; }
die()  { echo "  ${R}✘ $*${N}" >&2; exit 1; }

case "$ROLE" in lab|agent|server) ;; *) die "$(t "--rolle muss lab, agent oder server sein" "--role must be lab, agent or server")";; esac
[ "$ROLE" = agent ] && [ -z "$SERVER_URL" ] && die "$(t "Rolle agent braucht --server URL (z. B. http://10.0.0.5:8740)" "role agent needs --server URL (e.g. http://10.0.0.5:8740)")"

# Wer ist der eigentliche Benutzer? (bei sudo der aufrufende)
if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then USR=$SUDO_USER; else USR=$(id -un); fi
UHOME=$(getent passwd "$USR" | cut -d: -f6)
DEST=${DEST:-$UHOME/keyleash-lab}
if [ $LANG_GIVEN = 0 ] && [ -f "$DEST/keyleash.env" ]; then  # Sprache einer vorhandenen Installation übernehmen
  l=$(sed -n 's/^KEYLEASH_LANG=\([a-z]*\).*/\1/p' "$DEST/keyleash.env"); [ -n "$l" ] && LANG_SEL=$l
fi

run_root() {  # Befehl mit Root-Rechten (sudo, falls nötig)
  if [ $DRY = 1 ]; then echo "    [$(t trockenlauf dry-run)] $*"; return 0; fi
  if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi
}
run_user() {  # Befehl als eigentlicher Benutzer
  if [ $DRY = 1 ]; then echo "    [$(t trockenlauf dry-run)] $*"; return 0; fi
  if [ "$(id -u)" = 0 ] && [ "$USR" != root ]; then sudo -u "$USR" "$@"; else "$@"; fi
}
confirm() {
  [ $YES = 1 ] && return 0
  [ -t 0 ] || die "$(t "keine Rückfrage möglich (kein Terminal) – mit --ja bestätigen" "cannot ask (no terminal) – confirm with --yes")"
  local a; read -r -p "  $1 [j/N] " a; [[ "$a" =~ ^[jJyY] ]]
}

echo "${B}keyleash Lab – $(t Installation installer) $VERSION${N}"
echo "  $(t Rolle Role): $ROLE   $(t Ziel Target): $DEST   $(t Benutzer User): $USR"

# ---------------------------------------------------------------- System ----
step "$(t System System)"
OSR=${KEYLEASH_OS_RELEASE:-/etc/os-release}
[ -r "$OSR" ] || die "$(t "$OSR fehlt – System nicht erkannt" "$OSR missing – system not recognised")"
OS_ID=$(. "$OSR"; echo "${ID:-}"); OS_LIKE=$(. "$OSR"; echo "${ID_LIKE:-}"); OS_NAME=$(. "$OSR"; echo "${PRETTY_NAME:-$ID}")
case " $OS_ID $OS_LIKE " in
  *" debian "*|*" ubuntu "*) PM=apt ;;
  *" fedora "*|*" rhel "*|*" centos "*) PM=dnf ;;
  *) die "$(t "nicht unterstützt: $OS_NAME (nur apt- oder dnf-Systeme)" "not supported: $OS_NAME (apt or dnf systems only)")" ;;
esac
ok "$OS_NAME ($PM)"
EL=0; case " $OS_ID $OS_LIKE " in *" rhel "*|*" centos "*) EL=1 ;; esac

HAVE_TPM=0; [ -c /dev/tpmrm0 ] && HAVE_TPM=1
if [ "$ROLE" != server ]; then
  if [ $HAVE_TPM = 1 ]; then ok "$(t "Hardware-TPM gefunden" "hardware TPM found") (/dev/tpmrm0)"
  elif [ $WANT_SWTPM = 0 ]; then
    warn "$(t "kein /dev/tpmrm0 – TPM im BIOS aktivieren (Security/Trusted Computing) oder Software-TPM nutzen" "no /dev/tpmrm0 – enable the TPM in the BIOS (Security/Trusted Computing) or use the software TPM")"
    if [ $CHECK_ONLY = 1 ] || [ $DRY = 1 ]; then WANT_SWTPM=1; warn "$(t "Prüfung schließt das Software-TPM ein" "check includes the software TPM")"
    elif confirm "$(t "Software-TPM (swtpm) mitinstallieren?" "Install the software TPM (swtpm)?")"; then WANT_SWTPM=1
    else warn "$(t "ohne TPM lässt sich der Agent nicht nutzen" "the agent cannot be used without a TPM")"; fi
  fi
fi

# ----------------------------------------------------------------- Pakete ----
# Jeder Eintrag: Prüfung <TAB> apt-Paket (Alternativen mit /) <TAB> dnf-Paket
REQ=()
add() { REQ+=("$1"$'\t'"$2"$'\t'"$3"); }
add "command -v python3"                                   "python3"                  "python3"
add "python3 -c 'import cryptography'"                    "python3-cryptography"     "python3-cryptography"
add "command -v openssl"                                   "openssl"                  "openssl"
add "command -v curl"                                      "curl"                     "curl"
if [ "$ROLE" != server ]; then
  add "command -v tpm2_createprimary"                      "tpm2-tools"               "tpm2-tools"
fi
if [ $WANT_SWTPM = 1 ] && [ "$ROLE" != server ]; then
  add "command -v swtpm"                                   "swtpm"                    "swtpm"
  add "command -v swtpm_setup"                             "swtpm-tools"              "swtpm-tools"
  add "command -v tpm2-abrmd"                              "tpm2-abrmd"               "tpm2-abrmd"
  add "ldconfig -p | grep -q libtss2-tcti-tabrmd"         "libtss2-tcti-tabrmd0"     "tpm2-abrmd"
  add "ldconfig -p | grep -q libtss2-tcti-swtpm"          "libtss2-tcti-swtpm0t64/libtss2-tcti-swtpm0" "tpm2-tss"
  add "command -v dbus-daemon"                             "dbus-daemon/dbus"         "dbus-daemon"
fi

pkg_available() {  # apt: gibt es das Paket in den Quellen?
  case $PM in
    apt) apt-cache show "$1" >/dev/null 2>&1 ;;
    dnf) dnf -q info "$1" >/dev/null 2>&1 ;;
  esac
}

step "$(t "Benötigte Software" "Required software")"
MISSING=()
for r in "${REQ[@]}"; do
  IFS=$'\t' read -r test apkg dpkg <<<"$r"
  [ $PM = apt ] && want=$apkg || want=$dpkg
  if bash -c "$test" >/dev/null 2>&1; then ok "${want%%/*}"
  else warn "$(t fehlt missing): ${want%%/*}"; MISSING+=("$want"); fi
done
# Duplikate entfernen (dnf: tpm2-abrmd deckt Dienst und TCTI ab)
mapfile -t MISSING < <(printf '%s\n' "${MISSING[@]+"${MISSING[@]}"}" | awk 'NF && !s[$0]++')

if [ $CHECK_ONLY = 1 ]; then
  [ ${#MISSING[@]} = 0 ] && ok "$(t "alles vorhanden" "everything present")" || echo "  $(t "würde installieren" "would install"): ${MISSING[*]}"
  exit 0
fi

if [ ${#MISSING[@]} -gt 0 ]; then
  if [ $PM = apt ]; then
    [ $DRY = 1 ] || run_root apt-get update -qq >/dev/null
  elif [ $EL = 1 ] && [ $WANT_SWTPM = 1 ]; then
    warn "$(t "RHEL-Familie: swtpm und tpm2-abrmd liegen je nach Version in AppStream oder EPEL" "RHEL family: swtpm and tpm2-abrmd are in AppStream or EPEL depending on the version")"
  fi
  PKGS=()
  for want in "${MISSING[@]}"; do
    chosen=""
    IFS='/' read -r -a alts <<<"$want"
    for p in "${alts[@]}"; do
      if [ $DRY = 1 ] || pkg_available "$p"; then chosen=$p; break; fi
    done
    if [ -z "$chosen" ]; then
      if [ $EL = 1 ]; then die "$(t "Paket nicht gefunden: $want – EPEL aktivieren: sudo dnf install epel-release" "package not found: $want – enable EPEL: sudo dnf install epel-release")"; fi
      die "$(t "Paket nicht gefunden: $want" "package not found: $want")"
    fi
    PKGS+=("$chosen")
  done
  step "$(t "Installiere" "Installing"): ${PKGS[*]}"
  confirm "$(t "Diese Pakete jetzt installieren?" "Install these packages now?")" || die "$(t abgebrochen aborted)"
  PLOG=$(mktemp)
  if [ $PM = apt ]; then inst=(env DEBIAN_FRONTEND=noninteractive apt-get install -y "${PKGS[@]}")
  else inst=(dnf install -y "${PKGS[@]}"); fi
  if [ $DRY = 1 ]; then run_root "${inst[@]}"
  elif ! run_root "${inst[@]}" >"$PLOG" 2>&1; then tail -n 15 "$PLOG"; die "$(t "Installation fehlgeschlagen, Protokoll:" "installation failed, log:") $PLOG"; fi
  # Nachkontrolle: ist jetzt alles da?
  for r in "${REQ[@]}"; do IFS=$'\t' read -r test apkg dpkg <<<"$r"
    [ $DRY = 1 ] || bash -c "$test" >/dev/null 2>&1 || die "$(t "fehlt nach der Installation noch" "still missing after installation"): ${apkg%%/*}"; done
  rm -f "$PLOG"; ok "$(t "Pakete installiert" "packages installed")"
fi

if [ "$ROLE" != server ] && command -v tpm2_sign >/dev/null; then
  TV=$(tpm2_sign --version 2>&1 | sed -n 's/.*version="\([0-9]*\.[0-9]*\).*/\1/p')
  if [ -n "$TV" ] && [ "$(printf '%s\n5.5\n' "$TV" | sort -V | head -1)" != 5.5 ]; then
    warn "$(t "tpm2-tools $TV: Das Schlüsselgeheimnis steht beim Signieren kurz in der Prozessliste (ab 5.5 nicht mehr). Für das Lab in Ordnung, für die Härtung nicht." "tpm2-tools $TV: the key secret is briefly visible in the process list while signing (not from 5.5 on). Fine for the lab, not for hardening.")"
  fi
fi

# Systemweiter abrmd würde mit dem Kernel-Resource-Manager konkurrieren
if [ "$ROLE" != server ] && command -v systemctl >/dev/null && systemctl is-enabled tpm2-abrmd.service >/dev/null 2>&1; then
  step "$(t "Systemweiten tpm2-abrmd abschalten (das Lab nutzt /dev/tpmrm0 direkt)" "Disabling system-wide tpm2-abrmd (the lab uses /dev/tpmrm0 directly)")"
  run_root systemctl disable --now tpm2-abrmd.service >/dev/null 2>&1 || true
fi

# ------------------------------------------------------------ TPM-Zugriff ----
RELOGIN=0
if [ "$ROLE" != server ] && [ $HAVE_TPM = 1 ]; then
  step "$(t "Zugriff auf /dev/tpmrm0" "Access to /dev/tpmrm0")"
  GRP=$(stat -c %G /dev/tpmrm0)
  if [ "$GRP" != tss ]; then
    warn "$(t "/dev/tpmrm0 gehört Gruppe '$GRP' – lege udev-Regel für tss an" "/dev/tpmrm0 belongs to group '$GRP' – creating a udev rule for tss")"
    getent group tss >/dev/null || run_root groupadd --system tss
    if [ $DRY = 1 ]; then echo "    [$(t trockenlauf dry-run)] /etc/udev/rules.d/60-keyleash-tpm.rules"
    else echo 'KERNEL=="tpmrm[0-9]*", TAG+="systemd", MODE="0660", GROUP="tss"' | run_root tee /etc/udev/rules.d/60-keyleash-tpm.rules >/dev/null; fi
    run_root udevadm control --reload; run_root udevadm trigger --name-match=tpmrm0
  fi
  if id -nG "$USR" | tr ' ' '\n' | grep -qx tss; then ok "$(t "$USR ist in Gruppe tss" "$USR is in group tss")"
  else run_root usermod -aG tss "$USR"; RELOGIN=1; ok "$(t "$USR zur Gruppe tss hinzugefügt" "$USR added to group tss")"; fi
fi

# ---------------------------------------------------------------- Dateien ----
step "$(t "Lab-Dateien nach" "Lab files to") $DEST"
FRESH=1; [ -f "$DEST/keyleash.env" ] && FRESH=0
SELF="${BASH_SOURCE[0]}"
LINE=$(awk '/^__KEYLEASH_PAYLOAD__$/{print NR+1; exit 0}' "$SELF")
[ -n "$LINE" ] || die "$(t "Installationsdatei beschädigt (kein Inhalt)" "installer damaged (no payload)")"
SUM=$(tail -n +"$LINE" "$SELF" | sha256sum | cut -d' ' -f1)
[ "$SUM" = "$PAYLOAD_SHA256" ] || die "$(t "Prüfsumme stimmt nicht – Datei beschädigt oder verändert" "checksum mismatch – file damaged or modified")"
ok "$(t "Prüfsumme in Ordnung" "checksum OK") (sha256 ${SUM:0:16}…)"

if [ $DRY = 1 ]; then echo "    [$(t trockenlauf dry-run)] $(t entpacken unpack) → $DEST"; else
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  tail -n +"$LINE" "$SELF" | tar xzmf - -C "$TMP"   # -m: Zeitstempel = jetzt (VM-Uhren gehen oft falsch)
  SRC="$TMP/keyleash-lab"
  if [ -d "$DEST" ]; then
    BK="$DEST.sicherung-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar czf "$BK" --exclude=state -C "$(dirname "$DEST")" "$(basename "$DEST")"
    ok "$(t "vorhandenes Lab gesichert (ohne state/)" "existing lab backed up (without state/)"): $BK"
    # eigene Einstellungen behalten
    for keep in keyleash.env keyleash.mail.env; do
      if [ -f "$DEST/$keep" ] && [ -f "$SRC/$keep" ]; then
        if ! cmp -s "$DEST/$keep" "$SRC/$keep"; then cp "$SRC/$keep" "$DEST/$keep.neu"
          warn "$(t "$keep behalten, neue Vorlage: $keep.neu" "$keep kept, new template: $keep.neu")"; fi
        rm -f "$SRC/$keep"
      fi
    done
  fi
  mkdir -p "$DEST"
  cp -a "$SRC/." "$DEST/"
  # Ausführrechte gehen beim Kopieren über andere Rechner oft verloren
  find "$DEST" -path "$DEST/state" -prune -o -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod +x {} +
  if [ "$(id -u)" = 0 ] && [ "$USR" != root ]; then
    chown -R "$USR": "$DEST"; [ -n "${BK:-}" ] && chown "$USR": "$BK"
  fi
  ok "$(t "installiert, state/ unverändert" "installed, state/ untouched")"
fi

# ------------------------------------------------------------ keyleash.env ----
setenv() {  # setenv KEY VALUE  – nur in frisch installierter Datei oder ausdrücklich gewünscht
  local f="$DEST/keyleash.env"
  [ $DRY = 1 ] && { echo "    [$(t trockenlauf dry-run)] $1=$2"; return; }
  if grep -q "^$1=" "$f"; then sed -i "s#^$1=[^ ]*#$1=$2#" "$f"; else echo "$1=$2" >> "$f"; fi
  ok "$1=$2"
}
step "$(t Einstellungen Settings) (keyleash.env)"
# Vorhandene Einstellungen bleiben; geändert wird nur, was neu ist oder ausdrücklich angegeben wurde
{ [ $FRESH = 1 ] || [ $LANG_GIVEN = 1 ]; } && setenv KEYLEASH_LANG "$LANG_SEL"
if [ "$ROLE" != server ] && { [ $FRESH = 1 ] || [ $SWTPM_GIVEN = 1 ]; }; then
  if [ $HAVE_TPM = 1 ]; then setenv KEYLEASH_TPM hw; elif [ $WANT_SWTPM = 1 ]; then setenv KEYLEASH_TPM swtpm; fi
fi
[ $FRESH = 0 ] && ok "$(t "vorhandene keyleash.env beibehalten" "existing keyleash.env kept")"
[ -n "$SERVER_URL" ] && setenv KEYLEASH_SERVER "$SERVER_URL"
[ -n "$LISTEN" ] && setenv KEYLEASH_LISTEN "$LISTEN"
if [ -n "$LISTEN" ] && [ "${LISTEN%%:*}" != 127.0.0.1 ]; then
  warn "$(t "Der Lab-Server spricht HTTP ohne TLS. Nur in einem vertrauenswürdigen Netz betreiben; erlaubte Netze: KEYLEASH_ALLOWED_CIDRS." "The lab server speaks HTTP without TLS. Run it on a trusted network only; allowed networks: KEYLEASH_ALLOWED_CIDRS.")"
fi

# ------------------------------------------------------------------ Test ----
step "$(t "Kurztest" "Quick test")"
if [ $DRY = 1 ]; then echo "    [$(t trockenlauf dry-run)] tests/test_policy.sh"
elif [ "$ROLE" = server ]; then
  run_user python3 "$DEST/server/authz_server.py" --help >/dev/null && ok "$(t "Server startbar" "server starts")"
elif [ $WANT_SWTPM = 1 ] && [ $HAVE_TPM = 0 ]; then
  ( cd "$DEST" && { [ -S state/swtpm/dbus.sock ] && [ -f state/swtpm/swtpm.pid ] && kill -0 "$(cat state/swtpm/swtpm.pid)" 2>/dev/null \
      || run_user env KEYLEASH_TPM=swtpm bash tools/swtpm-start.sh >/dev/null; } && \
    run_user env KEYLEASH_TPM=swtpm bash tests/test_policy.sh ) && ok "$(t "Policy-Berechnung stimmt mit dem TPM überein" "policy computation matches the TPM")" \
    || warn "$(t "Kurztest fehlgeschlagen – Details: cd $DEST && tests/test_policy.sh" "quick test failed – details: cd $DEST && tests/test_policy.sh")"
elif [ $RELOGIN = 1 ]; then
  warn "$(t "Test nach dem Neuanmelden (Gruppe tss): cd $DEST && tests/test_policy.sh" "test after logging in again (group tss): cd $DEST && tests/test_policy.sh")"
elif [ $HAVE_TPM = 1 ]; then
  ( cd "$DEST" && run_user bash tests/test_policy.sh ) && ok "$(t "Policy-Berechnung stimmt mit dem TPM überein" "policy computation matches the TPM")" \
    || warn "$(t "Kurztest fehlgeschlagen – Details: cd $DEST && tests/test_policy.sh" "quick test failed – details: cd $DEST && tests/test_policy.sh")"
fi

# ----------------------------------------------------------------- Weiter ----
step "$(t Fertig Done)"
case $ROLE in
  lab)    echo "  cd $DEST && demos/alle.sh" ;;
  agent)  echo "  cd $DEST && demos/10-provisionieren.sh   ($(t "Server" "server"): $SERVER_URL)" ;;
  server) echo "  cd $DEST && tools/server.sh start"
          echo "  $(t "Optional, Schlüssel ins NetHSM:" "Optional, keys into a NetHSM:") python3 tools/nethsm-setup.py import --url https://NETHSM:8443" ;;
esac
[ $RELOGIN = 1 ] && echo "  ${Y}$(t "Vorher einmal ab- und wieder anmelden (oder: newgrp tss)." "Log out and in once first (or: newgrp tss).")${N}"
[ $WANT_SWTPM = 1 ] && [ $HAVE_TPM = 0 ] && echo "  $(t "Software-TPM nach Neustart starten:" "Start the software TPM after a reboot:") tools/swtpm-start.sh"
exit 0
__KEYLEASH_PAYLOAD__
