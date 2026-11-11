# keyleash Lab – Testumgebung für das Konzept „Souveräne Missbrauchserkennung für Maschinenidentitäten“

Proof of Concept (Konzept, Abschnitt „Pilot“, Schritte 1–2) auf einem Rechner:
TPM-gebundener Maschinenschlüssel, Autorisierungsserver mit befristeten Tickets,
Verwaltungs-CA, SIEM-Protokoll und Härtung Stufe 1. Alles Open Source:
tpm2-tools/tpm2-tss, OpenSSL, Python (stdlib + cryptography).

```
 gmkbox
 ┌─────────────────────────────────────────────────────────────┐
 │  agent/agent.py ──Quote+Nonce──▶ server/authz_server.py      │
 │        │        ◀──Ticket──────       │ CA · SIEM-Log         │
 │        ▼                              ▼                       │
 │   TPM 2.0 (/dev/tpmrm0)        state/server/siem.jsonl        │
 │   Schlüssel + Policy                                          │
 │        │ Signatur                                             │
 │        ▼                                                      │
 │  verify/verify.sh  (Gegenstelle: prüft nur Zertifikat + Sig.) │
 └─────────────────────────────────────────────────────────────┘
```

## Installation mit einer Datei

`keyleash-install.sh` enthält das ganze Lab, prüft die Voraussetzungen und installiert fehlende
Pakete (apt: Debian, Ubuntu, Mint; dnf: Fedora, RHEL, Rocky, AlmaLinux). Root-Rechte holt sie sich
nur für Pakete, Gruppe `tss` und udev-Regel über `sudo`.

```bash
bash keyleash-install.sh --pruefen          # nur zeigen, was fehlt
bash keyleash-install.sh                    # Lab auf dieser Maschine (Server + Agent)
bash keyleash-install.sh --swtpm            # zusätzlich Software-TPM (ohne TPM: wird angeboten)
bash keyleash-install.sh --rolle server --listen 0.0.0.0:8740
bash keyleash-install.sh --rolle agent --server http://10.0.0.5:8740
bash keyleash-install.sh --hilfe            # alle Optionen
```

Zielordner ist `~/keyleash-lab` (`--ziel` ändert das). Bei einer vorhandenen Installation sichert
sie den alten Stand als `.tar.gz`, lässt `state/`, `keyleash.env` und `keyleash.mail.env` unverändert
und legt eine neue Vorlage als `keyleash.env.neu` daneben. Der Inhalt ist per SHA-256 geprüft; die
Datei bricht ab, wenn er verändert wurde. Bauen: `tools/build-installer.sh` (→ `dist/`).
Getestet in Containern mit Ubuntu 24.04, Debian 12, Fedora 40 und Rocky Linux 9 (Software-TPM).
Mit tpm2-tools älter als 5.5 (Debian 12, RHEL 9) steht das Schlüsselgeheimnis beim Signieren kurz in der
Prozessliste; die Installation warnt dann. Für das Lab in Ordnung, für die Härtung Stufe 1 nicht.

## Vertrauensanker im NetHSM (optional)

Ticket-Signaturschlüssel und CA-Schlüssel des Servers liegen im Lab als Dateien in `state/server/`. Wer sie
hat, stellt sich beliebige Tickets und Zertifikate aus. Mit einem Nitrokey NetHSM verlassen sie die Hardware
nicht mehr: Der Server schickt nur noch Prüfsummen zum Signieren und prüft jede Antwort gegen den
öffentlichen Schlüssel, bevor er sie verwendet.

```bash
python3 tools/nethsm-setup.py import --url https://NETHSM:8443 [--insecure]   # Admin-Passwort wird abgefragt
tools/server.sh stop && tools/server.sh start
python3 tools/nethsm-setup.py check
```

`import` übernimmt die vorhandenen Schlüssel, damit alle provisionierten Maschinen gültig bleiben. Es legt
einen Benutzer mit der Rolle Operator an (darf signieren, nicht exportieren), speichert dessen Passwort in
`state/server/nethsm.pass` (600), setzt `KEYLEASH_KEYSTORE=nethsm` und die übrigen `KEYLEASH_NETHSM_*`
in `keyleash.env` und verschiebt die Schlüsseldateien nach `state/server/vor-nethsm/`. Diese danach
offline sichern oder mit `shred -u` löschen. `--insecure` nur für ein Test-NetHSM mit selbstsigniertem
Zertifikat; sonst `KEYLEASH_NETHSM_CA` auf dessen Zertifikat setzen. Getestet gegen die öffentliche
NetHSM-Demo von Nitrokey (Import, Tickets, Zertifikate für Zweckschlüssel, Demos 20 und 67).
Für ein frisches Test-NetHSM im Container: `python3 tools/nethsm-setup.py provision --url … --insecure`.

## Demo: geschützte Anwendung auf einer VM (labbox-1)

Ein Dashboard auf der VM zeigt Statistiken und Protokolle des keyleash-Servers. Die Daten bekommt es
nur mit seiner Maschinenidentität: Nonce holen, vom TPM der VM signieren lassen, Signatur und Zertifikat
an die Daten-Schnittstelle auf gmkbox schicken. Die Schnittstelle (`server/data_api.py`, Port 8741)
prüft nur Zertifikat und Signatur und weiß nichts von Tickets. Ob signiert werden darf, entscheidet das TPM.

```bash
bash tools/labbox-deploy.sh user@192.0.2.10   # einrichten (Passwort einmalig, dann SSH-Schlüssel)
bash tools/labbox-deploy.sh sperren               # in unter einer Minute: TPM signiert nicht, Dashboard rot
bash tools/labbox-deploy.sh entsperren            # in unter 30 s wieder grün
bash tools/labbox-deploy.sh status
```

Auf der VM: `keyleash-agent` (erneuert Tickets, TTL 30 s), `keyleash-dashboard` (Port 8080), ohne vTPM
zusätzlich `keyleash-swtpm`. Server und Schnittstelle lauschen dafür auf allen Adressen und sprechen HTTP
ohne TLS: nur im internen VM-Netz verwenden.

## Demo: Webserver ohne kopierbare Geheimnisse (WordPress)

Anlass: PHP2Shell (Okt. 2026), Codeausführung im PHP-Prozess. keyleash verhindert den Einbruch nicht,
aber der Angreifer findet nichts, was er mitnehmen kann. WordPress hat kein Datenbank-Passwort; es meldet
sich bei MariaDB mit einem **Kurzzeit-Zertifikat** an (Standard in der Demo 60 s). Der Agent erzeugt dafür
laufend einen frischen Software-Schlüssel und lässt den Antrag vom TPM-Maschinenschlüssel signieren. Das
TPM signiert nur mit gültigem Ticket, der Server stellt nur für nicht gesperrte Maschinen aus
(`/cert/nonce`, `/cert/short`). MariaDB lässt den Benutzer nur mit diesem Zertifikat herein
(`REQUIRE SUBJECT '/CN=HOST/OU=wpdb' AND ISSUER …`).

```bash
bash tools/webdemo.sh setup      # einmalig: MariaDB mit TLS, PHP, WordPress (sudo, Internet)
demos/85-webserver.sh            # kopieren, sperren, ablaufen lassen, entsperren (~90 s)
bash tools/webdemo.sh stop       # vor demos/alle.sh stoppen (eigener Agent erneuert Tickets)
bash tools/webdemo.sh remove     # Datenbank, MariaDB-Konfiguration und WordPress entfernen
```

Ablauf: Seite läuft → Angreifer kopiert Schlüssel und Zertifikat, kommt damit an die Datenbank und hält eine
Verbindung offen → Sperre → der **Sperr-Hook** (`KEYLEASH_REVOKE_HOOK`, von `setup` eingerichtet) sperrt das
Konto `wp` und beendet offene Verbindungen → WordPress zeigt „Database refused“, die gestohlene Kopie ist
wertlos → Entsperren, Seite nach höchstens 10 s wieder da. MariaDB prüft das Zertifikat nur beim
Verbindungsaufbau; ohne Hook bliebe eine offen gehaltene Verbindung bestehen, und die Sperre wirkte erst mit
Ablauf des letzten Zertifikats. Der Hook wird als `HOOK revoke|unrevoke HOST` aufgerufen und erscheint im
SIEM (`sperr_hook`). Grenzen: Solange der Angreifer im
Webserver sitzt, kommt er an alles, was die Datenbank WordPress gibt; die Salts in `wp-config.php` bleiben
gemeinsame Geheimnisse. Datenbank- und keyleash-Server brauchen eine übereinstimmende Uhr (NTP).
Agent-Befehl allgemein: `agent/agent.py shortcert NAME --lifetime S --loop` (Ergebnis unter
`state/agent/shortcert-NAME/current/`).

## Demo: Privilegierte Konten an Admin-Arbeitsplätze binden (SSH)

Admin-Zugänge sind das wertvollste Diebesgut. Der SSH-Server nimmt Admins nur mit einem **SSH-Zertifikat
für 2 Minuten** an (`KEYLEASH_ADMIN_CERT_LIFETIME`), das der keyleash-Server ausstellt – nur für einen
Arbeitsplatz mit gültigem TPM-Ticket, Prinzipal `keyleash-admin`, Schlüssel-ID = Hostname. Keine
`authorized_keys`, keine Passwörter: ein gestohlener oder eigener Schlüssel des Angreifers kommt nicht herein.

```bash
bash tools/admindemo.sh setup      # einmalig: OpenSSH, SSH-CA vom Server, sshd ohne root auf 127.0.0.1:2222
demos/86-admin-arbeitsplatz.sh     # anmelden, kopieren, sperren, entsperren (~40 s)
bash tools/admindemo.sh ssh        # selbst als Admin anmelden
bash tools/admindemo.sh remove
```

Ablauf: normaler Schlüssel abgewiesen → Admin meldet sich mit Kurzzeit-Zertifikat an und hält eine Sitzung
offen → Schadsoftware kopiert Schlüssel und Zertifikat, die Kopie funktioniert zunächst → Sperre → der
Sperr-Hook schreibt den Host in die Widerrufsliste (KRL) und beendet laufende Admin-Sitzungen (gemessen
0,4 s) → Kopie und neues Zertifikat abgewiesen → Entsperren: neues Zertifikat nach höchstens 10 s, die vor
der Sperre ausgestellten Zertifikate bleiben bis zu ihrem Ablauf widerrufen (`state/server/ssh-serials.tsv`).
Mehrere Hooks verteilt `tools/revoke-hooks.sh` (alle ausführbaren Dateien in `state/hooks.d/`). Grenzen: In
der Demo liegen SSH-Server und keyleash-Server auf einer Maschine; produktiv verteilt man KRL und
Sitzungsende an die Zielsysteme. Notzugang (Break-Glass) gehört getrennt davon – ein Offline-Schlüssel, dessen
Nutzung selbst Alarm auslöst.

## Demo: RDP nur über den keyleash-Tunnel (xrdp)

Dasselbe Prinzip für RDP, ohne Windows-Lizenz: xrdp lauscht auf **keinem Netzwerk-Port**, nur auf einem
lokalen Socket. Erreichbar ist es nur über das Admin-Gateway aus Demo 86, also nur mit einem
Kurzzeit-Zertifikat vom Arbeitsplatz: `tools/admindemo.sh tunnel` öffnet einen lokalen Port, jede Verbindung
darauf wird zu einer SSH-Sitzung, die per `socat` an den Socket durchreicht (das Gateway selbst erlaubt keine
Weiterleitungen, `DisableForwarding yes`). Bei einer Sperre trennt der Hook der Admin-Demo die Gateway-Sitzung,
und ein zweiter Hook meldet die RDP-Sitzung ab – gemessen beides nach 0,5 s. Ohne ihn bliebe sie nur
*getrennt* und ließe sich wieder aufnehmen.

```bash
bash tools/admindemo.sh setup && bash tools/rdpdemo.sh setup   # xrdp, xorgxrdp, Xvfb, FreeRDP (sudo)
demos/87-rdp.sh                                                # Tunnel, RDP, sperren, entsperren
bash tools/rdpdemo.sh remove
```

Hinweis: FreeRDP 3 folgt den Proxy-Variablen (`https_proxy`); die Demo startet den Client ohne sie.
`setup` legt den Benutzer `kl-rdp` mit Zufallspasswort an (`state/rdpdemo/pw`) und eine sudo-Regel, die nur
`pkill -KILL -u kl-rdp` erlaubt. Ein von `setup` neu installiertes System-xrdp wird abgeschaltet, weil es sonst
auf 3389 im Netz lauschen würde. Unter Windows entspricht der Socket einer Firewall-Regel „3389 nur vom
Gateway“, das Abmelden einem Hook mit `logoff` bzw. `Invoke-RDUserLogoff`. Getestet auf Ubuntu 24.04.

## Demo: Signaturdienst für Systeme ohne TPM (NetHSM)

Für Rechner ohne TPM, etwa Cloud-VMs ohne vTPM (Hetzner Cloud bietet keins): Der Signaturschlüssel liegt
**im NetHSM hinter dem keyleash-Server**, nie auf der VM. Die VM hat nur einen Anmeldeschlüssel (Ed25519) und
signiert damit jede Anfrage. Der Server prüft der Reihe nach: bekanntes System, Sperre, Absenderadresse,
Einmal-Nonce, Anmeldesignatur, erlaubter Zweck, Betriebsfenster und Menge – die zählt er **selbst**
(`KEYLEASH_REMOTE_LIMIT`, Standard 10 je Zweck im Fenster `KEYLEASH_SIG_WINDOW`). Erst dann signiert das NetHSM
(ECDSA P-256), mit einem Zertifikat der keyleash-CA je Zweck.

```bash
demos/88-signaturdienst.sh          # richtet beim ersten Lauf die VM „cloudvm“ ein (Zweck deploy)
python3 agent/remote.py init --host NAME            # auf der VM: Anmeldeschlüssel
python3 tools/remote-setup.py add NAME --purpose deploy --client-pub client_pub.pem --ip 203.0.113.7
python3 agent/remote.py sign DATEI --purpose deploy -o DATEI.sig
```

Gegenüber dem TPM: Die Sperre wirkt bei der nächsten Anfrage (kein Ticket, das ablaufen muss), und die
Zählung ist nicht fälschbar. Dafür hängt die Identität der VM an einem kopierbaren Anmeldeschlüssel; Absender-
bindung, Grenze und Sperre begrenzen den Schaden, verhindern aber nicht, dass ein Angreifer *auf* der VM bis
dahin signieren lässt. Mit `KEYLEASH_KEYSTORE=nethsm` legt `remote-setup.py` die Schlüssel im NetHSM an
(Administrator-Passwort wird abgefragt), sonst als Datei unter `state/server/remote/` (nur Lab).

## Schnellstart

```bash
cd ~/keyleash-lab
chmod +x *.sh */*.sh */*.py   # Ausführrechte gehen beim Kopieren verloren
sudo ./setup.sh                 # Pakete, Gruppe tss; danach ab- und wieder anmelden
demos/00-pruefen.sh             # TPM ansehen (nur lesend)
tools/server.sh vorne           # Server in einem eigenen Terminal, Entscheidungen live
demos/alle.sh                   # alle Szenarien im zweiten Terminal
```

Standard ist das **echte TPM** (`KEYLEASH_TPM=hw` in `keyleash.env`). Wenn du zuerst
gefahrlos ausprobieren willst: `sudo ./setup.sh --swtpm`, dann
`tools/swtpm-start.sh` und `KEYLEASH_TPM=swtpm demos/alle.sh`.

## Sprache / Language

Alle Ausgaben, Demos und SIEM-Ereignisse gibt es auf Deutsch und Englisch: `KEYLEASH_LANG=de` oder `en` in
`keyleash.env` (oder vor einem Befehl: `KEYLEASH_LANG=en demos/alle.sh`). Intern bleiben die Codes gleich;
übersetzt wird nur die Ausgabe. `tools/siem-report.py` wertet Logs beider Sprachen aus.
English documentation: `README.en.md`.

## Was im TPM passiert

| Element | Umsetzung | Konzept |
|---|---|---|
| Maschinenschlüssel | RSA-2048, `fixedtpm|fixedparent|sensitivedataorigin|sign`, **ohne** `userwithauth` | nicht exportierbar, nur über die Policy nutzbar |
| Schlüssel-Policy | `PolicyAuthorize(Authz-Server, policyRef=Host)` → `PolicyAuthValue` | nur mit signierter Freigabe; Prozessgeheimnis für Stufe 1 |
| Ticket (approved policy) | `PolicyCounterTimer(clock ≤ Ablauf)` → `PolicyCounterTimer(resetCount ≤ Grenze)` → `PolicyCounterTimer(safe = YES)` → `PolicyPCR(7,16)` | Laufzeit, Neustart-Grenze, gesicherte Uhr, Boot-Zustand |
| Ticket nach unsicherer Uhr | `PolicyCounterTimer(clock ≤ Ablauf)` → `PolicyCounterTimer(resetCount = aktuell)` → `PolicyPCR(7,16)` | gilt nur für diesen Systemstart, siehe „Die TPM-Uhr als Sensor“ |
| Provisionierung | EK → AK, `MakeCredential/ActivateCredential`, `TPM2_Certify` des Schlüssels durch den AK | Key Attestation gegenüber der CA |
| Erneuerung | `TPM2_Quote` über PCRs mit Server-Nonce; Uhr und resetCount kommen signiert aus dem Quote | Attestation + Anfrage |

Der Server braucht selbst kein TPM: Er berechnet Policy-Digests in Python
(`lib/kl/tpmstruct.py`). `tests/test_policy.sh` gleicht das gegen Trial-Sessions des TPM ab.

## Demos

| Skript | Zeigt | Erwartung |
|---|---|---|
| `00-pruefen.sh` | Werkzeuge, Hersteller, Uhr, PCRs, Lockout-Zähler | nur lesend |
| `10-provisionieren.sh` | Enrollment, Key Attestation, Zertifikat | `--neu` legt neu an |
| `20-signieren.sh` | Normalbetrieb + 3 Angriffe: Passwort statt Policy, gefälschtes Ticket, verlängertes Ticket | alle drei verweigert das TPM |
| `30-ablauf.sh [s]` | Ticket läuft ab, keine Erneuerung | TPM verweigert (PolicyCounterTimer) |
| `40-sperrung.sh [s]` | Admin sperrt; letztes Ticket gilt bis Ablauf | Erneuerung verweigert, dann TPM |
| `50-manipulation.sh` | PCR 16 erweitert (simulierte Manipulation) | Ticket sofort wirkungslos, Server alarmiert |
| `60-parallel.sh` | doppelte Anfrage, Replay | Alarm `anfrage_zu_haeufig_parallel`, `nonce_ungueltig_replay` |
| `70-neustart.sh` | Neustart-Grenze | auf Hardware mit echten Reboots, siehe unten |
| `72-uhr.sh` | TPM-Uhr als Sensor: Stromausfall, Snapshot/Klon, angehaltene VM (nur swtpm) | altes Ticket verweigert, Ticket nur für diesen Start; Alarm `tpm_zaehler_ruecklaeufig`; Warnung `tpm_uhr_abweichung` |
| `65-signaturen.sh [n]` | Signaturzählung: Lernphase, dann Ausreißer mit neuem Zweck | Warnung `neuer_signaturzweck`, Alarm `signaturvolumen_auffaellig` |
| `67-freigabe.sh` | Zweck `release` nur mit Freigabe eines zweiten Systems: ohne, gefälscht, regulär, wiederverwendet, manipulierter Build, Umgehung mit vollem Zugriff | nur der reguläre Weg signiert; das TPM prüft die Freigabe selbst |
| `75-herzschlag.sh` | Agent schweigt | Alarm `erneuerung_ausgeblieben` |
| `80-siem.sh` | Auswertung aller Entscheidungen | |
| `85-webserver.sh` | WordPress ohne Datenbank-Passwort: Kurzzeit-Zertifikat kopieren, sperren, ablaufen lassen | Kopie nur bis zum Ablauf nutzbar, danach Seite 503; nach `tools/webdemo.sh setup` |
| `86-admin-arbeitsplatz.sh` | Admin-SSH nur mit Kurzzeit-Zertifikat vom Arbeitsplatz: kopieren, sperren, entsperren | Sitzung nach 0,4 s beendet, Kopie abgewiesen; nach `tools/admindemo.sh setup` |
| `87-rdp.sh` | RDP nur über den Tunnel mit Kurzzeit-Zertifikat: anmelden, sperren, entsperren | Tunnel getrennt, Sitzung abgemeldet; nach `tools/rdpdemo.sh setup` |
| `88-signaturdienst.sh` | Signaturdienst ohne TPM: Schlüssel im NetHSM, Server prüft, zählt, sperrt | gestohlener Anmeldeschlüssel, Wiederholung, fremder Zweck abgewiesen; Sperre sofort; Grenze 10 |
| `90-haertung.sh` | Härtung Stufe 1 | nach `sudo harden/harden.sh` |

**Neustart-Grenze auf echter Hardware:** `demos/70-neustart.sh` sichert ein Ticket mit
1 h Laufzeit. Nach jedem Reboot `demos/70-neustart.sh pruefen`. Nach `KEYLEASH_MAX_RESETS`+1
Neustarts verweigert das TPM. Den Server währenddessen nicht laufen lassen (oder den Agent
nicht erneuern lassen), sonst gibt es frische Tickets.

Server-Verwaltung: `tools/server.sh hosts | revoke HOST | unrevoke HOST | rebaseline HOST | sigreset HOST | siem`.
`rebaseline` nach einem legitimen Firmware-/Secure-Boot-Update: der nächste Quote wird neue Referenz.
`sigreset` löscht die gelernte Signaturmenge eines Systems und gibt ein wegen Ausreißer gesperrtes System wieder frei.

## Signaturzählung

Agent und Signaturdienst zählen jede Signatur und melden Anzahl und Zwecke mit jeder Erneuerung. Der Server lernt den Median
der Signaturen pro Erneuerung und alarmiert, wenn eine Meldung `KEYLEASH_SIG_FACTOR` × Median (mindestens `KEYLEASH_SIG_MIN_ALARM`)
übersteigt, sowie bei einem bisher unbekannten Zweck. Mit `KEYLEASH_SIG_DENY=1` wird das Ticket dann verweigert. Ziel ist das
Signaturorakel: ein Angreifer, der die legitime Signaturumgebung benutzt.
Neue Zwecke zählt der Server zusätzlich über ein Zeitfenster (`KEYLEASH_SIG_WINDOW`, Standard 3600 s): Übersteigt
ihre Summe `KEYLEASH_SIG_MIN_ALARM`, gibt es einen Alarm, auch wenn sich die Serie auf mehrere Erneuerungen verteilt
(Befund vom 01.11.2026: 9 + 6 Signaturen blieben pro Erneuerung unter der Grenze). `sigreset` setzt auch die bekannten
Zwecke zurück. Zwecke `cert-…` zählt der Server selbst bei der Ausstellung und sind ausgenommen.
Grenze: Die Zählung meldet der Prozess selbst. Ein Angreifer mit Kontrolle über diesen Prozess kann zu niedrige Zahlen melden; belastbar
wird sie erst im geschützten Signaturdienst (Stufe 1 gegen gewöhnliche Prozesse, Stufe 2 auch gegen root).
Forschungspunkt: Command Audit des TPM (signierte Hash-Kette über jeden `TPM2_Sign`) könnte die Zählung auch ohne
geschützten Dienst fälschungssicher machen – noch nicht untersucht.

## Sicherheit auf dem echten TPM

- Das Lab legt **nichts dauerhaft im TPM** ab: keine persistenten Handles, keine NV-Indizes,
  kein `tpm2_clear`, keine Änderung an Owner-/Endorsement-Passwörtern. Schlüssel liegen als
  verschlüsselte Blobs in `state/` und sind nach `./teardown.sh` wertlos.
- Voraussetzung: Owner- und Endorsement-Hierarchie ohne Passwort (Auslieferungszustand unter Linux).
- **Dictionary-Attack-Schutz:** Die Demos machen keine Fehlversuche mit falschen Passwörtern
  (Angriff 1 scheitert an der fehlenden Policy, das zählt nicht). Aber: Hartes Ausschalten
  während TPM-Nutzung zählt das TPM als Verdachtsfall. `demos/00-pruefen.sh` zeigt den Zähler.
- PCR 16 ist das Debug-PCR, frei rücksetzbar, von keiner Systemkomponente genutzt. PCR 7
  (Secure Boot) wird nur gelesen.
- `KEYLEASH_TRACE=1` vor einem Befehl zeigt jeden tpm2-tools-Aufruf.

## Härtung Stufe 1

```bash
tools/server.sh start
sudo harden/harden.sh                  # Dienst keyleash-signer, eigene Identität <host>-signer
demos/90-haertung.sh
sudo harden/unharden.sh                # vollständiger Rückbau
```

| Maßnahme | Umsetzung |
|---|---|
| eigener Prozess, eigener Benutzer | systemd-Dienst `keyleash-signer`, Benutzer `keyleash`, Code root-eigen unter `/opt/keyleash` |
| Speicher abschotten | Geheimnis in `memfd_secret` (Fallback `mlock`+`MADV_DONTDUMP`), `PR_SET_DUMPABLE=0`, `LimitCORE=0` |
| TPM-Zugriff an den Prozess binden | `PolicyAuthValue`: ohne das Geheimnis nützt auch ein gültiges Ticket nichts; `DeviceAllow=/dev/tpmrm0` |
| Debugger sperren | AppArmor `deny ptrace`; optional `--ptrace-lock` (`ptrace_scope=3`, **bis Reboot unumkehrbar**) |
| Signaturentscheidung im geschützten Bereich | Dienst signiert nur Zwecke aus `KEYLEASH_SIGN_PURPOSES` (`/etc/keyleash/signer.env`) |
| systemd-Isolation | `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, leere Capabilities, `MemoryDenyWriteExecute` … |

Optional `--tss-entziehen`: Dein Benutzer verliert direkten TPM-Zugriff, nur der Dienst behält ihn.
Die Lab-Demos laufen dann nur noch per `sudo`.

## Freigabe durch ein zweites System

Für besonders wertvolle Zwecke (Standard: `release`) bekommt ein System einen eigenen Schlüssel
(`agent.py enroll-purpose release`). Dessen Tickets enthalten zusätzlich **PolicySigned**: Das TPM signiert
nur, wenn der Freigabeschlüssel des Zwecks eine Freigabe über den **cpHash genau dieses Signaturaufrufs**
erteilt hat, also über Schlüssel und Daten-Hash. Ablauf:

1. `agent.py request DATEI --purpose release -o ANFRAGE` auf dem signierenden System
2. `tools/approve.py approve ANFRAGE --file EIGENE_KOPIE` auf dem zweiten System: prüft seine eigene Kopie,
   gibt nur bei gleichem Hash frei (`tools/approve.py init release` erzeugt den Freigabeschlüssel)
3. `agent.py sign DATEI -o SIG --purpose release --approval FREIGABE`

Weil der Server die Bedingung über PolicyAuthorize in das Ticket schreibt, muss für neue Regeln nichts neu
provisioniert werden. Ohne Freigabeschlüssel kann auch root auf dem signierenden System nicht signieren.
Grenze: Der Freigebende schützt nur, wenn er unabhängig prüft (eigene Kopie, idealerweise reproduzierbarer
Build auf einem getrennten System). Im Lab liegt der Freigabeschlüssel in `state/approver/` auf demselben
Rechner; im Betrieb gehört er auf ein anderes System oder ein Hardware-Token.

## Die TPM-Uhr als Sensor

Die Laufzeit eines Tickets hängt an `clock`, nicht an `time`. `time` beginnt bei jedem Start neu,
`clock` ist persistent und lässt sich vom Owner nur vorstellen (das verkürzt ein Ticket nur). Das TPM
sichert `clock` aber nur alle `TPM2_PT_CLOCK_UPDATE` Millisekunden (`tpm2_getcap properties-fixed`).
Nach einem harten Stromausfall startet die Uhr beim gesicherten Stand und meldet `safe = NO`. Wer den
Strom wiederholt kappt, könnte so ein Ticket strecken.

**Gemessen auf gmkbox (Intel PTT, Hersteller INTC): `TPM2_PT_CLOCK_UPDATE = 0x400000`, also
4 194 304 ms ≈ 70 Minuten** (swtpm zum Vergleich: 4096 ms). Bei Standardwerten (Laufzeit 600 s,
`KEYLEASH_MAX_RESETS=2`) ließe sich ein Ticket ohne Gegenmaßnahme mit zwei gezielten Stromausfällen
um bis zu etwa 140 Minuten verlängern, also auf das rund 15-Fache, ohne dass der Server davon
erfährt. Folge der Gegenmaßnahme: Nach einem Stromausfall meldet das TPM bis zu 70 Minuten lang
`safe = NO`. In dieser Zeit gibt es nur Tickets für den laufenden Systemstart. Mit Serververbindung
merkt man nichts, ohne Verbindung übersteht in diesem Fenster kein Ticket einen Neustart.
Ordnungsgemäße Neustarts betreffen das nicht, weil das TPM die Uhr beim `TPM2_Shutdown` sichert.
Nebeneffekt: `tpm_uhr_unsicher` im SIEM zeigt harte Stromausfälle an, ordnungsgemäße Neustarts nicht.

Drei Gegenmaßnahmen sind umgesetzt:

1. **Ticket verlangt `safe = YES`** (`PolicyCounterTimer`, Offset 24, Gleichheit). Nach einem
   Stromausfall ist das alte Ticket sofort wirkungslos, das TPM prüft das selbst.
2. **Ticket nur für diesen Systemstart.** Meldet der Quote `safe = NO`, stellt der Server ein Ticket
   mit `resetCount = aktuell` statt `≤ Grenze` aus und ohne safe-Bedingung. Ohne Neustart kann die Uhr
   nicht zurückfallen, also lässt sich nichts strecken. SIEM: Warnung `tpm_uhr_unsicher`.
   `KEYLEASH_UNSAFE_CLOCK=deny` verweigert stattdessen.
3. **Erneuerungsstrom als Sensor.** Der Server vergleicht jeden Quote mit dem zuletzt gesehenen:
   - `resetCount` kleiner, oder gleicher Start und `clock` kleiner: zweiter, älterer TPM-Zustand
     (Snapshot, Klon, Replay). Alarm `tpm_zaehler_ruecklaeufig`, kein Ticket.
   - Neuer Start, `clock` unter dem zuletzt gesehenen Wert, aber `safe = YES`: Alarm
     `tpm_uhr_ruecksprung`, Ticket nur für diesen Start (`KEYLEASH_CLOCK_ROLLBACK=deny` verweigert).
     Nach der Spezifikation heißt `safe = YES`, dass nie ein größerer Wert gemeldet wurde. Ein
     geklonter Zustand, der mehrfach neu gestartet wird, sieht so aus. Im Test meldet aber auch swtpm
     nach `kill -9` so, darum standardmäßig kein harter Abbruch. Auf gmkbox mit echtem TPM prüfen.
   - Gleicher Start und gleicher `restartCount`: Die TPM-Uhr muss etwa so weit gelaufen sein wie die
     Serveruhr. Weicht sie mehr als `max(KEYLEASH_CLOCK_TOLERANCE, KEYLEASH_CLOCK_DRIFT × Abstand)`
     ab, meldet der Server `tpm_uhr_abweichung` (angehaltene VM, Snapshot, Migration). Nur Warnung,
     weil Live-Migration und manche Ruhezustände das auch auslösen.

Nebenbefund aus dem Test: Ein harter Stromausfall erhöht den Lockout-Zähler (DA) des TPM. Viele
Stromausfälle hintereinander sperren alle Schlüssel mit DA-Schutz, bis der Lockout-Berechtigte
zurücksetzt. Die Demo setzt ihn deshalb sofort zurück. Für den Betrieb gehört das ins Runbook.

## Stand der Technik und Abgrenzung

Ergebnis einer Recherche im Oktober 2026 (Bericht „Vergleichbare Lösungen zu keyleash“). Kurz:

- **Bekannt** sind die TPM-Bausteine (PolicyAuthorize, PolicyCounterTimer, PolicySigned mit Ablauf,
  TCG-Standard; *A Practical Guide to TPM 2.0*, 2015, Kap. 14, zeigt schon eine vom Admin signierte,
  an einen Boot-Zyklus gebundene Policy), Sperren durch Nicht-Erneuern (Topalovic/Boneh 2012, IETF
  STAR, noRevAvail), Schlüsselfreigabe nach Attestierung (AWS Nitro/NitroTPM, Azure SKR, Google
  Confidential Space, CoCo Trustee) und Allowlisting (fapolicyd, WDAC, ThreatLocker).
- **Marktübliches Muster:** Das TPM dient als Startanker beim Join (SPIRE `tpm_devid`, Teleport,
  Vault TPM-Auth, AWS IAM Roles Anywhere, Smallstep), danach liegen Credentials in Software oder der
  TPM-Schlüssel ist höchstens per Passwort geschützt. Ein Angreifer mit Root kann ihn dann als
  Signatur-Orakel benutzen. Den Ablauf setzt die Gegenseite durch, nicht das TPM (Entra PRT, DBSC).
- **Nicht gefunden:** die Kombination aus (a) Ablauf, den das TPM des Hosts selbst durchsetzt, also
  Sperre auf Schlüsselebene auch gegen Root mit Kopie des Key-Blobs, (b) Erneuerungs- und
  Signaturstrom als Sensor (resetCount, restartCount, clock, safe, parallele Instanzen, Signatur-
  menge und -zweck) und (c) zweckgebundene Zweitfreigabe aus einer anderen Vertrauensdomäne, die das
  TPM per `PolicySigned` mit cpHash selbst prüft. Konfidenz mittel, Recherche ohne Patentdatenbanken.
- **Einordnung:** keyleash ergänzt SPIRE, Vault und Keylime und passt zur Rolle „Credential Broker“
  in `draft-bdnr-rats-trustworthy-credentials`, erweitert um Widerruf durch Nicht-Erneuern. Neu ist
  das Systemdesign mit seiner Analyseschicht, nicht die TPM-Mechanik.
- **Patente:** Microsoft US11316693B2 (TPM-Policy mit Nutzungszähler) und US12452054B2 (Erneuerung
  eines Attestierungsartefakts innerhalb einer Boot-Session) vor jeder Veröffentlichung weiterer
  Details von einem Patentanwalt prüfen lassen. Eine Variante „höchstens n Signaturen pro Ticket“ per
  NV-Zähler käme dem ersten nahe und ist hier bewusst nicht umgesetzt. Das ist ein technischer
  Prior-Art-Scan, keine rechtliche Bewertung.
- **Aus der Recherche übernommen:** `clock` statt `time`, `safe = YES` bzw. festgeschriebener
  resetCount, Uhr-Signale (siehe oben), gestufte Reaktionen statt harter Sperre bei mehrdeutigen
  Signalen. Offen: PolicySigned mit Ablauf als Alternative für einzelne sensible Operationen,
  Lernphase für die Uhr-Toleranz, Abstufung nach Keylime-Vorschlag 46 für das IMA-Gate.

## Abweichungen vom Konzept und offene Punkte

1. **resetCount statt eigenem NV-Counter.** Das TPM zählt Neustarts selbst (`TPMS_CLOCK_INFO.resetCount`),
   und `PolicyCounterTimer` kann ihn direkt prüfen. Ein NV-Counter, den das Betriebssystem beim Boot
   hochzählt, ließe sich durch Weglassen des Hochzählens umgehen; resetCount nicht. Vorschlag für
   das Konzeptpapier: Abschnitt „Manipulation der Uhr“ entsprechend anpassen.
2. **Uhr nach Stromausfall:** Die TPM-Uhr wird nur periodisch gesichert und kann nach einem harten
   Abschalten zurückliegen. Tickets verlangen deshalb `safe = YES`, nach unsicherer Uhr gilt ein
   Ticket nur für den laufenden Systemstart. Details im Abschnitt „Die TPM-Uhr als Sensor“ (Demo 72).
3. **EK-Zertifikat wird nicht geprüft** (Lab: Vertrauen beim ersten Kontakt). Für den Pilot:
   `tpm2_getekcertificate` und Prüfung gegen die Hersteller-CA.
4. **tpm2_certify** setzt in tpm2-tools 5.x keine Nonce; die Frische kommt aus dem Quote.
5. **Python-Signaturpfad:** Das Geheimnis wird beim Aufruf von `tpm2_sign` kurz in Heap und Pipe
   kopiert. Für den Pilot: Signaturpfad in C/Rust direkt gegen tss2-esys.
6. **AppArmor-Profil** ist syntaktisch geprüft (AppArmor 4.0.1), aber nicht auf gmkbox erprobt.
   Wenn der Dienst nicht startet: `journalctl -u keyleash-signer`, `sudo aa-complain keyleash-signer`
   oder `sudo harden/harden.sh --ohne-apparmor`.
7. Nicht umgesetzt: Notfallmodus, IMA-Messung (braucht Boot-Parameter), Stufe 2 (TEE),
   Netzsegment-Erkennung mit mehreren Rechnern (Logik vorhanden, `KEYLEASH_ALLOWED_CIDRS`).

## Dateien

```
keyleash.env           zentrale Einstellungen (TPM-Modus, Sprache, Laufzeiten, PCRs, Fenster)
setup.sh / teardown.sh Einrichtung / Rückbau
server/authz_server.py Autorisierungsserver + CA + SIEM-Log
agent/agent.py         Agent: enroll | renew | loop | sign | status
lib/kl/                TPM-Strukturen, Policy-Berechnung, Hilfsfunktionen
verify/verify.sh       Gegenstelle (OpenSSL)
demos/                 Szenarien 00–90
harden/                Härtung Stufe 1 (Dienst, systemd-Unit, AppArmor)
lib/i18n.sh            Sprachumschaltung für Shell-Skripte (lib/kl/i18n.py für Python)
tools/                 server.sh, swtpm-start.sh, siem-report.py, approve.py, mail-setup.sh
tests/test_policy.sh   Python-Policy == TPM-Trial-Session
state/                 Laufzeitdaten (wird von teardown.sh gelöscht)
```

## E-Mail-Zugangsdaten (tools/mail-setup.sh)

Fragt SMTP-Server, Verschlüsselung (starttls/ssl/keine), Port, Benutzer, Passwort, Absender und Empfänger ab und schreibt sie nach `keyleash.mail.env` (Rechte 600). Die Datei steht in `.gitignore` und gehört nicht in einen Export; `keyleash.env` bleibt frei von Geheimnissen.

    tools/mail-setup.sh            # erfassen bzw. ändern, vorhandene Werte sind Vorgabe
    tools/mail-setup.sh --test     # Testmail senden
    tools/mail-setup.sh --zeigen   # Werte anzeigen, Passwort maskiert
    tools/mail-setup.sh --loeschen # Datei entfernen
    tools/mail-setup.sh --datei P  # andere Zieldatei

## Video (demos/reel.sh, tools/reel.tape)

Kurzfassung für die Website: sieben Szenen in gut eineinhalb Minuten (neu: 6 aufgeteilte Signaturserie, 7 Cloud-VM ohne TPM mit Signaturdienst/NetHSM), ohne TPM-Befehle, Fehlercodes, Pfade
oder Rechnernamen. Läuft getrennt vom Lab (Zustand `state/reel/`, Server auf Port 8742, System
`build-server-01`).

    demos/reel.sh all              # zum Üben im Terminal
    vhs tools/reel.tape            # Aufnahme -> keyleash-reel-en.mp4

`vhs` installieren (Linux Mint/Ubuntu):

    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
    echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
    sudo apt update && sudo apt install vhs ffmpeg ttyd

## Lizenz

Copyright (c) 2026 Christian Scheller.

keyleash ist freie Software: Du kannst es unter den Bedingungen der **GNU Affero General Public License**,
Version 3 oder (nach deiner Wahl) jeder späteren Version, weitergeben und verändern (`AGPL-3.0-or-later`,
Volltext in `LICENSE`). Die Software wird ohne jede Gewährleistung bereitgestellt.

Wer eine **veränderte** Fassung als Netzwerkdienst betreibt, etwa den keyleash-Server, muss deren Nutzern
den Quelltext der veränderten Fassung anbieten (AGPL, Abschnitt 13). Ausnahme: `webdemo/db.php` und
`webdemo/db-error.php` stehen als WordPress-Drop-ins unter GPL-2.0-or-later. Fremdsoftware: `NOTICE`.
Beiträge: `CONTRIBUTING.md`; Sicherheitslücken bitte vertraulich melden: `SECURITY.md`.
