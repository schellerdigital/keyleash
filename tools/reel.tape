# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# keyleash – Video-Aufnahme mit vhs (https://github.com/charmbracelet/vhs)
# Aufruf aus dem Lab-Verzeichnis:   vhs tools/reel.tape
# Ergebnis: keyleash-reel-en.mp4
# Mit NetHSM (KEYLEASH_KEYSTORE=nethsm): vorher einmal "demos/reel.sh prep" im Terminal ausführen
# (fragt das NetHSM-Administrator-Passwort für den Schlüssel der Cloud-VM; danach nicht mehr).
# Deutsch: Output in keyleash-reel-de.mp4 umbenennen, KEYLEASH_LANG auf "de", FontSize 22 (längere Zeilen)
#
# Recording with vhs. Run from the lab directory: vhs tools/reel.tape

Output keyleash-reel-en.mp4

Set Shell "bash"
Set FontSize 24
Set Width 1280
Set Height 620
Set Padding 28
Set TypingSpeed 35ms
Set Framerate 30
Set WindowBar Colorful
Set BorderRadius 8

Env KEYLEASH_LANG "en"
Env PS1 "$ "

# Vorbereitung unsichtbar: eigener Server und Zustand für die Aufnahme
Hide
# Schlägt die Vorbereitung fehl, beendet sich die Shell und vhs bricht ohne Video ab
Type "demos/reel.sh clean >/dev/null; demos/reel.sh prep >/tmp/keyleash-reel-prep.log 2>&1 || exit; clear"
Enter
Wait@120s /\$\s*$/
Show

Type "# keyleash: machine keys that only work with a short-lived ticket"
Sleep 400ms
Enter
Sleep 2s

Type "demos/reel.sh 1"
Enter
Wait@30s /\$\s*$/
Sleep 4s
Hide
Type "clear"
Enter
Show

Type "demos/reel.sh 2"
Enter
Wait@30s /\$\s*$/
Sleep 4s
Hide
Type "clear"
Enter
Show

# Szene 3 wartet 8 s auf den Ablauf – diese Zeit wird nicht aufgezeichnet
Type "demos/reel.sh 3"
Enter
Wait+Screen@30s /later/
Sleep 2s
Hide
Wait@30s /\$\s*$/
Show
Sleep 5s
Hide
Type "clear"
Enter
Show

Type "demos/reel.sh 4"
Enter
Wait@30s /\$\s*$/
Sleep 5s
Hide
Type "clear"
Enter
Show

Type "demos/reel.sh 5"
Enter
Wait@30s /\$\s*$/
Sleep 5s
Hide
Type "clear"
Enter
Show

# Szene 6 signiert zwölfmal – die Wartezeit wird nicht aufgezeichnet
Type "demos/reel.sh 6"
Enter
Hide
Wait@90s /\$\s*$/
Show
Sleep 6s
Hide
Type "clear"
Enter
Show

Type "demos/reel.sh 7"
Enter
Wait@60s /\$\s*$/
Sleep 6s
Hide
Type "clear"
Enter
Show

Type "demos/reel.sh siem"
Enter
Wait@30s /\$\s*$/
Sleep 4s

Type "# keyleash.de"
Sleep 3s

Hide
Type "demos/reel.sh clean >/dev/null"
Enter
Wait@30s /\$\s*$/
