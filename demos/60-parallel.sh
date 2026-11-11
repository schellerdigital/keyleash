#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Doppelte Anfragen und Replay
# Duplicate requests and replay
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
title "$(t 'Parallele Instanz / zu häufige Anfragen' 'Parallel instance / too frequent requests')"
pause_min_interval
$AG renew
step "$(t 'Sofort zweite Anfrage derselben Identität' 'Immediate second request from the same identity')"
expect_fail $AG renew

title "$(t 'Replay einer aufgezeichneten Anfrage' 'Replay of a recorded request')"
pause_min_interval
python3 - <<P
import json, os, sys
sys.path.insert(0, "$LAB/lib")
from kl import tpm; from kl.common import post, b64e
from kl.i18n import T
st = "$ST"; host = json.load(open(st + "/agent.json"))["host"]; pcrs = json.load(open(st + "/agent.json"))["pcrs"]
n = post("/ticket/nonce", {"host": host})["nonce"]
with tpm.Workdir() as w:
    m, s = tpm.quote(w, st, pcrs, n)
req = {"host": host, "nonce": n, "quote_attest": b64e(m), "quote_sig": b64e(s)}
r1 = post("/ticket", req)
print(T("  erste Anfrage :", "  first request:"), T("Ticket erhalten", "ticket received") if "error" not in r1 else r1["error"])
import time; time.sleep(float(os.environ.get("KEYLEASH_MIN_INTERVAL","5"))+1)
r2 = post("/ticket", req)
print(T("  Wiederholung  :", "  replay       :"),
      T("✘ Ticket erhalten (FEHLER)", "✘ ticket received (ERROR)") if "error" not in r2
      else T("✔ verweigert: ", "✔ refused: ") + r2["error"])
P
siem_tail 3
