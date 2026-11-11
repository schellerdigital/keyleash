#!/usr/bin/env python3
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""Client für den keyleash-Signaturdienst.

  signer-client.py status
  signer-client.py sign ZWECK DATEI -o SIGNATUR
"""
import argparse, base64, json, os, socket, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from kl.i18n import T  # noqa: E402

SOCK = os.environ.get("KEYLEASH_SIGNER_SOCK", "/run/keyleash/signer.sock")


def call(req):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    return json.loads(buf)


ap = argparse.ArgumentParser()
sub = ap.add_subparsers(dest="cmd", required=True)
sub.add_parser("status")
sg = sub.add_parser("sign"); sg.add_argument("purpose"); sg.add_argument("file"); sg.add_argument("-o", "--out", required=True)
a = ap.parse_args()
try:
    if a.cmd == "status":
        print(json.dumps(call({"cmd": "status"}), indent=2)); sys.exit(0)
    r = call({"purpose": a.purpose, "data": base64.b64encode(open(a.file, "rb").read()).decode()})
except PermissionError:
    print(T("  ✘ kein Zugriff auf den Signaturdienst (Gruppe keyleash-clients? neu anmelden)", "  ✘ no access to the signing service (group keyleash-clients? log in again)")); sys.exit(1)
except FileNotFoundError:
    print(T("  ✘ Signaturdienst läuft nicht (systemctl status keyleash-signer)", "  ✘ signing service is not running (systemctl status keyleash-signer)")); sys.exit(1)
if r.get("ok"):
    open(a.out, "wb").write(base64.b64decode(r["signature"]))
    print(T("  ✔ Signaturdienst hat signiert", "  ✔ signing service signed") + f" ({a.purpose})")
else:
    print(T("  ✘ Signaturdienst verweigert: ", "  ✘ signing service refused: ") + r['error']); sys.exit(1)
