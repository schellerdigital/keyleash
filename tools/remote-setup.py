#!/usr/bin/env python3
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""System ohne TPM beim Signaturdienst eintragen (Admin, auf dem keyleash-Server).

  remote-setup.py add HOST --purpose ZWECK [--purpose …] --client-pub DATEI [--ip ADRESSE]

Legt für jeden Zweck einen ECDSA-P-256-Schlüssel an – im NetHSM (KEYLEASH_KEYSTORE=nethsm; dafür
wird das Administrator-Passwort abgefragt oder aus KEYLEASH_NETHSM_ADMIN_PASS gelesen und nie
gespeichert) oder im Lab ohne NetHSM als Datei unter state/server/remote/ – und trägt das System mit
seinem Anmeldeschlüssel (Ed25519, erzeugt mit agent/remote.py init) und optional seiner festen
Absenderadresse beim Server ein. Der Server stellt je Zweck ein Zertifikat der keyleash-CA aus.

Register a system without a TPM with the signing service (admin, on the keyleash server).
"""
import argparse
import getpass
import json
import os
import sys
import urllib.request

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(LAB, "lib"))
from kl.common import cfg, state_dir  # noqa: E402
from kl.i18n import T  # noqa: E402
from kl import keystore, remote  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["add"])
    ap.add_argument("host")
    ap.add_argument("--purpose", action="append", required=True)
    ap.add_argument("--client-pub", required=True)
    ap.add_argument("--ip", default="")
    a = ap.parse_args()

    keys = remote.RemoteKeys(state_dir("server"))
    admin = None
    def exists(kid):
        try:
            keys.public(kid); return True
        except Exception:
            return False
    if keys.nethsm and not all(exists(remote.key_id(a.host, p)) for p in a.purpose):
        pw = os.environ.get("KEYLEASH_NETHSM_ADMIN_PASS") or getpass.getpass(
            T("NetHSM-Administrator-Passwort: ", "NetHSM administrator passphrase: "))
        admin = keystore.NetHSM(user="admin", passphrase=pw)
    for p in a.purpose:
        kid = remote.key_id(a.host, p)
        keys.create(kid, admin)
        where = T("im NetHSM", "in the NetHSM") if keys.nethsm else T("als Datei auf dem Server", "as a file on the server")
        print(f"  ✔ {T('Schlüssel', 'key')} '{p}' ({kid}) {where}")
    body = {"host": a.host, "purposes": a.purpose, "client_pub": open(a.client_pub).read(), "ip": a.ip}
    server = cfg("KEYLEASH_SERVER", "http://127.0.0.1:8740")
    req = urllib.request.Request(server + "/admin/remote-add", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        r = json.load(urllib.request.urlopen(req, timeout=20))
    except urllib.error.HTTPError as e:
        sys.exit(f"  ✘ {e.code} {e.read().decode(errors='replace')}")
    print(f"  ✔ {T('eingetragen', 'registered')}: {a.host}, {T('Zwecke', 'purposes')} {', '.join(sorted(r['purposes']))}"
          + (f", {T('nur von', 'only from')} {a.ip}" if a.ip else ""))


if __name__ == "__main__":
    main()
