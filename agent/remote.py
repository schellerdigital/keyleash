#!/usr/bin/env python3
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""Client des Signaturdienstes für Systeme ohne TPM (z. B. Cloud-VMs).

  remote.py init --host NAME                   Anmeldeschlüssel (Ed25519) erzeugen, öffentlichen Teil ausgeben
  remote.py sign DATEI --purpose ZWECK -o SIG  Datei vom keyleash-Server signieren lassen
            [--source IP]                      Absenderadresse (nur Demo: anderer Rechner)
            [--dir VERZ]                       anderes Client-Verzeichnis (z. B. gestohlene Kopie)

Auf dem Client liegt kein Signaturschlüssel, nur der Anmeldeschlüssel. Das Zertifikat zum
Signaturschlüssel schreibt sign neben die Signatur (SIG.crt). Exit 0 = signiert, 1 = abgelehnt.

Client of the signing service for systems without a TPM. No signing key on the client, only the
sign-in key. Exit 0 = signed, 1 = refused.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
import sys
import urllib.parse

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(LAB, "lib"))
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from kl.common import cfg, write  # noqa: E402
from kl.i18n import T  # noqa: E402
from kl.remote import request_message  # noqa: E402

DEFAULT_DIR = os.path.join(cfg("KEYLEASH_STATE", os.path.join(LAB, "state")), "remote-client")


def post(path, body, source=None):
    u = urllib.parse.urlparse(cfg("KEYLEASH_SERVER", "http://127.0.0.1:8740"))
    c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=20,
                                   source_address=(source, 0) if source else None)
    c.request("POST", path, json.dumps(body), {"Content-Type": "application/json"})
    r = c.getresponse()
    d = json.loads(r.read() or b"{}")
    return r.status, d


def init(a):
    os.makedirs(a.dir, mode=0o700, exist_ok=True)
    kp = os.path.join(a.dir, "client_key.pem")
    if not os.path.exists(kp):
        k = ed25519.Ed25519PrivateKey.generate()
        write(kp, k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()), 0o600)
    write(os.path.join(a.dir, "host"), a.host + "\n", 0o644)
    k = serialization.load_pem_private_key(open(kp, "rb").read(), None)
    pub = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    write(os.path.join(a.dir, "client_pub.pem"), pub, 0o644)
    print(pub.decode(), end="")


def sign(a):
    host = open(os.path.join(a.dir, "host")).read().strip()
    k = serialization.load_pem_private_key(open(os.path.join(a.dir, "client_key.pem"), "rb").read(), None)
    digest = hashlib.sha256(open(a.file, "rb").read()).hexdigest()
    st, d = post("/remote/nonce", {"host": host}, a.source)
    if st != 200:
        print(f"✘ {T('abgelehnt', 'refused')}: {d.get('error', st)}"); return 1
    nonce = d["nonce"]
    body = {"host": host, "purpose": a.purpose, "digest": digest, "nonce": nonce,
            "sig": base64.b64encode(k.sign(request_message(host, a.purpose, nonce, digest))).decode()}
    if a.save_request:
        write(a.save_request, json.dumps(body), 0o600)
    st, d = post("/remote/sign", body, a.source)
    if st != 200:
        print(f"✘ {T('abgelehnt', 'refused')}: {d.get('error', st)}"); return 1
    write(a.o, base64.b64decode(d["signature"]), 0o644)
    write(a.o + ".crt", d["cert"], 0o644)
    print(f"✔ {T('signiert', 'signed')}: {a.o} ({T('Zweck', 'purpose')} {a.purpose}, "
          f"{d['count']}/{d['limit']} {T('im Zeitfenster', 'in the time window')})")
    return 0


def replay(a):
    """Nur Demo: eine aufgezeichnete Anfrage noch einmal senden."""
    st, d = post("/remote/sign", json.load(open(a.request)), a.source)
    print(("✔ " + T("signiert", "signed")) if st == 200 else f"✘ {T('abgelehnt', 'refused')}: {d.get('error', st)}")
    return 0 if st == 200 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init"); i.add_argument("--host", required=True)
    s = sub.add_parser("sign"); s.add_argument("file"); s.add_argument("--purpose", required=True)
    s.add_argument("-o", required=True); s.add_argument("--save-request")
    r = sub.add_parser("replay"); r.add_argument("request")
    for x in (i, s, r):
        x.add_argument("--dir", default=DEFAULT_DIR)
        x.add_argument("--source", default=None)
    a = ap.parse_args()
    if a.cmd == "init":
        init(a)
    else:
        sys.exit(sign(a) if a.cmd == "sign" else replay(a))


if __name__ == "__main__":
    main()
