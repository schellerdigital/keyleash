#!/usr/bin/env python3
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""Freigabe-Werkzeug für das zweite System (Vier-Augen-Prinzip).

Läuft dort, wo der private Freigabeschlüssel liegt – im Lab simuliert als
eigener Ordner state/approver/. Es braucht kein TPM: Es prüft die Datei
SELBST (eigene Kopie, eigener Hash) und signiert dann eine Freigabe, die
das TPM des signierenden Systems per PolicySigned an genau diesen
Schlüssel und genau diesen Daten-Hash bindet.

  approve.py init ZWECK                       Freigabeschlüssel erzeugen
  approve.py approve ANFRAGE --file DATEI     Datei prüfen und freigeben
              [-o FREIGABE] [--yes]
"""
import argparse
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

from kl import tpmstruct as ts  # noqa: E402
from kl.common import bad, cfg, info, ok, state_dir, write  # noqa: E402
from kl.i18n import T  # noqa: E402


def adir():
    return cfg("KEYLEASH_APPROVER_DIR") or state_dir("approver")


def init(args):
    d = adir()
    kp = os.path.join(d, f"{args.purpose}_key.pem")
    if os.path.exists(kp):
        info(T(f"Freigabeschlüssel für '{args.purpose}' existiert bereits: {kp}", f"Approval key for '{args.purpose}' already exists: {kp}"))
        return
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    write(kp, k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))
    write(os.path.join(d, f"{args.purpose}_pub.pem"),
          k.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
    pub = os.path.join(d, args.purpose + '_pub.pem')
    ok(T(f"Freigabeschlüssel für '{args.purpose}' erzeugt; öffentlicher Teil: {pub}",
         f"Approval key for '{args.purpose}' created; public part: {pub}"))
    info(T("Im echten Betrieb gehört der private Teil auf ein anderes System oder ein Hardware-Token.", "In production the private part belongs on a separate system or a hardware token."))


def approve(args):
    req = json.load(open(args.request))
    purpose = req["purpose"]
    digest = ts.sha256(open(args.file, "rb").read())
    info(T(f"Anfrage: System {req['host']}, Zweck '{purpose}', Datei {req['file']}", f"Request: host {req['host']}, purpose '{purpose}', file {req['file']}"))
    info(T("eigener Hash der Datei: ", "own hash of the file: ") + digest.hex())
    if digest.hex() != req["digest"]:
        bad(T("Hash der eigenen Kopie weicht von der Anfrage ab – keine Freigabe", "Hash of our own copy differs from the request – no approval"))
        sys.exit(1)
    if not args.yes:
        if input(T("  Freigeben? [j/N] ", "  Approve? [y/N] ")).strip().lower() not in ("j", "ja", "y", "yes"):
            bad(T("nicht freigegeben", "not approved"))
            sys.exit(1)
    key = serialization.load_pem_private_key(
        open(os.path.join(adir(), f"{purpose}_key.pem"), "rb").read(), None)
    cphash = ts.sign_cphash(bytes.fromhex(req["key_name"]), digest)
    sig = key.sign(ts.approval_message(cphash, purpose), padding.PKCS1v15(), hashes.SHA256())
    out = args.out or args.request.rsplit(".", 1)[0] + T(".freigabe", ".approval")
    write(out, json.dumps({"purpose": purpose, "digest": digest.hex(), "key_name": req["key_name"],
                           "signature": base64.b64encode(sig).decode()}, indent=2), 0o644)
    ok(T(f"Freigabe erteilt: {out} (gilt nur für genau diese Datei und diesen Schlüssel)", f"Approval granted: {out} (valid only for exactly this file and this key)"))


def main():
    ap = argparse.ArgumentParser(description=T("keyleash Freigabe-Werkzeug (zweites System)", "keyleash approval tool (second system)"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init"); i.add_argument("purpose")
    a = sub.add_parser("approve"); a.add_argument("request"); a.add_argument("--file", required=True)
    a.add_argument("-o", "--out"); a.add_argument("--yes", action="store_true")
    args = ap.parse_args()
    {"init": init, "approve": approve}[args.cmd](args)


if __name__ == "__main__":
    main()
