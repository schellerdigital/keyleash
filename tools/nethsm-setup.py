#!/usr/bin/env python3
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""Ticket- und CA-Schlüssel des keyleash-Servers in ein Nitrokey NetHSM verlegen.

  nethsm-setup.py provision --url URL            nur für ein frisches Test-NetHSM (Container)
  nethsm-setup.py import    --url URL [--insecure]
        importiert state/server/authz_key.pem und ca_key.pem (bestehende Maschinen bleiben gültig),
        legt den Operator-Benutzer an, schreibt die Einstellungen in keyleash.env und
        verschiebt die Schlüsseldateien nach state/server/vor-nethsm/ (danach sicher löschen!)
  nethsm-setup.py check                          Testsignatur über beide Schlüssel, Prüfung
  nethsm-setup.py unlock    --url URL            nach Neustart des NetHSM entsperren (Unlock-Passphrase)

Das Administrator-Passwort wird abgefragt (oder KEYLEASH_NETHSM_ADMIN_PASS) und nie gespeichert.
Der Server braucht nur den Operator: der darf signieren, aber keine Schlüssel exportieren oder ändern.
"""
import argparse
import base64
import datetime as dt
import getpass
import hashlib
import os
import secrets
import shutil
import sys

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(LAB, "lib"))
from cryptography.hazmat.primitives import serialization  # noqa: E402
from kl.common import cfg, write  # noqa: E402
from kl.i18n import T  # noqa: E402
from kl import keystore  # noqa: E402

SD = os.path.join(cfg("KEYLEASH_STATE", os.path.join(LAB, "state")), "server")
ENV = os.path.join(LAB, "keyleash.env")


def b64int(n):
    return base64.b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode()


def admin_hsm(a):
    pw = os.environ.get("KEYLEASH_NETHSM_ADMIN_PASS") or getpass.getpass(T("NetHSM-Administrator-Passwort: ", "NetHSM administrator passphrase: "))
    if a.insecure:
        os.environ["KEYLEASH_NETHSM_INSECURE"] = "1"
    return keystore.NetHSM(url=a.url, user="admin", passphrase=pw)


def setenv(key, val):
    lines = open(ENV).read().splitlines() if os.path.exists(ENV) else []
    out, done = [], False
    for l in lines:
        if l.startswith(key + "="):
            out.append(f"{key}={val}"); done = True
        else:
            out.append(l)
    if not done:
        out.append(f"{key}={val}")
    open(ENV, "w").write("\n".join(out) + "\n")
    print(f"  ✔ {key}={val}")


def provision(a):
    hsm = keystore.NetHSM(url=a.url, user="x", passphrase="x")
    if a.insecure:
        hsm.ctx = __import__("ssl")._create_unverified_context()
    state = hsm.call("GET", "/health/state")["state"]
    if state != "Unprovisioned":
        sys.exit(T(f"NetHSM ist bereits eingerichtet ({state})", f"NetHSM is already provisioned ({state})"))
    unlock = getpass.getpass("Unlock-Passphrase (min. 10): ")
    admin = getpass.getpass(T("Administrator-Passwort (min. 10): ", "Administrator passphrase (min. 10): "))
    hsm.call("POST", "/provision", {"unlockPassphrase": unlock, "adminPassphrase": admin,
                                    "systemTime": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    print("  ✔ " + T("provisioniert", "provisioned"))


def unlock(a):
    hsm = keystore.NetHSM(url=a.url, user="x", passphrase="x")
    if a.insecure or cfg("KEYLEASH_NETHSM_INSECURE") == "1":
        hsm.ctx = __import__("ssl")._create_unverified_context()
    state = hsm.call("GET", "/health/state")["state"]
    if state != "Locked":
        print("  · NetHSM: " + state); return
    hsm.call("POST", "/unlock", {"passphrase": getpass.getpass("Unlock-Passphrase: ")})
    print("  ✔ NetHSM: " + hsm.call("GET", "/health/state")["state"])


def do_import(a):
    hsm = admin_hsm(a)
    print("  NetHSM: " + hsm.call("GET", "/health/state")["state"])
    user = cfg("KEYLEASH_NETHSM_USER", "keyleash")
    pf = os.path.join(SD, "nethsm.pass")
    if not os.path.exists(pf):
        pw = secrets.token_urlsafe(24)
        hsm.call("PUT", f"/users/{user}", {"realName": "keyleash authz server", "role": "Operator", "passphrase": pw})
        write(pf, pw + "\n", 0o600)
        print("  ✔ " + T(f"Operator '{user}' angelegt, Passwort in {pf} (600)", f"operator '{user}' created, passphrase in {pf} (600)"))
    for kid, fname in ((cfg("KEYLEASH_NETHSM_AUTHZ_KEY", "keyleashauthz"), "authz_key.pem"),
                       (cfg("KEYLEASH_NETHSM_CA_KEY", "keyleashca"), "ca_key.pem")):
        p = os.path.join(SD, fname)
        if not os.path.exists(p):
            print("  · " + T(f"{fname} nicht vorhanden (schon importiert?)", f"{fname} not present (already imported?)")); continue
        priv = serialization.load_pem_private_key(open(p, "rb").read(), None)
        k = priv.private_numbers()
        try:   # Schlüssel schon im NetHSM (früherer Import)? Dann nur prüfen, ob er derselbe ist
            have = serialization.load_pem_public_key(hsm.call("GET", f"/keys/{kid}/public.pem", raw=True))
        except keystore.NetHSMError:
            have = None
        if have is not None:
            if have.public_numbers() == priv.public_key().public_numbers():
                print("  · " + T(f"'{kid}' ist schon im NetHSM, identisch mit {fname}", f"'{kid}' is already in the NetHSM, identical to {fname}"))
                continue
            sys.exit("  ✘ " + T(f"'{kid}' im NetHSM ist ein ANDERER Schlüssel als {fname}. Nichts geändert. "
                                f"Prüfen, welcher gilt (Maschinen wurden mit dem bisherigen provisioniert).",
                                f"'{kid}' in the NetHSM is a DIFFERENT key than {fname}. Nothing changed. "
                                f"Check which one is valid (machines were provisioned with the current one)."))
        hsm.call("PUT", f"/keys/{kid}", {"type": "RSA", "mechanisms": ["RSA_Signature_PKCS1"],
                                         "private": {"primeP": b64int(k.p), "primeQ": b64int(k.q),
                                                     "publicExponent": b64int(k.public_numbers.e)}})
        print("  ✔ " + T(f"{fname} → NetHSM-Schlüssel '{kid}'", f"{fname} → NetHSM key '{kid}'"))
    setenv("KEYLEASH_KEYSTORE", "nethsm")
    setenv("KEYLEASH_NETHSM_URL", a.url)
    setenv("KEYLEASH_NETHSM_USER", user)
    setenv("KEYLEASH_NETHSM_PASS_FILE", pf)
    if a.insecure:
        setenv("KEYLEASH_NETHSM_INSECURE", "1")
    for k, v in (("KEYLEASH_KEYSTORE", "nethsm"), ("KEYLEASH_NETHSM_URL", a.url), ("KEYLEASH_NETHSM_USER", user),
                 ("KEYLEASH_NETHSM_PASS_FILE", pf)):
        os.environ[k] = v
    if check(None):
        bk = os.path.join(SD, "vor-nethsm")
        os.makedirs(bk, mode=0o700, exist_ok=True)
        for fname in ("authz_key.pem", "ca_key.pem"):
            if os.path.exists(os.path.join(SD, fname)):
                shutil.move(os.path.join(SD, fname), os.path.join(bk, fname))
        print("  ! " + T(f"Schlüsseldateien nach {bk} verschoben. Offline sichern oder löschen: shred -u {bk}/*.pem",
                         f"key files moved to {bk}. Back them up offline or delete: shred -u {bk}/*.pem"))
        print("  → " + T("Server neu starten: tools/server.sh stop && tools/server.sh start",
                         "restart the server: tools/server.sh stop && tools/server.sh start"))


def check(_a):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    ok = True
    hsm = keystore.NetHSM()
    for name, kid in ((T("Ticket-Schlüssel", "ticket key"), cfg("KEYLEASH_NETHSM_AUTHZ_KEY", "keyleashauthz")),
                      ("CA", cfg("KEYLEASH_NETHSM_CA_KEY", "keyleashca"))):
        try:
            k = keystore.NetHSMRSAKey(hsm, kid)
            msg = b"keyleash check " + secrets.token_bytes(8)
            k.public_key().verify(k.sign(msg, padding.PKCS1v15(), hashes.SHA256()), msg, padding.PKCS1v15(), hashes.SHA256())
            fp = hashlib.sha256(k.public_key().public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:16]
            print(f"  ✔ {name} '{kid}': " + T("Signatur aus dem NetHSM geprüft", "NetHSM signature verified") + f" (SPKI {fp}…)")
        except Exception as e:
            ok = False
            print(f"  ✘ {name} '{kid}': {e}")
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["provision", "import", "check", "unlock"])
    ap.add_argument("--url", default=cfg("KEYLEASH_NETHSM_URL"))
    ap.add_argument("--insecure", action="store_true", help=T("TLS nicht prüfen (nur Lab)", "do not verify TLS (lab only)"))
    a = ap.parse_args()
    if a.cmd != "check" and not a.url:
        sys.exit("--url")
    if a.cmd == "provision":
        provision(a)
    elif a.cmd == "unlock":
        unlock(a)
    elif a.cmd == "import":
        do_import(a)
    else:
        sys.exit(0 if check(a) else 1)


if __name__ == "__main__":
    main()
