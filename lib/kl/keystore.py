# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""Schlüsselablage des Autorisierungsservers: Datei (Lab-Standard) oder Nitrokey NetHSM.

Ticket-Signaturschlüssel und CA-Schlüssel sind die Vertrauensanker von keyleash.
Wer sie hat, stellt sich beliebige Tickets und Zertifikate aus. Im NetHSM
verlassen sie die Hardware nicht; der Server schickt nur noch Prüfsummen zum
Signieren. Jede Signatur des NetHSM wird vor der Verwendung gegen den
öffentlichen Schlüssel geprüft.

  KEYLEASH_KEYSTORE=file|nethsm
  KEYLEASH_NETHSM_URL=https://nethsm.example:8443   (ohne /api/v1)
  KEYLEASH_NETHSM_USER=keyleash                      (Rolle Operator)
  KEYLEASH_NETHSM_PASS_FILE=state/server/nethsm.pass (Modus 600, nie in keyleash.env)
  KEYLEASH_NETHSM_CA=/pfad/zu/nethsm-ca.pem          (TLS-Zertifikat des NetHSM)
  KEYLEASH_NETHSM_INSECURE=1                         (nur Lab: TLS nicht prüfen)
  KEYLEASH_NETHSM_AUTHZ_KEY=keyleashauthz, KEYLEASH_NETHSM_CA_KEY=keyleashca
"""
import base64
import hashlib
import json
import os
import ssl
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from kl.common import cfg

# DER-Präfix von DigestInfo für SHA-256 (RFC 8017, 9.2): NetHSM-Modus PKCS1 erwartet DigestInfo
DIGESTINFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


class NetHSMError(RuntimeError):
    pass


class NetHSM:
    def __init__(self, url=None, user=None, passphrase=None):
        self.base = (url or cfg("KEYLEASH_NETHSM_URL", "")).rstrip("/") + "/api/v1"
        user = user or cfg("KEYLEASH_NETHSM_USER", "keyleash")
        if passphrase is None:
            pf = cfg("KEYLEASH_NETHSM_PASS_FILE")
            if not pf or not os.path.exists(pf):
                raise NetHSMError("KEYLEASH_NETHSM_PASS_FILE fehlt / missing")
            passphrase = open(pf).read().strip()
        self.auth = "Basic " + base64.b64encode(f"{user}:{passphrase}".encode()).decode()
        if cfg("KEYLEASH_NETHSM_INSECURE") == "1":
            self.ctx = ssl._create_unverified_context()
        else:
            self.ctx = ssl.create_default_context(cafile=cfg("KEYLEASH_NETHSM_CA") or None)

    def call(self, method, path, body=None, raw=False, auth=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Authorization": auth or self.auth,
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=10) as r:
                d = r.read()
                return d if raw else (json.loads(d) if d else None)
        except urllib.error.HTTPError as e:
            raise NetHSMError(f"NetHSM {method} {path}: {e.code} {e.read()[:200].decode(errors='replace')}")
        except urllib.error.URLError as e:
            raise NetHSMError(f"NetHSM {self.base}: {e.reason}")


class NetHSMRSAKey(rsa.RSAPrivateKey):
    """RSA-Schlüssel im NetHSM. Genügt der Schnittstelle von cryptography für sign(),
    damit Zertifikate und Tickets ohne Sonderweg signiert werden können."""

    def __init__(self, hsm: NetHSM, key_id: str):
        self.hsm, self.key_id = hsm, key_id
        pem = hsm.call("GET", f"/keys/{key_id}/public.pem", raw=True)
        self._pub = serialization.load_pem_public_key(pem)

    def sign(self, data, pad, algorithm):
        if not isinstance(pad, padding.PKCS1v15):
            raise NotImplementedError("nur PKCS#1 v1.5")
        if isinstance(algorithm, utils.Prehashed):
            digest = data
        else:
            if not isinstance(algorithm, hashes.SHA256):
                raise NotImplementedError("nur SHA-256")
            digest = hashlib.sha256(data).digest()
        r = self.hsm.call("POST", f"/keys/{self.key_id}/sign",
                          {"mode": "PKCS1", "message": base64.b64encode(DIGESTINFO_SHA256 + digest).decode()})
        sig = base64.b64decode(r["signature"])
        # Nie ungeprüft verwenden: Signatur gegen den öffentlichen Schlüssel prüfen
        self._pub.verify(sig, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return sig

    def public_key(self):
        return self._pub

    @property
    def key_size(self):
        return self._pub.key_size

    def decrypt(self, *a):
        raise NotImplementedError

    def private_numbers(self):
        raise NotImplementedError("Schlüssel verlässt das NetHSM nicht")

    def private_bytes(self, *a):
        raise NotImplementedError("Schlüssel verlässt das NetHSM nicht")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


def server_keys(d, generate_file_key):
    """Liefert (authz, ca) als private Schlüssel mit sign() – aus Dateien oder dem NetHSM."""
    if cfg("KEYLEASH_KEYSTORE", "file") == "nethsm":
        hsm = NetHSM()
        return (NetHSMRSAKey(hsm, cfg("KEYLEASH_NETHSM_AUTHZ_KEY", "keyleashauthz")),
                NetHSMRSAKey(hsm, cfg("KEYLEASH_NETHSM_CA_KEY", "keyleashca")))
    return generate_file_key("authz_key.pem"), generate_file_key("ca_key.pem")
