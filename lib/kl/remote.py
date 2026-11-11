# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""Signaturdienst für Systeme ohne TPM (z. B. Cloud-VMs): Der Signaturschlüssel liegt beim
keyleash-Server – im NetHSM oder, im Lab ohne NetHSM, in einer Datei auf dem Server – und nie auf
dem Client. Der Client hat nur einen Anmeldeschlüssel (Ed25519), mit dem er jede Anfrage signiert.
Der Server prüft Anmeldung, Absenderadresse, Nonce, Zweck, Sperre und Menge, zählt selbst und
signiert erst dann.

Signing service for systems without a TPM (e.g. cloud VMs): the signing key stays with the keyleash
server – in the NetHSM or, in a lab without one, in a file on the server – and never on the client.

Schlüssel-IDs im NetHSM: "kr" + 20 Hex-Zeichen aus sha256(host|zweck) (NetHSM erlaubt nur [a-z0-9]).
"""
import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from kl.common import cfg, write
from kl import keystore


def key_id(host: str, purpose: str) -> str:
    return "kr" + hashlib.sha256(f"{host}|{purpose}".encode()).hexdigest()[:20]


def request_message(host: str, purpose: str, nonce: str, digest_hex: str) -> bytes:
    """Was der Client mit seinem Anmeldeschlüssel signiert."""
    return f"keyleash-remote|{host}|{purpose}|{nonce}|{digest_hex}".encode()


def _der(sig: bytes) -> bytes:
    """NetHSM liefert ECDSA je nach Version roh (r||s) oder DER – immer DER zurückgeben."""
    if len(sig) == 64 and sig[0] != 0x30:
        return utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    return sig


class RemoteKeys:
    def __init__(self, server_dir: str):
        self.dir = os.path.join(server_dir, "remote")
        self.nethsm = cfg("KEYLEASH_KEYSTORE", "file") == "nethsm"
        self._hsm = None
        self._pub = {}

    @property
    def where(self) -> str:
        return "nethsm" if self.nethsm else "file"

    def hsm(self):
        if self._hsm is None:
            self._hsm = keystore.NetHSM()
        return self._hsm

    def _file(self, kid):
        return os.path.join(self.dir, kid + ".pem")

    # Anlegen: im NetHSM nur mit Administrator-Rechten (Werkzeug tools/remote-setup.py)
    def create(self, kid: str, admin_hsm=None):
        if self.nethsm:
            hsm = admin_hsm or self.hsm()
            try:
                hsm.call("GET", f"/keys/{kid}")
                return self.public(kid)          # gibt es schon
            except keystore.NetHSMError:
                pass
            hsm.call("POST", "/keys/generate", {"mechanisms": ["ECDSA_Signature"], "type": "EC_P256", "id": kid})
        else:
            if not os.path.exists(self._file(kid)):
                os.makedirs(self.dir, mode=0o700, exist_ok=True)
                k = ec.generate_private_key(ec.SECP256R1())
                write(self._file(kid), k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()), 0o600)
        return self.public(kid)

    def public(self, kid: str):
        if kid in self._pub:
            return self._pub[kid]
        self._pub[kid] = self._load_public(kid)
        return self._pub[kid]

    def _load_public(self, kid: str):
        if self.nethsm:
            return serialization.load_pem_public_key(self.hsm().call("GET", f"/keys/{kid}/public.pem", raw=True))
        return serialization.load_pem_private_key(open(self._file(kid), "rb").read(), None).public_key()

    def sign(self, kid: str, digest: bytes) -> bytes:
        """ECDSA P-256 über einen SHA-256-Hash; Ergebnis wird vor der Rückgabe geprüft."""
        if self.nethsm:
            r = self.hsm().call("POST", f"/keys/{kid}/sign",
                                {"mode": "ECDSA", "message": base64.b64encode(digest).decode()})
            sig = _der(base64.b64decode(r["signature"]))
        else:
            k = serialization.load_pem_private_key(open(self._file(kid), "rb").read(), None)
            sig = k.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        self.public(kid).verify(sig, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return sig
