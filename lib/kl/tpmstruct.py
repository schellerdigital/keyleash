# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""TPM-2.0-Strukturen und Policy-Digests in reinem Python.

Der Autorisierungsserver braucht kein TPM: Er berechnet Policy-Digests,
Namen und prüft Attestation-Strukturen selbst. Die Formeln sind gegen
tpm2-tools (Trial-Sessions) getestet, siehe tests/test_policy.sh.
"""
import hashlib
import struct
from dataclasses import dataclass

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_CERTIFY = 0x8017
TPM_ST_ATTEST_QUOTE = 0x8018

TPM_ALG_RSA = 0x0001
TPM_ALG_SHA256 = 0x000B
TPM_ALG_NULL = 0x0010

CC_POLICY_AUTHORIZE = 0x0000016A
CC_POLICY_AUTH_VALUE = 0x0000016B
CC_POLICY_COUNTER_TIMER = 0x0000016D
CC_POLICY_PCR = 0x0000017F
CC_POLICY_SIGNED = 0x00000160
CC_SIGN = 0x0000015D
TPM_ALG_RSASSA = 0x0014
TPM_ST_HASHCHECK = 0x8024
TPM_RH_NULL = 0x40000007

TPM_EO_EQ = 0x0000
TPM_EO_UNSIGNED_LE = 0x0009

# Offsets in TPMS_TIME_INFO (für PolicyCounterTimer)
OFF_CLOCK = 8          # UINT64, ms, persistent (läuft nur mit Strom)
OFF_RESET_COUNT = 16   # UINT32, +1 bei jedem TPM-Reset (= Reboot)
OFF_SAFE = 24          # BYTE, YES = Uhr seit dem letzten Sichern nicht zurückgefallen

# TPMA_OBJECT
A_FIXED_TPM = 1 << 1
A_FIXED_PARENT = 1 << 4
A_SENSITIVE_DATA_ORIGIN = 1 << 5
A_USER_WITH_AUTH = 1 << 6
A_ADMIN_WITH_POLICY = 1 << 7
A_RESTRICTED = 1 << 16
A_DECRYPT = 1 << 17
A_SIGN = 1 << 18


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


class Reader:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def take(self, n):
        if self.i + n > len(self.d):
            raise ValueError("TPM-Struktur zu kurz")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack(">H", self.take(2))[0]

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def tpm2b(self):
        return self.take(self.u16())

    def rest(self):
        return self.d[self.i:]


# ---------------------------------------------------------------- Public ---

@dataclass
class RsaPublic:
    tpmt: bytes          # TPMT_PUBLIC (ohne Größenpräfix)
    name_alg: int
    attrs: int
    auth_policy: bytes
    scheme: int
    key_bits: int
    exponent: int
    modulus: bytes

    @property
    def name(self) -> bytes:
        return struct.pack(">H", self.name_alg) + sha256(self.tpmt)

    def has(self, bit):
        return bool(self.attrs & bit)


def parse_tpm2b_public(data: bytes) -> RsaPublic:
    """Parst eine TPM2B_PUBLIC-Datei (tpm2-tools -u / -f tss)."""
    r = Reader(data)
    tpmt = r.tpm2b()
    p = Reader(tpmt)
    typ = p.u16()
    if typ != TPM_ALG_RSA:
        raise ValueError("nur RSA-Schlüssel werden im Lab unterstützt")
    name_alg = p.u16()
    attrs = p.u32()
    auth_policy = p.tpm2b()
    sym = p.u16()
    if sym != TPM_ALG_NULL:
        p.u16(); p.u16()
    scheme = p.u16()
    if scheme != TPM_ALG_NULL:
        p.u16()
    key_bits = p.u16()
    exponent = p.u32() or 65537
    modulus = p.tpm2b()
    return RsaPublic(tpmt, name_alg, attrs, auth_policy, scheme, key_bits, exponent, modulus)


def external_rsa_name(modulus: bytes, exponent: int = 65537) -> bytes:
    """Name eines per tpm2_loadexternal geladenen RSA-Public-Keys.

    Entspricht der Vorlage von tpm2-tools 5.x: sign|decrypt|userwithauth,
    keine Policy, kein Schema, Exponent explizit.
    """
    tpmt = struct.pack(">HHI", TPM_ALG_RSA, TPM_ALG_SHA256,
                       A_SIGN | A_DECRYPT | A_USER_WITH_AUTH)
    tpmt += struct.pack(">H", 0)                       # authPolicy leer
    tpmt += struct.pack(">HH", TPM_ALG_NULL, TPM_ALG_NULL)
    tpmt += struct.pack(">HI", len(modulus) * 8, exponent)
    tpmt += struct.pack(">H", len(modulus)) + modulus
    return struct.pack(">H", TPM_ALG_SHA256) + sha256(tpmt)


# ---------------------------------------------------------------- Attest ---

@dataclass
class Attest:
    raw: bytes
    type: int
    signer: bytes
    extra: bytes
    clock: int
    reset_count: int
    restart_count: int
    safe: int
    firmware: int
    # Quote
    pcr_select: bytes = b""
    pcr_digest: bytes = b""
    # Certify
    cert_name: bytes = b""
    cert_qname: bytes = b""


def parse_attest(data: bytes) -> Attest:
    r = Reader(data)
    if r.u32() != TPM_GENERATED_VALUE:
        raise ValueError("kein TPM-generiertes Attest (magic)")
    typ = r.u16()
    signer = r.tpm2b()
    extra = r.tpm2b()
    clock = r.u64(); reset = r.u32(); restart = r.u32(); safe = r.u8()
    fw = r.u64()
    a = Attest(data, typ, signer, extra, clock, reset, restart, safe, fw)
    if typ == TPM_ST_ATTEST_QUOTE:
        start = r.i
        count = r.u32()
        for _ in range(count):
            r.u16(); r.take(r.u8())
        a.pcr_select = data[start:r.i]
        a.pcr_digest = r.tpm2b()
    elif typ == TPM_ST_ATTEST_CERTIFY:
        a.cert_name = r.tpm2b()
        a.cert_qname = r.tpm2b()
    else:
        raise ValueError(f"unerwarteter Attest-Typ 0x{typ:04x}")
    return a


# ---------------------------------------------------------------- Policy ---

def pcr_selection(pcrs) -> bytes:
    """TPML_PCR_SELECTION für eine SHA-256-Bank."""
    bitmap = bytearray(3)
    for p in pcrs:
        bitmap[p // 8] |= 1 << (p % 8)
    return struct.pack(">IHB", 1, TPM_ALG_SHA256, 3) + bytes(bitmap)


def parse_pcr_list(spec: str):
    """'sha256:7,16' -> [7, 16]"""
    bank, _, idx = spec.partition(":")
    if bank != "sha256":
        raise ValueError("nur die SHA-256-Bank wird unterstützt")
    return sorted(int(x) for x in idx.split(",") if x != "")


def policy_counter_timer(d: bytes, operand: int, size: int, offset: int,
                         op: int = TPM_EO_UNSIGNED_LE) -> bytes:
    args = sha256(operand.to_bytes(size, "big") + struct.pack(">HH", offset, op))
    return sha256(d + struct.pack(">I", CC_POLICY_COUNTER_TIMER) + args)


def policy_pcr(d: bytes, pcrs, pcr_digest: bytes) -> bytes:
    return sha256(d + struct.pack(">I", CC_POLICY_PCR) + pcr_selection(pcrs) + pcr_digest)


def policy_authorize(d: bytes, key_name: bytes, policy_ref: bytes) -> bytes:
    d = sha256(d + struct.pack(">I", CC_POLICY_AUTHORIZE) + key_name)
    return sha256(d + policy_ref)


def policy_auth_value(d: bytes) -> bytes:
    return sha256(d + struct.pack(">I", CC_POLICY_AUTH_VALUE))


ZERO = b"\0" * 32


def key_policy(authz_name: bytes, policy_ref: bytes) -> bytes:
    """authPolicy des Maschinenschlüssels.

    PolicyAuthorize (nur vom Autorisierungsserver signierte Tickets)
    gefolgt von PolicyAuthValue (Geheimnis, das nur der berechtigte
    Prozess kennt; Grundlage der Härtung Stufe 1).
    """
    return policy_auth_value(policy_authorize(ZERO, authz_name, policy_ref))


def approved_policy(expiry_clock: int, max_resets: int, pcrs, pcr_digest: bytes,
                    clock_safe: bool = True, pin_resets: bool = False) -> bytes:
    """Der Inhalt eines Tickets: Ablauf, Neustart-Grenze, Uhr-Zustand, Boot-Zustand.

    Ablauf über clock (nicht time): clock ist persistent und kann nur
    vorwärts gestellt werden. Nach einem Stromausfall fällt clock bis zum
    letzten gesicherten Stand zurück und das TPM meldet safe = NO. Zwei
    Varianten schließen aus, dass sich die Laufzeit so strecken lässt:
      clock_safe   das Ticket verlangt safe = YES (Normalfall)
      pin_resets   resetCount muss exakt gleich bleiben (Ticket nach
                   unsicherer Uhr: kein Neustart, also kein Rücksprung)
    """
    d = policy_counter_timer(ZERO, expiry_clock, 8, OFF_CLOCK)
    d = policy_counter_timer(d, max_resets, 4, OFF_RESET_COUNT,
                             TPM_EO_EQ if pin_resets else TPM_EO_UNSIGNED_LE)
    if clock_safe:
        d = policy_counter_timer(d, 1, 1, OFF_SAFE, TPM_EO_EQ)
    return policy_pcr(d, pcrs, pcr_digest)


def policy_ref_for(host_id: str) -> bytes:
    return sha256(b"keyleash/v1/" + host_id.encode())


# ---------------------------------------------------------- Freigaben ----
# Zwecke mit Freigabepflicht (z. B. "release") bekommen einen eigenen
# Schlüssel. Dessen Tickets verlangen zusätzlich PolicySigned: eine
# Signatur des Freigabeschlüssels über den cpHash genau des
# TPM2_Sign-Aufrufs, also über Schlüssel und Daten-Hash.

def purpose_policy_ref(host_id: str, purpose: str) -> bytes:
    return sha256(b"keyleash/v1/" + host_id.encode() + b"#" + purpose.encode())


def approval_ref(purpose: str) -> bytes:
    return sha256(b"keyleash/approval/" + purpose.encode())


def policy_signed(d: bytes, auth_name: bytes, policy_ref: bytes) -> bytes:
    d = sha256(d + struct.pack(">I", CC_POLICY_SIGNED) + auth_name)
    return sha256(d + policy_ref)


def approved_policy_with_approval(expiry_clock, max_resets, pcrs, pcr_digest,
                                  approver_name: bytes, purpose: str,
                                  clock_safe: bool = True, pin_resets: bool = False) -> bytes:
    d = approved_policy(expiry_clock, max_resets, pcrs, pcr_digest, clock_safe, pin_resets)
    return policy_signed(d, approver_name, approval_ref(purpose))


def sign_cphash(key_name: bytes, digest: bytes) -> bytes:
    """cpHash von TPM2_Sign(key, digest, RSASSA-SHA256, NULL-Ticket)."""
    params = struct.pack(">H", len(digest)) + digest
    params += struct.pack(">HH", TPM_ALG_RSASSA, TPM_ALG_SHA256)
    params += struct.pack(">HIH", TPM_ST_HASHCHECK, TPM_RH_NULL, 0)
    return sha256(struct.pack(">I", CC_SIGN) + key_name + params)


def approval_message(cphash: bytes, purpose: str) -> bytes:
    """Was der Freigebende signiert: nonceTPM (leer) | expiration (0) | cpHash | policyRef."""
    return struct.pack(">i", 0) + cphash + approval_ref(purpose)
