"""
algos.py - one uniform, bytes-in / bytes-out interface for every algorithm.

Why this file exists
--------------------
Every algorithm (classical or post-quantum) is wrapped so that:
  * the object/key-handle is created ONCE, outside any timing loop
  * every timed operation takes and returns raw bytes, exactly as the network
    layer would use it. So parsing/serialisation cost is INCLUDED for the
    classical algorithms the same way liboqs includes it internally.

KEM interface:   keygen() -> pk ; encaps(pk) -> (ct, ss) ; decaps(ct) -> ss
SIG interface:   keygen() -> pk ; sign(msg) -> sig ; verify(pk, msg, sig) -> bool
(secret keys stay inside the object, like liboqs does.)
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature

OQS_ERROR = None
try:
    import oqs
    HAVE_OQS = True
except BaseException as e:           # liboqs missing or cannot be loaded
    oqs = None
    HAVE_OQS = False
    OQS_ERROR = repr(e)

_CURVE = ec.SECP256R1
_ENC, _FMT = Encoding.X962, PublicFormat.UncompressedPoint


def _pk_bytes(private_key):
    return private_key.public_key().public_bytes(_ENC, _FMT)


# ----------------------------------------------------------------------------
# Classical
# ----------------------------------------------------------------------------
class EcdhKem:
    name, family, kind = "ECDH-P256", "classical", "kem"

    def __init__(self):
        self._sk = None

    def keygen(self):
        self._sk = ec.generate_private_key(_CURVE())
        return _pk_bytes(self._sk)

    def encaps(self, pk):
        eph = ec.generate_private_key(_CURVE())
        peer = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE(), pk)
        return _pk_bytes(eph), eph.exchange(ec.ECDH(), peer)

    def decaps(self, ct):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE(), ct)
        return self._sk.exchange(ec.ECDH(), peer)

    def sizes(self):
        pk = self.keygen()
        ct, ss = self.encaps(pk)
        return {"pk": len(pk), "sk": 32, "ct_or_sig": len(ct), "ss": len(ss)}


class EcdsaSig:
    name, family, kind = "ECDSA-P256", "classical", "sig"

    def __init__(self):
        self._sk = None

    def keygen(self):
        self._sk = ec.generate_private_key(_CURVE())
        return _pk_bytes(self._sk)

    def sign(self, msg):
        return self._sk.sign(msg, ECDSA(hashes.SHA256()))

    def verify(self, pk, msg, sig):
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE(), pk)
            peer.verify(sig, msg, ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def sizes(self):
        pk = self.keygen()
        sig = self.sign(b"x" * 100)
        return {"pk": len(pk), "sk": 32, "ct_or_sig": len(sig), "ss": 0}


# ----------------------------------------------------------------------------
# Post-quantum (liboqs)
# ----------------------------------------------------------------------------
class OqsKem:
    family, kind = "post-quantum", "kem"

    def __init__(self, alg):
        self.name = alg
        self._o = oqs.KeyEncapsulation(alg)

    def keygen(self):
        return self._o.generate_keypair()

    def encaps(self, pk):
        return self._o.encap_secret(pk)

    def decaps(self, ct):
        return self._o.decap_secret(ct)

    def sizes(self):
        d = self._o.details
        return {"pk": d["length_public_key"], "sk": d["length_secret_key"],
                "ct_or_sig": d["length_ciphertext"], "ss": d["length_shared_secret"]}


class OqsSig:
    family, kind = "post-quantum", "sig"

    def __init__(self, alg):
        self.name = alg
        self._o = oqs.Signature(alg)

    def keygen(self):
        return self._o.generate_keypair()

    def sign(self, msg):
        return self._o.sign(msg)

    def verify(self, pk, msg, sig):
        return self._o.verify(msg, sig, pk)

    def sizes(self):
        d = self._o.details
        return {"pk": d["length_public_key"], "sk": d["length_secret_key"],
                "ct_or_sig": d["length_signature"], "ss": 0}


# ----------------------------------------------------------------------------
# Discovery - never assume a name exists; ask the installed liboqs.
# ----------------------------------------------------------------------------
def _enabled(kind):
    if not HAVE_OQS:
        return set()
    fn = oqs.get_enabled_kem_mechanisms if kind == "kem" else oqs.get_enabled_sig_mechanisms
    return set(fn())


def _find_slh(enabled, size, variant):
    """Find the SLH-DSA SHAKE parameter set for the Windows simulation."""
    want = f"{size}{variant}".lower()
    cands = [n for n in enabled
             if want in n.lower() and "shake" in n.lower() and "prehash" not in n.lower()
             and ("slh" in n.lower() or "sphincs" in n.lower())]
    cands.sort(key=lambda n: (0 if "slh" in n.lower() else 1, n))   # prefer FIPS 205 names
    return cands[0] if cands else None


def kem_catalog():
    """[(label, factory)] in display order. Classical first."""
    cat = [("ECDH-P256", lambda: EcdhKem())]
    en = _enabled("kem")
    for n in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        if n in en:
            cat.append((n, (lambda n=n: OqsKem(n))))
    return cat


def sig_catalog(include_slow=True):
    cat = [("ECDSA-P256", lambda: EcdsaSig())]
    en = _enabled("sig")
    names = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512", "Falcon-1024"]
    names.append(_find_slh(en, "128", "f"))
    if include_slow:
        names.append(_find_slh(en, "128", "s"))
    for n in names:
        if n and n in en:
            cat.append((n, (lambda n=n: OqsSig(n))))
    return cat


# Slow signers need a smaller sample budget (they take 100s of ms to seconds on weak CPUs)
def is_slow(name):
    return name.upper().endswith("128S") or "128s" in name


def pipeline_pairs(include_slow=True):
    """(label, kem_label, sig_label) combinations used by the end-to-end pipeline."""
    kems = dict(kem_catalog())
    sigs = dict(sig_catalog(include_slow))
    wanted = [("classical", "ECDH-P256", "ECDSA-P256"),
              ("ML-KEM-512 + ML-DSA-44", "ML-KEM-512", "ML-DSA-44"),
              ("ML-KEM-768 + ML-DSA-65", "ML-KEM-768", "ML-DSA-65"),
              ("ML-KEM-1024 + ML-DSA-87", "ML-KEM-1024", "ML-DSA-87"),
              ("ML-KEM-512 + Falcon-512", "ML-KEM-512", "Falcon-512")]
    fast = _find_slh(_enabled("sig"), "128", "f")
    slow = _find_slh(_enabled("sig"), "128", "s")
    if fast:
        wanted.append((f"ML-KEM-512 + {fast}", "ML-KEM-512", fast))
    if slow and include_slow:
        wanted.append((f"ML-KEM-512 + {slow}", "ML-KEM-512", slow))
    return [(l, k, s) for (l, k, s) in wanted if k in kems and s in sigs]
