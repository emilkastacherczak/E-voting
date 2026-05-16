"""Minimal RSA signing used for voter keys and CA-issued certificates.

Keys are plain dicts:
  pub  = {"n": n, "e": e}
  priv = {"n": n, "e": e, "d": d}

Signature scheme: hash-then-sign with SHA-256 reduced mod n. This is a
teaching implementation; real systems should use RSA-PSS.
"""

import hashlib
from math import gcd

from primes import gen_prime, modinv


E = 65537


def keygen(bits=512):
    """Generate an RSA keypair with public exponent E."""
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(E, phi) == 1:
            break
    n = p * q
    d = modinv(E, phi)
    return {"n": n, "e": E}, {"n": n, "e": E, "d": d}


def hash_to_int(data, n):
    """Hash bytes to an integer modulo n."""
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, "big") % n


def sign(priv, data):
    return pow(hash_to_int(data, priv["n"]), priv["d"], priv["n"])


def verify(pub, data, sig):
    if not isinstance(sig, int) or sig < 0 or sig >= pub["n"]:
        return False
    return pow(sig, pub["e"], pub["n"]) == hash_to_int(data, pub["n"])
