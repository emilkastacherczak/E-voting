"""Minimal RSA signing used for voter keys and CA-issued certificates.

Keys are plain dicts:
  pub  = {"n": n, "e": e}
  priv = {"n": n, "e": e, "d": d}
"""

import hashlib

from primes import gen_prime, modinv


def keygen(bits=512):
    e = 65537
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e != 0:
            break
    n = p * q
    d = modinv(e, phi)
    pub = {"n": n, "e": e}
    priv = {"n": n, "e": e, "d": d}
    return pub, priv


def hash_to_int(data, n):
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, "big") % n


def sign(priv, data):
    return pow(hash_to_int(data, priv["n"]), priv["d"], priv["n"])


def verify(pub, data, sig):
    return pow(sig, pub["e"], pub["n"]) == hash_to_int(data, pub["n"])
