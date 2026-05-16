"""Textbook Paillier cryptosystem with additive homomorphism.

Keys are plain dicts:
  pub  = {"n": n}
  priv = {"n": n, "lam": lam, "mu": mu}

Operations (g = n+1):
  Encrypt(m, r) = g^m * r^n   mod n^2     with r uniformly in Z_n^*
  Decrypt(c)    = L(c^lam mod n^2) * mu   mod n,   L(x) = (x-1)/n
  Add(c1, c2)   = c1 * c2     mod n^2     decrypts to m1 + m2 mod n
"""

import secrets
from math import gcd

from primes import gen_prime, lcm, modinv


def keygen(bits=512):
    """Generate Paillier keypair. Modulus n has roughly `bits` bits."""
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        # n must be coprime with phi(n) — this is automatic for safe choices
        # but we verify because gen_prime can in principle pick any prime.
        if gcd(n, (p - 1) * (q - 1)) == 1:
            break
    lam = lcm(p - 1, q - 1)
    # With g = n+1 we have L(g^lam mod n^2) = lam mod n, so mu = lam^-1 mod n.
    mu = modinv(lam % n, n)
    return {"n": n}, {"n": n, "lam": lam, "mu": mu}


def _rand_coprime(n):
    """Sample uniformly from Z_n^*."""
    while True:
        r = 1 + secrets.randbelow(n - 1)
        if gcd(r, n) == 1:
            return r


def encrypt(pub, m, r=None):
    """Encrypt m under pub. Returns (ciphertext, r) where r is the receipt."""
    n = pub["n"]
    n2 = n * n
    if not (0 <= m < n):
        raise ValueError("plaintext out of range [0, n)")
    if r is None:
        r = _rand_coprime(n)
    elif not (1 <= r < n) or gcd(r, n) != 1:
        raise ValueError("randomness r must be in Z_n^*")
    c = (pow(n + 1, m, n2) * pow(r, n, n2)) % n2
    return c, r


def decrypt(priv, c):
    n = priv["n"]
    n2 = n * n
    if not (0 <= c < n2):
        raise ValueError("ciphertext out of range [0, n^2)")
    u = pow(c, priv["lam"], n2)
    return (((u - 1) // n) * priv["mu"]) % n


def add(pub, c1, c2):
    """Homomorphic addition of two ciphertexts."""
    n2 = pub["n"] * pub["n"]
    return (c1 * c2) % n2
