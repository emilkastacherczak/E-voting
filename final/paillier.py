import random
from math import gcd

from primes import gen_prime, lcm, modinv


def keygen(bits=512):
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        if gcd(n, (p - 1) * (q - 1)) == 1:
            break
    lam = lcm(p - 1, q - 1)
    # With g = n+1, L(g^lambda mod n^2) = lambda mod n, so mu = lambda^-1 mod n.
    mu = modinv(lam % n, n)
    pub = {"n": n}
    priv = {"n": n, "lam": lam, "mu": mu}
    return pub, priv


def rand_coprime(n):
    while True:
        r = random.randrange(1, n)
        if gcd(r, n) == 1:
            return r


def encrypt(pub, m, r=None):
    n = pub["n"]
    n2 = n * n
    if r is None:
        r = rand_coprime(n)
    g = n + 1
    c = (pow(g, m, n2) * pow(r, n, n2)) % n2
    return c, r


def decrypt(priv, c):
    n = priv["n"]
    n2 = n * n
    u = pow(c, priv["lam"], n2)
    L = (u - 1) // n
    return (L * priv["mu"]) % n


def add(pub, c1, c2):
    n2 = pub["n"] * pub["n"]
    return (c1 * c2) % n2
