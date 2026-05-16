"""Prime generation and modular utilities used by both Paillier and RSA.

Uses `secrets` (CSPRNG) instead of `random` — the `random` module is a
Mersenne Twister, fine for simulations but not for cryptographic keys.
"""

import secrets
from math import gcd


_SMALL_PRIMES = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
)


def miller_rabin(n, rounds=40):
    """Probabilistic primality test. Error probability <= 4^-rounds."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    """Generate a prime of exactly `bits` bits."""
    if bits < 8:
        raise ValueError("bits too small for safe prime generation")
    while True:
        candidate = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        if miller_rabin(candidate):
            return candidate


def lcm(a, b):
    return a // gcd(a, b) * b


def modinv(a, m):
    """Modular inverse of a mod m. Requires Python 3.8+."""
    return pow(a, -1, m)
