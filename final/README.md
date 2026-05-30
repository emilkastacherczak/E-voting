## Authors

- Oliwia Łośko
- Emilia Stacherczak
- Michał Niezgoda

# E-voting Simulation

A secure voting system in which votes are encrypted with **Paillier homomorphic encryption**, eligibility is enforced with **RSA certificates**, and the final result is computed **without decrypting any individual ballot**.

**Security properties**
- Eligibility is proven by a CA-signed certificate
- Each voter gets a private receipt only they can use to verify their own vote
- Double-voting is rejected
- Forged certificates (signed by an untrusted CA) are rejected
- Individual votes are never decrypted — only the aggregate is

---

## Requirements

- Python 3.8+ (uses `pow(a, -1, m)` for modular inverse)
- Standard library only (`hashlib`, `random`, `math`, `argparse`) — no external dependencies

---

## How to run

```
python3 main.py [--voters N] [--candidates NAME [NAME ...]]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--voters` | `int` | `10` | Number of voters to register. Also sets the encoding base `M = N + 1`. |
| `--candidates` | `str ...` | `Party A`, `Party B`, `Party C` | Space-separated candidate names. Must be at least 2. Wrap names containing spaces in quotes. |

**Examples**

```
# Defaults: 10 voters, 3 parties
python3 main.py

# 20 voters, two candidates
python3 main.py --voters 20 --candidates "Party A" "Party B"

# Custom names with spaces
python3 main.py --voters 6 --candidates "Alice Smith" "Bob Jones" "Carol Lee"
```

Running `main.py` performs a full end-to-end run: key generation -> voter registration -> random voting -> two attack simulations -> receipt verification -> homomorphic tally, with assertions checking correctness at each stage.

---

## Architecture

```
main.py
  |-- ca.py          CA          (RSA certificates)
  |-- election.py    Election    (Paillier keypair, ballot acceptance, tally)
  |-- voter.py       Voter       (RSA keys, vote encoding/encryption, receipt)
  |-- paillier.py    keygen / encrypt / decrypt / add
  |-- rsa_sig.py     keygen / sign / verify
  |-- primes.py      gen_prime / miller_rabin / lcm / modinv
```

Dependency direction: `ca`, `election`, `voter` build on `paillier` and `rsa_sig`, which both build on `primes`.

---

## Module reference

### `primes.py` — number-theoretic primitives
Shared low-level helpers for both cryptosystems.

| Function | Description |
|----------|-------------|
| `miller_rabin(n, rounds=40)` | Probabilistic primality test. Returns `True`/`False`. |
| `gen_prime(bits)` | Returns a random prime of exactly `bits` bits (top and bottom bit forced to 1). |
| `lcm(a, b)` | Least common multiple. |
| `modinv(a, m)` | Modular inverse of `a` mod `m`. |

### `rsa_sig.py` — RSA hash-then-sign
Used for both voter keys and CA certificates. Signing is `H(data)^d mod n`, where `H` is SHA-256 reduced mod `n`.

| Function | Returns | Notes |
|----------|---------|-------|
| `keygen(bits=512)` | `(pub, priv)` | `pub = {"n", "e"}`, `priv = {"n", "e", "d"}`, public exponent `e = 65537`. |
| `hash_to_int(data, n)` | `int` | SHA-256 of `data` interpreted as a big integer, mod `n`. |
| `sign(priv, data)` | `int` | Signature over `data` (bytes). |
| `verify(pub, data, sig)` | `bool` | `True` iff `sig` is a valid signature on `data` under `pub`. |

### `paillier.py` — Paillier cryptosystem
Additively homomorphic encryption with generator `g = n + 1`.

| Function | Returns | Notes |
|----------|---------|-------|
| `keygen(bits=512)` | `(pub, priv)` | `pub = {"n"}`, `priv = {"n", "lam", "mu"}`. |
| `encrypt(pub, m, r=None)` | `(c, r)` | `c = g^m * r^n mod n^2`. Returns the randomness `r` so it can be saved as a receipt. Pass `r` to reproduce a previous ciphertext. |
| `decrypt(priv, c)` | `int` | Recovers the plaintext `m`. |
| `add(pub, c1, c2)` | `int` | `c1 * c2 mod n^2`, which decrypts to `m1 + m2`. This is the homomorphic property the tally relies on. |

### `ca.py` — Certificate Authority
Holds an RSA keypair. Issues and verifies certificates that bind a voter id to a public key.

- **Certificate format:** `{"voter_id", "voter_pub", "ca_sig"}`
- **Signed payload (`cert_payload`):** `f"{voter_id}|{pub_n}|{pub_e}"`

| Method | Description |
|--------|-------------|
| `__init__(bits=512)` | Generates the CA's RSA keypair. |
| `issue(voter_id, voter_pub)` | Builds a certificate and signs it with the CA private key. |
| `verify(cert)` | `True` iff `ca_sig` is valid under this CA's public key. A certificate signed by a different (rogue) CA fails here. |

### `voter.py` — Voter
Holds an RSA keypair and a CA-issued certificate. Encodes, encrypts, and signs a ballot.

- **Ballot format:** `{"cert", "ciphertext", "voter_sig"}`
- **Signed payload (`ballot_payload`):** `f"{voter_id}|{ciphertext}"`
- **Receipt:** tuple `(choice_index, plaintext, r)` saved on the first cast.

| Method | Description |
|--------|-------------|
| `__init__(voter_id, ca, bits=512)` | Generates RSA keys and requests a certificate from `ca`. |
| `cast(election_pub, choice_index, num_candidates, base_M)` | Encodes the vote as `base_M ** choice_index`, encrypts it with Paillier, signs the ballot, stores the receipt, returns the ballot. |
| `verify_recorded(election_pub, stored_ciphertext)` | Re-encrypts the receipt plaintext with the saved `r` and checks it equals `stored_ciphertext`. Proves the ballot box did not alter the vote. |

### `election.py` — Election authority
Holds the Paillier keypair and the candidate list, accepts ballots, and tallies.

| Attribute / Method | Description |
|--------------------|-------------|
| `__init__(ca, candidates, expected_voters, paillier_bits=512)` | Stores the candidate list, sets `base_M = expected_voters + 1`, generates the Paillier keypair. |
| `base_M` | Encoding base. Chosen larger than the maximum possible count for any single candidate so digit sums never carry. |
| `submit(ballot)` | Validates and stores a ballot. Returns `True`/`False`. Checks (in order): certificate signed by trusted CA -> ballot signed by the named voter -> voter has not already voted. |
| `stored_ciphertext(voter_id)` | Returns the stored ciphertext for a voter, or `None`. |
| `tally()` | Homomorphically sums all ciphertexts, decrypts once, decodes the base-`M` digits, returns `{candidate: count}`. |

### `main.py` — demo driver
Parses CLI flags and runs the full scenario described in **How to run**.

---

## How the multi-candidate encoding works

A vote for candidate `i` is encrypted as the number **`M^i`**, where `M = expected_voters + 1`.

Because Paillier is additively homomorphic, multiplying all ciphertexts together and decrypting once yields the integer:

```
sum = c_0 * M^0 + c_1 * M^1 + c_2 * M^2 + ...
```

where `c_i` is the number of votes candidate `i` received. Since every `c_i <= expected_voters < M`, no digit can overflow into the next, so the **base-`M` digits of `sum` are exactly the per-candidate counts**. The tally extracts them with repeated `% M` / `// M`.

Example: with `M = 11` (10 voters), if candidate 0 gets 4 votes, candidate 1 gets 2, candidate 2 gets 4, the decrypted integer is `4*1 + 2*11 + 4*121 = 510`, whose base-11 digits are `(4, 2, 4)`.

---

## Execution flow

1. **CA setup** — CA generates an RSA keypair; it will sign certificates proving eligibility.
2. **Election setup** — election authority generates a Paillier keypair.
3. **Registration** — each voter generates an RSA keypair and receives a CA-signed certificate.
4. **Voting** — each voter encodes their choice as `M^i`, encrypts it under the election public key, signs the ballot, and keeps a private receipt `(choice, plaintext, r)`.
5. **Submission** — election verifies the certificate, verifies the ballot signature, and rejects repeat voters.
6. **Attack #1** — a voter tries to vote twice -> rejected (id already present).
7. **Attack #2** — an outsider with a certificate from a rogue CA tries to vote -> rejected (`CA.verify` fails).
8. **Verification** — every voter re-encrypts with their saved `r` and confirms the stored ciphertext matches.
9. **Tally** — all ciphertexts are multiplied and a single integer is decrypted; its base-`M` digits give the counts. No individual ballot is ever decrypted.

---

## Security notes / limitations

This is a teaching implementation, not production-grade:
- 512-bit keys and `random` (Mersenne Twister) are used for speed, not cryptographic strength — a real system needs >= 2048-bit keys and a CSPRNG.
- RSA signatures are textbook hash-then-sign; real systems should use RSA-PSS.
- There is no voter-vote unlinkability beyond not decrypting individual ballots, and no ballot anonymization on the network layer.

---