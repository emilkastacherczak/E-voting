"""Election authority: holds the Paillier keypair, accepts ballots, tallies."""

import secrets

import paillier
import rsa_sig
from ballot_box import BallotBox
from voter import ballot_payload


PHASE_VOTING = "voting"
PHASE_CLOSED = "closed"


class Election:
    def __init__(self, ca, candidates, expected_voters, paillier_bits=512,
                 election_id=None):
        if len(candidates) < 2:
            raise ValueError("need at least two candidates")
        if expected_voters < 1:
            raise ValueError("expected_voters must be positive")
        self.ca = ca
        self.candidates = list(candidates)
        self.expected_voters = expected_voters
        self.election_id = election_id or f"election-{secrets.token_hex(4)}"
        self.pub, self.priv = paillier.keygen(paillier_bits)
        self.box = BallotBox()
        self.ballots = {}  # voter_id -> ballot
        self.phase = PHASE_VOTING

    @property
    def base_M(self):
        """Base used to encode multi-candidate votes. M > max possible count
        for any single candidate prevents carries when summing."""
        return self.expected_voters + 1

    @property
    def max_plaintext(self):
        """Largest plaintext we might encrypt (vote for the last candidate)."""
        return pow(self.base_M, len(self.candidates) - 1)

    @property
    def max_tally_plaintext(self):
        """Largest possible value of the decrypted sum."""
        return self.expected_voters * pow(self.base_M, len(self.candidates) - 1)

    def submit(self, ballot):
        """Returns (accepted: bool, reason: str)."""
        if self.phase != PHASE_VOTING:
            return False, "voting is closed"
        if not isinstance(ballot, dict):
            return False, "malformed ballot"
        for key in ("cert", "ciphertext", "election_id", "timestamp", "voter_sig"):
            if key not in ballot:
                return False, f"ballot missing field {key!r}"
        if ballot["election_id"] != self.election_id:
            return False, "ballot is for a different election"
        if not self.ca.verify(ballot["cert"]):
            return False, "certificate is not signed by the trusted CA (or revoked)"
        if not rsa_sig.verify(
            ballot["cert"]["voter_pub"], ballot_payload(ballot), ballot["voter_sig"]
        ):
            return False, "voter signature is invalid"
        n2 = self.pub["n"] * self.pub["n"]
        if not (0 <= ballot["ciphertext"] < n2):
            return False, "ciphertext out of range"
        voter_id = ballot["cert"]["voter_id"]
        if voter_id in self.ballots:
            return False, "voter already cast a ballot (double vote)"
        if len(self.ballots) >= self.expected_voters:
            return False, "voter roll is full"
        self.ballots[voter_id] = ballot
        self.box.append(ballot)
        return True, "ballot accepted"

    def stored_ciphertext(self, voter_id):
        b = self.ballots.get(voter_id)
        return b["ciphertext"] if b else None

    def close(self):
        self.phase = PHASE_CLOSED

    def tally(self):
        """Homomorphically sum every ciphertext, decrypt once, decode base-M digits.

        Returns:
          counts:      dict candidate_name -> count
          encrypted:   the aggregate ciphertext (None if no ballots)
          plain_sum:   the integer that was decrypted (the base-M digits)
        """
        counts = {c: 0 for c in self.candidates}
        if not self.ballots:
            return counts, None, 0

        ciphertexts = [b["ciphertext"] for b in self.ballots.values()]
        acc = ciphertexts[0]
        for c in ciphertexts[1:]:
            acc = paillier.add(self.pub, acc, c)

        plain_sum = paillier.decrypt(self.priv, acc)

        # Decode base-M digits — leftmost digit = candidate 0, etc.
        M = self.base_M
        x = plain_sum
        for cand in self.candidates:
            counts[cand] = x % M
            x //= M
        return counts, acc, plain_sum
