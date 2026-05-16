"""Election authority: holds the Paillier keypair, accepts ballots, tallies homomorphically."""

import paillier
import rsa_sig
from voter import ballot_payload


class Election:
    def __init__(self, ca, paillier_bits=512):
        self.ca = ca
        self.pub, self.priv = paillier.keygen(paillier_bits)
        self.ballots = {}  # voter_id -> ballot (enforces one-vote-per-voter)

    def submit(self, ballot):
        if not self.ca.verify(ballot["cert"]):
            return False
        if not rsa_sig.verify(ballot["cert"]["voter_pub"], ballot_payload(ballot), ballot["voter_sig"]):
            return False
        voter_id = ballot["cert"]["voter_id"]
        if voter_id in self.ballots:
            return False
        self.ballots[voter_id] = ballot
        return True

    def stored_ciphertext(self, voter_id):
        b = self.ballots.get(voter_id)
        return b["ciphertext"] if b else None

    def tally(self):
        ciphertexts = [b["ciphertext"] for b in self.ballots.values()]
        if not ciphertexts:
            return 0
        acc = ciphertexts[0]
        for c in ciphertexts[1:]:
            acc = paillier.add(self.pub, acc, c)
        return paillier.decrypt(self.priv, acc)
