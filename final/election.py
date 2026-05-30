import paillier
import rsa_sig
from voter import ballot_payload


class Election:
    def __init__(self, ca, candidates, expected_voters, paillier_bits=512):
        self.ca = ca
        self.candidates = list(candidates)
        self.base_M = expected_voters + 1  # base > max votes per candidate prevents carries
        self.pub, self.priv = paillier.keygen(paillier_bits)
        self.ballots = {}  # voter_id -> ballot

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
        counts = {c: 0 for c in self.candidates}
        if not self.ballots:
            return counts
        ciphertexts = [b["ciphertext"] for b in self.ballots.values()]
        acc = ciphertexts[0]
        for c in ciphertexts[1:]:
            acc = paillier.add(self.pub, acc, c)
        x = paillier.decrypt(self.priv, acc)
        for cand in self.candidates:
            counts[cand] = x % self.base_M
            x //= self.base_M
        return counts