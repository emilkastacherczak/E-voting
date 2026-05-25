import paillier
import rsa_sig


def ballot_payload(ballot):
    return f"{ballot['cert']['voter_id']}|{ballot['ciphertext']}".encode()


class Voter:
    def __init__(self, voter_id, ca, bits=512):
        self.voter_id = voter_id
        self.pub, self.priv = rsa_sig.keygen(bits)
        self.cert = ca.issue(voter_id, self.pub)
        self.receipt = None  # (vote, r) saved on first cast

    def cast(self, election_pub, vote):
        ciphertext, r = paillier.encrypt(election_pub, vote)
        if self.receipt is None:
            self.receipt = (vote, r)
        ballot = {"cert": self.cert, "ciphertext": ciphertext, "voter_sig": 0}
        ballot["voter_sig"] = rsa_sig.sign(self.priv, ballot_payload(ballot))
        return ballot

    def verify_recorded(self, election_pub, stored_ciphertext):
        """Re-encrypt with saved randomness and compare to the ballot box's record."""
        if self.receipt is None:
            return False
        vote, r = self.receipt
        expected, _ = paillier.encrypt(election_pub, vote, r=r)
        return expected == stored_ciphertext
