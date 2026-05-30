import paillier
import rsa_sig


def ballot_payload(ballot):
    return f"{ballot['cert']['voter_id']}|{ballot['ciphertext']}".encode()


class Voter:
    def __init__(self, voter_id, ca, bits=512):
        self.voter_id = voter_id
        self.pub, self.priv = rsa_sig.keygen(bits)
        self.cert = ca.issue(voter_id, self.pub)
        self.receipt = None  # (choice_index, plaintext, r)

    def cast(self, election_pub, choice_index, num_candidates, base_M):
        if not (0 <= choice_index < num_candidates):
            raise ValueError(f"invalid candidate index {choice_index}")
        plaintext = pow(base_M, choice_index)
        ciphertext, r = paillier.encrypt(election_pub, plaintext)
        if self.receipt is None:
            self.receipt = (choice_index, plaintext, r)
        ballot = {"cert": self.cert, "ciphertext": ciphertext, "voter_sig": 0}
        ballot["voter_sig"] = rsa_sig.sign(self.priv, ballot_payload(ballot))
        return ballot

    def verify_recorded(self, election_pub, stored_ciphertext):
        if self.receipt is None:
            return False
        _choice, plaintext, r = self.receipt
        expected, _ = paillier.encrypt(election_pub, plaintext, r=r)
        return expected == stored_ciphertext