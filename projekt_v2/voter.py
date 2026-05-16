"""Voter: holds an RSA keypair + CA cert, casts an encrypted ballot.

Multi-candidate encoding:
  A ballot for candidate index i is the Paillier encryption of M^i,
  where M is the chosen base (typically M = expected_voters + 1).

Because each per-candidate count is at most expected_voters < M, the
homomorphic sum of all ballots decrypts to a single integer whose
base-M digits are the per-candidate counts (no carries between digits).

Ballot format:
  {"cert", "ciphertext", "election_id", "timestamp", "voter_sig"}
"""

import time

import paillier
import rsa_sig


def ballot_payload(ballot):
    """Bytes signed by the voter — binds ciphertext to voter id + election + time."""
    return (
        f"{ballot['election_id']}"
        f"|{ballot['cert']['voter_id']}"
        f"|{ballot['ciphertext']}"
        f"|{ballot['timestamp']}"
    ).encode()


class Voter:
    def __init__(self, voter_id, ca, bits=512):
        self.voter_id = voter_id
        self.pub, self.priv = rsa_sig.keygen(bits)
        self.cert = ca.issue(voter_id, self.pub)
        # Receipt from the FIRST cast, kept so the voter can later verify
        # what's in the ballot box matches what they sent.
        self.receipt = None  # dict: {"choice", "plaintext", "r", "ciphertext", "timestamp"}

    def encode_vote(self, choice_index, num_candidates, base_M):
        if not (0 <= choice_index < num_candidates):
            raise ValueError(
                f"invalid candidate index {choice_index} (have {num_candidates} candidates)"
            )
        return pow(base_M, choice_index)

    def cast(self, election_pub, election_id, choice_index, num_candidates, base_M):
        plaintext = self.encode_vote(choice_index, num_candidates, base_M)
        ciphertext, r = paillier.encrypt(election_pub, plaintext)
        timestamp = time.time()

        if self.receipt is None:
            self.receipt = {
                "choice": choice_index,
                "plaintext": plaintext,
                "r": r,
                "ciphertext": ciphertext,
                "timestamp": timestamp,
            }

        ballot = {
            "cert": self.cert,
            "ciphertext": ciphertext,
            "election_id": election_id,
            "timestamp": timestamp,
            "voter_sig": 0,
        }
        ballot["voter_sig"] = rsa_sig.sign(self.priv, ballot_payload(ballot))
        return ballot

    def verify_recorded(self, election_pub, stored_ciphertext):
        """Re-encrypt with the saved randomness and compare to what the
        ballot box claims to have stored under this voter's id."""
        if self.receipt is None or stored_ciphertext is None:
            return False
        expected, _ = paillier.encrypt(
            election_pub, self.receipt["plaintext"], r=self.receipt["r"]
        )
        return expected == stored_ciphertext
