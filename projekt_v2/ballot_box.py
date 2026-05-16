"""Tamper-evident ballot box: a hash chain of accepted ballots.

Each entry contains the SHA-256 hash of (prev_hash || entry_data). Modifying
any past entry makes every subsequent hash mismatch, so the chain detects
tampering. This is the minimal "blockchain-like" structure mentioned in the
project brief — no consensus, no proof of work, just an append-only log.
"""

import hashlib


GENESIS = b"\x00" * 32


def _entry_hash(prev_hash, voter_id, ciphertext, election_id, timestamp, voter_sig):
    h = hashlib.sha256()
    h.update(prev_hash)
    h.update(voter_id.encode())
    h.update(str(ciphertext).encode())
    h.update(str(election_id).encode())
    h.update(str(timestamp).encode())
    h.update(str(voter_sig).encode())
    return h.digest()


class BallotBox:
    def __init__(self):
        self.chain = []  # list of entry dicts

    def __len__(self):
        return len(self.chain)

    def append(self, ballot):
        prev = self.chain[-1]["hash"] if self.chain else GENESIS
        entry = {
            "index": len(self.chain),
            "voter_id": ballot["cert"]["voter_id"],
            "ciphertext": ballot["ciphertext"],
            "election_id": ballot["election_id"],
            "timestamp": ballot["timestamp"],
            "voter_sig": ballot["voter_sig"],
            "prev_hash": prev,
        }
        entry["hash"] = _entry_hash(
            prev,
            entry["voter_id"],
            entry["ciphertext"],
            entry["election_id"],
            entry["timestamp"],
            entry["voter_sig"],
        )
        self.chain.append(entry)
        return entry

    def find(self, voter_id):
        for e in self.chain:
            if e["voter_id"] == voter_id:
                return e
        return None

    def verify_integrity(self):
        """Returns (ok: bool, first_bad_index: int or None)."""
        prev = GENESIS
        for i, e in enumerate(self.chain):
            if e["prev_hash"] != prev:
                return False, i
            expected = _entry_hash(
                prev,
                e["voter_id"],
                e["ciphertext"],
                e["election_id"],
                e["timestamp"],
                e["voter_sig"],
            )
            if expected != e["hash"]:
                return False, i
            prev = e["hash"]
        return True, None
