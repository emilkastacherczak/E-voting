"""Certificate Authority: signs certificates binding a voter id to a public key.

Differences from the original:
- The CA refuses to issue two certificates for the same voter_id.
- It maintains a revocation list.
- It carries a human-readable name so a "rogue CA" is clearly distinguishable
  in logs and the GUI.

Certificate format:
  {"voter_id", "voter_pub", "ca_name", "ca_sig"}
"""

import rsa_sig


def cert_payload(cert):
    """Bytes signed by the CA. Includes ca_name so two CAs can't sign the
    same logical certificate."""
    pub = cert["voter_pub"]
    return (
        f"{cert['ca_name']}|{cert['voter_id']}|{pub['n']}|{pub['e']}"
    ).encode()


class CA:
    def __init__(self, name="CentralCA", bits=512):
        self.name = name
        self.pub, self.priv = rsa_sig.keygen(bits)
        self.issued = {}      # voter_id -> cert
        self.revoked = set()  # voter_id

    def issue(self, voter_id, voter_pub):
        if voter_id in self.issued:
            raise ValueError(f"CA already issued a certificate for {voter_id!r}")
        cert = {
            "voter_id": voter_id,
            "voter_pub": voter_pub,
            "ca_name": self.name,
            "ca_sig": 0,
        }
        cert["ca_sig"] = rsa_sig.sign(self.priv, cert_payload(cert))
        self.issued[voter_id] = cert
        return cert

    def revoke(self, voter_id):
        self.revoked.add(voter_id)

    def verify(self, cert):
        """A cert is valid iff:
        - it claims to be from this CA (ca_name matches our name), and
        - the signature checks out under our public key, and
        - the voter_id is not on the revocation list.
        Mismatching ca_name => verification fails (rogue CA defense)."""
        if not isinstance(cert, dict):
            return False
        if cert.get("ca_name") != self.name:
            return False
        if cert.get("voter_id") in self.revoked:
            return False
        try:
            return rsa_sig.verify(self.pub, cert_payload(cert), cert["ca_sig"])
        except (KeyError, TypeError):
            return False
