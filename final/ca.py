import rsa_sig


def cert_payload(cert):
    pub = cert["voter_pub"]
    return f"{cert['voter_id']}|{pub['n']}|{pub['e']}".encode()


class CA:
    def __init__(self, bits=512):
        self.pub, self.priv = rsa_sig.keygen(bits)

    def issue(self, voter_id, voter_pub):
        cert = {"voter_id": voter_id, "voter_pub": voter_pub, "ca_sig": 0}
        cert["ca_sig"] = rsa_sig.sign(self.priv, cert_payload(cert))
        return cert

    def verify(self, cert):
        return rsa_sig.verify(self.pub, cert_payload(cert), cert["ca_sig"])
