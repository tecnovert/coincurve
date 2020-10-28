from coincurve.dleag import dleag_prove, dleag_verify
from coincurve.ed25519 import get_valid_secret
from coincurve.keys import PrivateKey, PublicKey


class TestDLEAG:
    def test_dleag(self):
        secret = get_valid_secret()
        private_key = PrivateKey(secret)
        proof = dleag_prove(private_key)

        assert True == dleag_verify(proof)
