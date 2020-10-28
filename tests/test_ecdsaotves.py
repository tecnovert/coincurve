import sys
from coincurve.ecdsaotves import ecdsaotves_enc_sign, ecdsaotves_enc_verify, ecdsaotves_dec_sig, ecdsaotves_rec_enc_key
from coincurve.keys import PrivateKey, PublicKey
from coincurve.utils import get_valid_secret, sha256


class TestECDSAOTVES:
    def test_ecdsaotves(self):
        secret_sign = get_valid_secret()
        secret_encrypt = get_valid_secret()

        pk_sign = PublicKey.from_secret(secret_sign)
        pk_encrypt = PublicKey.from_secret(secret_encrypt)
        pk_sb = pk_sign.format()
        pk_eb = pk_encrypt.format()

        message = 'otves message'
        if sys.version_info[0] > 2:
            message_hash = sha256(bytes(message, 'utf-8'))
        else:
            message_hash = sha256(message)

        ct = ecdsaotves_enc_sign(secret_sign, pk_eb, message_hash)

        assert ecdsaotves_enc_verify(pk_sb, pk_eb, message_hash, ct)

        sig = ecdsaotves_dec_sig(secret_encrypt, ct)

        assert pk_sign.verify(sig, message_hash, hasher=None)

        secret_rec = ecdsaotves_rec_enc_key(pk_eb, ct, sig)

        assert secret_rec == secret_encrypt
