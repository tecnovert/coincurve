from asn1crypto.keys import ECDomainParameters, ECPointBitString, ECPrivateKey, PrivateKeyAlgorithm, PrivateKeyInfo

from coincurve.context import GLOBAL_CONTEXT
from coincurve.ecdsa import cdata_to_der, der_to_cdata, deserialize_recoverable, recover, serialize_recoverable
from coincurve.flags import EC_COMPRESSED, EC_UNCOMPRESSED
from coincurve.utils import bytes_to_int, int_to_bytes_padded
from ._libsecp256k1 import ffi, lib


DEFAULT_NONCE = (ffi.NULL, ffi.NULL)
GROUP_ORDER_INT = 2 ** 252 + 27742317777372353535851937790883648493


def get_valid_secret():
    try:
        import secrets

        return int_to_bytes_padded(9 + secrets.randbelow(GROUP_ORDER_INT - 9))
    except Exception:
        from os import urandom

        while True:
            secret = urandom(32)
            if 9 < bytes_to_int(secret) < GROUP_ORDER_INT:
                return secret


class Ed25519PrivateKey:
    def __init__(self, secret=None, context=GLOBAL_CONTEXT):
        self.context = context


class Ed25519PublicKey:
    def __init__(self, data, context=GLOBAL_CONTEXT):
        self.context = context
