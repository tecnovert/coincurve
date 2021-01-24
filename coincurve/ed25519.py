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


def ed25519_get_pubkey(privkey):
    pubkey_output = ffi.new('unsigned char[{}]'.format(32))
    privkey_le = privkey[::-1]
    rv = lib.crypto_scalarmult_ed25519_base_noclamp(pubkey_output, privkey_le)
    assert(rv == 0)
    return bytes(ffi.buffer(pubkey_output, 32))


def ed25519_scalar_add(x, y):
    output = ffi.new('unsigned char[{}]'.format(32))
    x_le = x[::-1]
    y_le = y[::-1]
    lib.crypto_core_ed25519_scalar_add(output, x_le, y_le)
    return bytes(ffi.buffer(output, 32))[::-1]


def ed25519_add(x, y):
    output = ffi.new('unsigned char[{}]'.format(32))
    rv = lib.crypto_core_ed25519_add(output, x, y)
    assert(rv == 0)
    return bytes(ffi.buffer(output, 32))


class Ed25519PrivateKey:
    def __init__(self, secret=None, context=GLOBAL_CONTEXT):
        self.context = context


class Ed25519PublicKey:
    def __init__(self, data, context=GLOBAL_CONTEXT):
        self.context = context
