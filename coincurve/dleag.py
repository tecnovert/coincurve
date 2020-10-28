from coincurve.context import GLOBAL_CONTEXT
from coincurve.flags import EC_COMPRESSED, EC_UNCOMPRESSED
from ._libsecp256k1 import ffi, lib


def dleag_proof_len(bits=252):
    return lib.secp256k1_dleag_size(bits)


def get_nonce():
    try:
        import secrets

        return secrets.token_bytes(32)
    except Exception:
        from os import urandom

        return urandom(32)


def dleag_prove(private_key, context=GLOBAL_CONTEXT):
    proof_length = dleag_proof_len()
    proof_output = ffi.new('unsigned char[{}]'.format(proof_length))

    proof_length_p = ffi.new('size_t *')
    proof_length_p[0] = proof_length

    # nonce_bytes = ffi.from_buffer(secrets.token_bytes(32))
    nonce_bytes = get_nonce()
    rv = lib.secp256k1_dleag_prove(
        context.ctx,
        proof_output,
        proof_length_p,
        private_key.secret,
        252,
        nonce_bytes,
        ffi.addressof(lib.secp256k1_generator_const_g),
        ffi.addressof(lib.secp256k1_generator_const_h),
        lib.ed25519_gen,
        lib.ed25519_gen2,
    )

    if rv != 1:
        raise ValueError('secp256k1_dleag_prove failed')

    # TODO: How to clear memory? Add random module to secp256k1?
    # ffi.memmove(nonce_bytes, bytes([0] * 32), 32)
    return bytes(ffi.buffer(proof_output, proof_length))


def dleag_verify(proof, context=GLOBAL_CONTEXT):
    proof_bytes = ffi.from_buffer(proof)
    proof_length = len(proof)

    rv = lib.secp256k1_dleag_verify(
        context.ctx,
        proof_bytes,
        proof_length,
        ffi.addressof(lib.secp256k1_generator_const_g),
        ffi.addressof(lib.secp256k1_generator_const_h),
        lib.ed25519_gen,
        lib.ed25519_gen2,
    )

    return True if rv == 1 else False
