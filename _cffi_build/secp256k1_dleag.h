
size_t secp256k1_dleag_size(size_t n_bits);

int secp256k1_dleag_prove(
    const secp256k1_context *ctx,
    unsigned char *proof_out,
    size_t *proof_len,              /* Input length of proof_out buffer, output length of proof. */
    const unsigned char *key,       /* 32 bytes */
    size_t n_bits,
    const unsigned char *nonce,     /* 32 bytes */
    const secp256k1_generator *gen_s_a,
    const secp256k1_generator *gen_s_b,
    const unsigned char *gen_e_a,
    const unsigned char *gen_e_b
);

int secp256k1_dleag_verify(
    const secp256k1_context *ctx,
    const unsigned char *proof,
    size_t proof_len,
    const secp256k1_generator *gen_s_a,
    const secp256k1_generator *gen_s_b,
    const unsigned char *gen_e_a,
    const unsigned char *gen_e_b
);
