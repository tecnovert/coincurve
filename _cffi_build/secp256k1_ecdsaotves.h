int ecdsaotves_enc_sign(
    const secp256k1_context *ctx,
    unsigned char *ct_out,
    const unsigned char *skS,
    const unsigned char *pkE,
    const unsigned char *msg32
);

int ecdsaotves_enc_verify(
    const secp256k1_context *ctx,
    const unsigned char *pkS,
    const unsigned char *pkE,
    const unsigned char *msg32,
    const unsigned char *ct
);

int ecdsaotves_dec_sig(
    const secp256k1_context *ctx,
    unsigned char *sig_out,
    size_t *sig_length,
    const unsigned char *skE,
    const unsigned char *ct
);

int ecdsaotves_rec_enc_key(
    const secp256k1_context *ctx,
    unsigned char *key_out,
    const unsigned char *pkE,
    const unsigned char *ct,
    const unsigned char *dersig,
    size_t sig_length
);
