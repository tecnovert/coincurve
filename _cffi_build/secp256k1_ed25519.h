extern const unsigned char ed25519_gen[32];
extern const unsigned char ed25519_gen2[32];

int crypto_scalarmult_ed25519_base_noclamp(unsigned char *q, const unsigned char *n);

int crypto_core_ed25519_add(unsigned char *r,
                            const unsigned char *p, const unsigned char *q);

void crypto_core_ed25519_scalar_add(unsigned char *z, const unsigned char *x,
                                    const unsigned char *y);
