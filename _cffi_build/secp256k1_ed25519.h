extern const unsigned char ed25519_gen[32];
extern const unsigned char ed25519_gen2[32];

int crypto_scalarmult_ed25519_base_noclamp(unsigned char *q, const unsigned char *n);
