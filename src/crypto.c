
#include "crt.h"

#if defined(AWS_OS_POSIX) && !defined(AWS_OS_APPLE)
#    include <openssl/crypto.h>
#    include <s2n.h>

void aws_crt_crypto_share(void) {
    /* Prevent s2n from initializing or de-initializing crypto */
    s2n_crypto_disable_init();

#    if !S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 0)
    OPENSSL_add_all_algorithms();
#    else
    OPENSSL_init_crypto(
        OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
#    endif
}

#else
void aws_crt_crypto_share(void) {}
#endif
