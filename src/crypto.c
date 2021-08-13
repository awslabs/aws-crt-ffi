
#include "crt.h"

#if defined(AWS_OS_LINUX)
#    include <openssl/crypto.h>
#    include <s2n.h>

void aws_crt_crypto_share(void) {
    /* Prevent s2n from initializing or de-initializing crypto */
    s2n_crypto_disable_init();
}

void init_crypto(void) {
    /*
     * OpenSSL prior to 1.1.x has idempotency issues with initialization and shutdown.
     * We initialize it minimally ourselves here, since s2n has been told not to.
     * Cleanup is handled by OpenSSL's atexit handler
     */
#    if !S2N_OPENSSL_VERSION_AT_LEAST(1, 1, 0)
    OPENSSL_add_all_algorithms();
#    else
    OPENSSL_init_crypto(
        OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS |
            OPENSSL_INIT_NO_ATEXIT,
        NULL);
#    endif
}

void shutdown_crypto(void) {}

#else
void aws_crt_crypto_share(void) {}
void init_crypto(void) {}
void shutdown_crypto(void) {}
#endif
