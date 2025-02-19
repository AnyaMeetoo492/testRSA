#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>

#define BUFFER_LENGTH 4096

int main() {
    // Load CA certificate
    mbedtls_x509_crt trust_ca, device_ctr;
    mbedtls_x509_crt_init(&trust_ca);
    mbedtls_x509_crt_init(&device_ctr);

    mbedtls_x509_crt_parse_file(&trust_ca, "/home/meetoo/Bureau/ISS/1-CA-CERT/ca.crt");
    mbedtls_x509_crt_parse_file(&device_ctr, "/home/meetoo/Bureau/ISS/3-CA-SIGN/device1.crt");

    // Open pipeline to Bob
    int fdchannel_a_c;
    if ((fdchannel_a_c = open("/tmp/unsecured-channel-a-c", O_WRONLY)) == -1) {
        printf("Error opening pipe %s, exit\n", "/tmp/unsecured-channel-a-c");
        return -1;
    }

    // Send Alice's certificate to Bob
    char crt_to_bob[BUFFER_LENGTH];
    size_t crt_len = device_ctr.raw.len;
    if (crt_len > BUFFER_LENGTH) {
        printf("Certificate is too large to fit into the buffer\n");
        return -1;
    }
    memcpy(crt_to_bob, device_ctr.raw.p, crt_len);
    printf("Sending Alice's certificate to Bob\n");
    write(fdchannel_a_c, crt_to_bob, crt_len);

    // Encrypt message with Alice's public key (just for demonstration)
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    char message[] = "Hello Bob!";
    char encrypted_message[BUFFER_LENGTH];
    size_t encrypted_len;
    int ret = mbedtls_rsa_rsaes_oaep_encrypt(mbedtls_pk_rsa(device_ctr.pk),
                                             mbedtls_ctr_drbg_random, &ctr_drbg,
                                             MBEDTLS_RSA_PUBLIC, NULL, 0,
                                             strlen(message), message,
                                             encrypted_message);
    if (ret != 0) {
        printf("Encryption failed\n");
        return -1;
    }

    // Send the encrypted message
    printf("Sending encrypted message to Bob\n");
    write(fdchannel_a_c, encrypted_message, encrypted_len);

    return 0;
}
