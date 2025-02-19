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
    mbedtls_x509_crt_parse_file(&device_ctr, "/home/meetoo/Bureau/ISS/3-CA-SIGN/device2.crt");

    // Open channel to communicate (read from Alice)
    int fdchannel_b_c;
    if ((fdchannel_b_c = open("/tmp/unsecured-channel-c-b", O_RDONLY)) == -1) {
        printf("Error opening pipe %s, exit\n", "/tmp/unsecured-channel-c-b");
        return -1;
    }

    // Receive certificate from Alice
    char crt_from_alice[BUFFER_LENGTH];
    int bytes_read = read(fdchannel_b_c, crt_from_alice, BUFFER_LENGTH);
    if (bytes_read <= 0) {
        printf("Error or no data received from Alice\n");
        return -1;
    }
    printf("Received certificate from Alice\n");

    // Parse the received certificate into an mbedtls_x509_crt structure
    mbedtls_x509_crt received_cert;
    mbedtls_x509_crt_init(&received_cert);
    if (mbedtls_x509_crt_parse(&received_cert, (const unsigned char *)crt_from_alice, bytes_read) != 0) {
        printf("Failed to parse Alice's certificate\n");
        return -1;
    }

    // Verify the certificate
    uint32_t verification_flags;
    int ret = mbedtls_x509_crt_verify(&received_cert, &trust_ca, NULL, NULL, &verification_flags, NULL, NULL);
    if (ret != 0) {
        printf("Device verification failed\n");
    } else {
        printf("Well Done! Authentication succeeded\n");
    }

    // Initialize the random number generator context (ctr_drbg)
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed the random number generator
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        printf("Failed to seed the random number generator\n");
        return -1;
    }

    // Decrypt the message from Alice (using Bob's private key)
    char encrypted_message[BUFFER_LENGTH];
    char decrypted_message[BUFFER_LENGTH];
    size_t decrypted_len;

    // Read the encrypted message from the pipe
    read(fdchannel_b_c, encrypted_message, BUFFER_LENGTH);

    // Load Bob's private key for decryption
    mbedtls_pk_context skey;
    mbedtls_pk_init(&skey);
    ret = mbedtls_pk_parse_keyfile(&skey, "device2-private-key.pem", NULL);
    if (ret != 0) {
        printf("Failed to parse Bob's private key\n");
        return -1;
    }

    // Set up RSA padding and encryption type
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(skey), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    // Decrypt the message using OAEP
    const unsigned char *label = NULL;  // No label is used for this example
    size_t label_len = 0;
    size_t output_max_len = sizeof(decrypted_message);

    ret = mbedtls_rsa_rsaes_oaep_decrypt(mbedtls_pk_rsa(skey),
                                         mbedtls_ctr_drbg_random, &ctr_drbg,
                                         MBEDTLS_RSA_PRIVATE, label, label_len,
                                         &decrypted_len, encrypted_message,
                                         decrypted_message, output_max_len);
    if (ret != 0) {
        printf("Decryption failed\n");
        return -1;
    }

    // Null-terminate and print the decrypted message
    decrypted_message[decrypted_len] = '\0';
    printf("Decrypted message from Alice: %s\n", decrypted_message);

    // Cleanup
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&skey);
    mbedtls_x509_crt_free(&trust_ca);
    mbedtls_x509_crt_free(&device_ctr);
    mbedtls_x509_crt_free(&received_cert);

    return 0;
}
