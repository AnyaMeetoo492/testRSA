#include <regex.h>
#include <inttypes.h>

#include <signal.h> 
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>

#define MESSAGE_MAXIMUM_LEN 256
int main()
{
        /** Initialization of entropy and drbg contexts **/
        
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init( &entropy );
	
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg,            // DRGB context structure
			      mbedtls_entropy_func, // Use the default Entropy source extractor function
			      &entropy,             // Entropy context structure
			      NULL,                 // Personalization data, can be NULL
			      0);                   // Length of the Personalization data
	
	/** Encryption **/
	
	mbedtls_x509_crt device_ctr;
	
	mbedtls_x509_crt_init      (&device_ctr);
	mbedtls_x509_crt_parse_file(&device_ctr,"device.crt");
	mbedtls_rsa_set_padding    (mbedtls_pk_rsa(device_ctr.pk), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
	
	char message[] = "HELLO";
	char ptx[MESSAGE_MAXIMUM_LEN], ctx[MESSAGE_MAXIMUM_LEN];

	int res = mbedtls_rsa_rsaes_oaep_encrypt(mbedtls_pk_rsa(device_ctr.pk),
	                    mbedtls_ctr_drbg_random,&ctr_drbg, // drbg function to use
                            MBEDTLS_RSA_PUBLIC,                // Public encryption
                            NULL,0,                            // Custom label (none here)
                            strlen(message),
                            message,
                            ctx);
        
        /** Decryption **/
        
	mbedtls_pk_context skey;
	mbedtls_pk_init         (&skey);
	mbedtls_pk_parse_keyfile(&skey, "device-private-key.pem",	 NULL); 
	mbedtls_rsa_set_padding (mbedtls_pk_rsa(skey),MBEDTLS_RSA_PKCS_V21 , MBEDTLS_MD_SHA256);
	
        int ptx_len;
	mbedtls_rsa_rsaes_oaep_decrypt(mbedtls_pk_rsa(skey),
                            mbedtls_ctr_drbg_random,&ctr_drbg, // drbg function to use
                            MBEDTLS_RSA_PRIVATE,               // Private decryption
                            NULL,0,                            // Custom label (none here)
                            &ptx_len,
                            ctx,
                            ptx,
                            MESSAGE_MAXIMUM_LEN);
                            
        ptx[ptx_len] = '\0';
            
        printf("message: %s. decrypted message: %s\n",message, ptx);
	/** free **/

	mbedtls_x509_crt_free(&device_ctr);
	mbedtls_pk_free      (&skey);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free (&entropy);

	return 0;
}
