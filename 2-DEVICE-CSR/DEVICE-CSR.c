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
#include <mbedtls/x509_csr.h>

int main()
{

	/** Must be completed **/
	mbedtls_pk_context pk;
	mbedtls_pk_init (&pk);

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init( &ctr_drbg );

	mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

	mbedtls_rsa_context rsa;
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

	/** Initialization of the CSR **/
	mbedtls_x509write_csr csr;
	mbedtls_x509write_csr_init( &csr );

		/** Certificate signing request **/
	mbedtls_x509write_csr_set_subject_name(&csr,"CN=My Device, OU=MSIoT Crypto Team, O=MSIoT, L=Toulouse, S=Haute-Garonne, C=FR");
	mbedtls_x509write_csr_set_key(&csr, &pk);
	mbedtls_x509write_csr_set_md_alg( &csr, MBEDTLS_MD_SHA256 );

	/** Generation of csr in PEM format **/
	unsigned char csr_str[4096];
	mbedtls_x509write_csr_pem(&csr,csr_str,4096,mbedtls_ctr_drbg_random,&ctr_drbg);
	size_t csr_str_len = strlen((const char*)csr_str);
	FILE* pem_file = fopen( "device.csr", "w" );
	fwrite( csr_str, 1, csr_str_len, pem_file );
	fclose( pem_file );

	/** free **/
	mbedtls_x509write_csr_free( &csr );
	mbedtls_pk_free (&pk);
	mbedtls_rsa_free( &rsa );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	
	return 0;
}
