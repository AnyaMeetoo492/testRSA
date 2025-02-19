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
	mbedtls_pk_context pk1;
	mbedtls_pk_init (&pk1);

	mbedtls_pk_context pk2;
	mbedtls_pk_init (&pk2);

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

	mbedtls_x509write_csr_set_subject_name(&csr,"CN=My Device1, OU=MSIoT Crypto Team, O=MSIoT, L=Toulouse, S=Haute-Garonne, C=FR");
	mbedtls_x509write_csr_set_key(&csr, &pk1);
	mbedtls_x509write_csr_set_md_alg( &csr, MBEDTLS_MD_SHA256 );

	/** Generation of csr in PEM format **/
	
	unsigned char csr_str1[4096];
	mbedtls_x509write_csr_pem(&csr,csr_str1,4096,mbedtls_ctr_drbg_random,&ctr_drbg);
	size_t csr_str_len1 = strlen((const char*)csr_str1);
	FILE* pem_file1 = fopen( "device1.csr", "w" );
	fwrite( csr_str1, 1, csr_str_len1, pem_file1 );
	fclose( pem_file1 );

	/** Certificate signing request **/

	mbedtls_x509write_csr_set_subject_name(&csr,"CN=My Device2, OU=MSIoT Crypto Team, O=MSIoT, L=Toulouse, S=Haute-Garonne, C=FR");
	mbedtls_x509write_csr_set_key(&csr, &pk2);
	mbedtls_x509write_csr_set_md_alg( &csr, MBEDTLS_MD_SHA256 );

	/** Generation of csr in PEM format **/
	
	unsigned char csr_str2[4096];
	mbedtls_x509write_csr_pem(&csr,csr_str2,4096,mbedtls_ctr_drbg_random,&ctr_drbg);
	size_t csr_str_len2 = strlen((const char*)csr_str1);
	FILE* pem_file2 = fopen( "device2.csr", "w" );
	fwrite( csr_str2, 1, csr_str_len2, pem_file2 );
	fclose( pem_file2 );

	/** free **/

	mbedtls_x509write_csr_free( &csr );
	mbedtls_pk_free (&pk1);
	mbedtls_pk_free (&pk2);

	mbedtls_rsa_free( &rsa );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	

	return 0;
}
