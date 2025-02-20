
#include <regex.h>
#include <inttypes.h>

#include <signal.h> 
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// POSIX library
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>


// mbedtls library
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>

int main()
{
	

	/** Initialization of the Entropy context **/
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init( &entropy );

	/** Initialization of the DRBG context **/
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_ctr_drbg_seed(&ctr_drbg,
			      mbedtls_entropy_func,
			      &entropy,
			      NULL,
			      0);

	/** Initialization of the RSA context **/
	mbedtls_rsa_context rsa;
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

	/** Initialization of the PK context **/
	mbedtls_pk_context pk;
	mbedtls_pk_init (&pk);
	mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA) );

	/** Generation of RSA parameters **/
	mbedtls_rsa_gen_key(mbedtls_pk_rsa( pk ), 
			    mbedtls_ctr_drbg_random,
			    &ctr_drbg,
			    2048,
			    65537);
			    
	/** Generation of the Certification Authority Self-Signed Certificate **/
	mbedtls_x509write_cert crt;
	mbedtls_x509write_crt_init( &crt );

	mbedtls_mpi cert_serial;
	mbedtls_mpi_init(&cert_serial);
	mbedtls_mpi_read_string (&cert_serial, 10, "1");

	mbedtls_x509write_crt_set_subject_key(&crt, &pk);
	mbedtls_x509write_crt_set_issuer_key (&crt, &pk);
	mbedtls_x509write_crt_set_subject_name(&crt,"CN=MSIoT CA, OU=MSIoT CA Team, O=MSIoT, L=Toulouse, S=Haute-Garonne, C=FR");
	mbedtls_x509write_crt_set_issuer_name (&crt,"CN=MSIoT CA, OU=MSIoT CA Team, O=MSIoT, L=Toulouse, S=Haute-Garonne, C=FR");
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg( &crt, MBEDTLS_MD_SHA256 );
	mbedtls_x509write_crt_set_serial(&crt, &cert_serial);
	
	mbedtls_x509write_crt_set_validity(&crt, 
					   "20200201000000",
					   "20310131235959");

	mbedtls_x509write_crt_set_basic_constraints(&crt,
						    1,   // Is a CA certificate ?
						    -1); // Max number of sub-CA (-1 -> none)
	mbedtls_x509write_crt_set_subject_key_identifier(&crt);
	mbedtls_x509write_crt_set_authority_key_identifier(&crt);
	mbedtls_x509write_crt_set_key_usage(&crt,MBEDTLS_X509_KU_KEY_CERT_SIGN);
	mbedtls_x509write_crt_set_ns_cert_type(&crt,MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA);

	/** Generation of the CA certificate in PEM format **/
	
	unsigned char cert_str[4096];
	mbedtls_x509write_crt_pem(&crt,cert_str,4096,mbedtls_ctr_drbg_random,&ctr_drbg);
	size_t cert_str_len = strlen((const char*)cert_str);
	FILE* pem_file = fopen( "ca.crt", "w" );
	fwrite( cert_str, 1, cert_str_len, pem_file );
	fclose( pem_file );

	/** Copy of the RSA secret key in PEM format **/

	unsigned char skey_str[4096];
	memset(skey_str, 0, 4096);
	mbedtls_pk_write_key_pem(&pk, skey_str, 4096 );
	size_t skey_len = strlen((const char*)skey_str);
	FILE* skey_file = fopen( "ca-signature-private-key.pem", "w" );
	fwrite( skey_str, 1, skey_len, skey_file );
	fclose( skey_file );

	/** Copy of the RSA public key in PEM format **/

	unsigned char pkey_str[4096];
	memset(pkey_str, 0, 4096);
	mbedtls_pk_write_pubkey_pem(&pk, pkey_str, 4096 );
	size_t pkey_len = strlen((const char*)pkey_str);
	FILE* pkey_file = fopen( "ca-signature-public-key.pem", "w" );
	fwrite( pkey_str, 1, pkey_len, pkey_file );
	fclose( pkey_file );

	
	/** free **/

	mbedtls_x509write_crt_free( &crt );
	mbedtls_mpi_free(&cert_serial);
	

	return 0;
}
