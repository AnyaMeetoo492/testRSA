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
#include <mbedtls/x509_csr.h>
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
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

	/** Initialization of the PK context **/
	mbedtls_pk_context pkey,skey;
	mbedtls_pk_init (&pkey);
	mbedtls_pk_init (&skey);
	
	/** Read RSA parameters **/	
	mbedtls_pk_parse_keyfile       (&skey, "/home/meetoo/Bureau/ISS/1-CA-CERT/ca-signature-private-key.pem", NULL); 
	mbedtls_pk_parse_public_keyfile(&pkey, "/home/meetoo/Bureau/ISS/1-CA-CERT/ca-signature-public-key.pem");

	if(mbedtls_pk_check_pair(&pkey,&skey)) 
	{
		printf("key-pair error\n");
		return 1;
	}

	/** Load csr **/
	char subject_name[4096];
	mbedtls_x509_csr csr;
	mbedtls_x509_csr_init( &csr);
	mbedtls_x509_csr_parse_file(&csr,"/home/meetoo/Bureau/ISS/2-DEVICE-CSR/device.csr");
	mbedtls_x509_dn_gets(subject_name,sizeof(subject_name),&csr.subject );
	mbedtls_pk_context *csr_pkey = &csr.pk;
	
	/** Generation of the certificate **/
	mbedtls_x509write_cert crt;
	mbedtls_x509write_crt_init( &crt);

	mbedtls_mpi cert_serial;
	mbedtls_mpi_init(&cert_serial);
	mbedtls_mpi_read_string (&cert_serial, 10, "1");	

	mbedtls_x509write_crt_set_subject_key(&crt, &pkey);
	mbedtls_x509write_crt_set_issuer_key (&crt,&skey);
	mbedtls_x509write_crt_set_subject_name(&crt,subject_name);
	mbedtls_x509write_crt_set_issuer_name (&crt,"CN=MSIoT CA, OU=MSIoT CA Team, O=MSIoT, L=Toulouse, S=Haute-Garonne, C=FR");
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg( &crt, MBEDTLS_MD_SHA256 );
	mbedtls_x509write_crt_set_serial(&crt, &cert_serial);
	
	mbedtls_x509write_crt_set_validity(&crt, "20200201000000", "20251231235959");

	mbedtls_x509write_crt_set_basic_constraints(&crt,0,-1);
	mbedtls_x509write_crt_set_subject_key_identifier  (&crt);
	mbedtls_x509write_crt_set_authority_key_identifier(&crt);
	mbedtls_x509write_crt_set_key_usage   (&crt, MBEDTLS_X509_KU_KEY_AGREEMENT);
	mbedtls_x509write_crt_set_ns_cert_type(&crt, MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER);

	/** Generation of the self-signed CA certificate in PEM format **/
	unsigned char cert_str[4096];
	mbedtls_x509write_crt_pem(&crt,cert_str,4096,mbedtls_ctr_drbg_random,&ctr_drbg);
	size_t cert_str_len = strlen((const char*)cert_str);
	FILE* pem_file = fopen( "device.crt", "w" );
	fwrite( cert_str, 1, cert_str_len, pem_file );
	fclose( pem_file );

	/** Free **/
	mbedtls_pk_free (&pkey);
	mbedtls_pk_free (&skey);
	mbedtls_x509_csr_free(&csr);
	mbedtls_x509write_crt_free( &csr);
	mbedtls_rsa_free( &rsa );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	

	return 0;
}
