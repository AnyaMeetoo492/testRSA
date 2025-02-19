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
	char subject_name1[4096];
	mbedtls_x509_csr csr1;
	mbedtls_x509_csr_init( &csr1);
	mbedtls_x509_csr_parse_file(&csr1,"/home/meetoo/Bureau/ISS/2-DEVICE-CSR/device1.csr");
	mbedtls_x509_dn_gets(subject_name1,sizeof(subject_name1),&csr1.subject );
	mbedtls_pk_context *csr_pkey1 = &csr1.pk;
	
	/** Generation of the certificate **/

	mbedtls_x509write_cert crt1;
	mbedtls_x509write_crt_init( &crt1);

	mbedtls_mpi cert_serial1;
	mbedtls_mpi_init(&cert_serial1);
	mbedtls_mpi_read_string (&cert_serial1, 10, "1");	

	mbedtls_x509write_crt_set_subject_key(&crt1, &pkey);
	mbedtls_x509write_crt_set_issuer_key (&crt1,&skey);
	mbedtls_x509write_crt_set_subject_name(&crt1,subject_name1);
	mbedtls_x509write_crt_set_issuer_name (&crt1,"CN=MSIoT CA, OU=MSIoT CA Team, O=MSIoT, L=Toulouse, S=Haute-Garonne, C=FR");
	mbedtls_x509write_crt_set_version(&crt1, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg( &crt1, MBEDTLS_MD_SHA256 );
	mbedtls_x509write_crt_set_serial(&crt1, &cert_serial1);
	
	mbedtls_x509write_crt_set_validity(&crt1, "20200201000000", "20251231235959");

	mbedtls_x509write_crt_set_basic_constraints(&crt1,0,-1);
	mbedtls_x509write_crt_set_subject_key_identifier  (&crt1);
	mbedtls_x509write_crt_set_authority_key_identifier(&crt1);
	mbedtls_x509write_crt_set_key_usage   (&crt1, MBEDTLS_X509_KU_KEY_AGREEMENT);
	mbedtls_x509write_crt_set_ns_cert_type(&crt1, MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER);

	/** Generation of the self-signed CA certificate in PEM format **/
	
	unsigned char cert_str1[4096];
	mbedtls_x509write_crt_pem(&crt1,cert_str1,4096,mbedtls_ctr_drbg_random,&ctr_drbg);
	size_t cert_str_len1 = strlen((const char*)cert_str1);
	FILE* pem_file1 = fopen( "device1.crt", "w" );
	fwrite( cert_str1, 1, cert_str_len1, pem_file1 );
	fclose( pem_file1 );

	/** Load csr **/
	char subject_name2[4096];
	mbedtls_x509_csr csr2;
	mbedtls_x509_csr_init( &csr2);
	mbedtls_x509_csr_parse_file(&csr2,"/home/meetoo/Bureau/ISS/2-DEVICE-CSR/device2.csr");
	mbedtls_x509_dn_gets(subject_name2,sizeof(subject_name2),&csr2.subject );
	mbedtls_pk_context *csr_pkey2 = &csr2.pk;
	
	/** Generation of the certificate **/

	mbedtls_x509write_cert crt2;
	mbedtls_x509write_crt_init( &crt2);

	mbedtls_mpi cert_serial2;
	mbedtls_mpi_init(&cert_serial2);
	mbedtls_mpi_read_string (&cert_serial2, 10, "1");	

	mbedtls_x509write_crt_set_subject_key(&crt2, &pkey);
	mbedtls_x509write_crt_set_issuer_key (&crt2,&skey);
	mbedtls_x509write_crt_set_subject_name(&crt2,subject_name2);
	mbedtls_x509write_crt_set_issuer_name (&crt2,"CN=MSIoT CA, OU=MSIoT CA Team, O=MSIoT, L=Toulouse, S=Haute-Garonne, C=FR");
	mbedtls_x509write_crt_set_version(&crt2, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg( &crt2, MBEDTLS_MD_SHA256 );
	mbedtls_x509write_crt_set_serial(&crt2, &cert_serial2);
	
	mbedtls_x509write_crt_set_validity(&crt2, "20200201000000", "20251231235900");

	mbedtls_x509write_crt_set_basic_constraints(&crt2,0,-1);
	mbedtls_x509write_crt_set_subject_key_identifier  (&crt2);
	mbedtls_x509write_crt_set_authority_key_identifier(&crt2);
	mbedtls_x509write_crt_set_key_usage   (&crt2, MBEDTLS_X509_KU_KEY_AGREEMENT);
	mbedtls_x509write_crt_set_ns_cert_type(&crt2, MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER);

	/** Generation of the self-signed CA certificate in PEM format **/
	
	unsigned char cert_str2[4096];
	mbedtls_x509write_crt_pem(&crt2,cert_str2,4096,mbedtls_ctr_drbg_random,&ctr_drbg);
	size_t cert_str_len2 = strlen((const char*)cert_str2);
	FILE* pem_file2 = fopen( "device2.crt", "w" );
	fwrite( cert_str2, 1, cert_str_len2, pem_file2 );
	fclose( pem_file2 );

	/** Free **/

	mbedtls_pk_free (&pkey);
	mbedtls_pk_free (&skey);

	mbedtls_x509_csr_free(&csr1);
	mbedtls_x509write_crt_free( &csr1);
	
	mbedtls_x509_csr_free(&csr2);
	mbedtls_x509write_crt_free( &csr2);

	mbedtls_rsa_free( &rsa );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	

	return 0;
}
