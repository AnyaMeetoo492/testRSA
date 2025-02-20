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

int main()
{
	mbedtls_x509_crt trust_ca,device_ctr,other_trust_ca;
	mbedtls_x509_crt_init(&trust_ca);
	mbedtls_x509_crt_init(&device_ctr);
	mbedtls_x509_crt_parse_file(&trust_ca  ,"../1-CA-CERT/ca.crt");
	mbedtls_x509_crt_parse_file(&device_ctr,"../3-CA-SIGN/device.crt");
	
	uint32_t verification_flags;
	if(mbedtls_x509_crt_verify(&device_ctr,
				    &trust_ca,
				    NULL,
				    NULL,
				    &verification_flags,
				    NULL, NULL ))
	{
		printf("Device verification failed\n");
	}else{
		printf("Well Done! Authentication succeeded\n");
	}
	return 0;
}
