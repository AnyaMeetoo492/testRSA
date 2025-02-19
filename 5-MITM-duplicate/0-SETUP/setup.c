#include <regex.h>
#include <inttypes.h>

#include <signal.h> 
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509_crt.h>


int main()
{
	unlink("/tmp/unsecured-channel-a-c");
	unlink("/tmp/unsecured-channel-b-c");
	unlink("/tmp/unsecured-channel-c-a");
	unlink("/tmp/unsecured-channel-c-b");
	mkfifo("/tmp/unsecured-channel-a-c",0760);
	mkfifo("/tmp/unsecured-channel-b-c",0760);
	mkfifo("/tmp/unsecured-channel-c-a",0760);
	mkfifo("/tmp/unsecured-channel-c-b",0760);
	return 0;
}
