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

#define BUFFER_LENGTH 4096

int main()
{
	int fdchannel_b_c;
	if( (fdchannel_b_c = open("/tmp/unsecured-channel-c-b", O_RDONLY)) == -1) {
		printf("Error opening pipe %s, exit\n","/tmp/unsecured-channel-b-c");
		return -1;	
	}
	
	char msg_from_alice[BUFFER_LENGTH];
	read(fdchannel_b_c,  msg_from_alice, BUFFER_LENGTH);
	
	printf("[bob     ] from alice: %s\n", msg_from_alice);
	
	if(!strcmp(msg_from_alice,"MY NAME IS ALICE")) {
	      int fdchannel_b_c;
	      if( (fdchannel_b_c = open("/tmp/unsecured-channel-b-c", O_WRONLY)) == -1) {
		      printf("Error opening pipe %s, exit\n","/tmp/unsecured-channel-b-c");
		      return -1;	
	      }
	      char msg_to_alice[BUFFER_LENGTH] = "WELCOME ALICE";
	      printf("[bob] to alice  : %s\n", msg_to_alice);
	      write(fdchannel_b_c,  msg_to_alice, sizeof(msg_to_alice));
	}else{
	      int fdchannel_b_c;
	      if( (fdchannel_b_c = open("/tmp/unsecured-channel-b-c", O_WRONLY)) == -1) {
		      printf("Error opening pipe %s, exit\n","/tmp/unsecured-channel-b-c");
		      return -1;	
	      }
	      char msg_to_alice[BUFFER_LENGTH] = "YOU ARE NOT ALICE";
	      printf("[bob     ] to alice  : %s\n", msg_to_alice);
	      write(fdchannel_b_c,  msg_to_alice, sizeof(msg_to_alice));	
	}
	
	return 0;
}
