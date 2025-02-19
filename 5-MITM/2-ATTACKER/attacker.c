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
        // ALICE MESSAGE INTERCEPTION
        
	int fdchannel_a_c;
	if( (fdchannel_a_c = open("/tmp/unsecured-channel-a-c", O_RDONLY)) == -1) {
		printf("Error opening pipe %s, exit\n","/tmp/unsecured-channel-a-c");
		return -1;	
	}
	
	char msg_from_alice[BUFFER_LENGTH];
	read(fdchannel_a_c,  msg_from_alice, BUFFER_LENGTH);
	
	printf("[attacker] from alice: %s\n", msg_from_alice);
	
	
	int fdchannel_b_c;
	if( (fdchannel_b_c = open("/tmp/unsecured-channel-c-b", O_WRONLY)) == -1) {
		printf("Error opening pipe %s, exit\n","/tmp/unsecured-channel-b-c");
		return -1;	
	}
	
	char msg_to_bob[BUFFER_LENGTH] = "MY NAME IS 4L1C3";
	printf("[attacker] to bob    : %s\n", msg_to_bob);
	write(fdchannel_b_c ,  msg_to_bob, sizeof(msg_to_bob));
	
	// BOB MESSAGE INTERCEPTION
	
	if( (fdchannel_b_c = open("/tmp/unsecured-channel-b-c", O_RDONLY)) == -1) {
		printf("Error opening pipe %s, exit\n","/tmp/unsecured-channel-b-c");
		return -1;	
	}
	char msg_from_bob[BUFFER_LENGTH];
	read(fdchannel_b_c,  msg_from_bob, BUFFER_LENGTH);
	
	printf("[attacker] from bob  : %s\n",msg_from_bob);
	
	if( (fdchannel_a_c = open("/tmp/unsecured-channel-c-a", O_WRONLY)) == -1) {
		printf("Error opening pipe %s, exit\n","/tmp/unsecured-channel-a-c");
		return -1;	
	}
		
	printf("[attacker] to alice  : %s\n",msg_from_bob);
	write(fdchannel_a_c,  msg_from_bob, sizeof(msg_from_bob));
	//fclose(fdchannel_a_c);
	
	return 0;
}
