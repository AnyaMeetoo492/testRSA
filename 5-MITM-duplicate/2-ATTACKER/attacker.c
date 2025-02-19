#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define BUFFER_LENGTH 4096

int main() {
    // The attacker intercepts the communication and attempts to modify or fake the message.
    
    // Simulate intercepting the message from Alice to Bob
    int fdchannel_a_c;
    char intercepted_message[BUFFER_LENGTH];
    int bytes_read = read(fdchannel_a_c, intercepted_message, BUFFER_LENGTH);

    if (bytes_read > 0) {
        printf("Attacker intercepted message: %s\n", intercepted_message);

        // Modify the message (for example, replacing Alice's message with a fake one)
        char modified_message[] = "Modified message from Alice!";

        // Send the modified message to Bob
        write(fdchannel_a_c, modified_message, strlen(modified_message));
    }

    return 0;
}
