#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>

#define __NR_recv_msg    551
#define __NR_send_msg    550

#define RX_MSG_SIZE      10

long recv_msg(int q_id, char *msg, size_t msglen) {
    return syscall(__NR_recv_msg, q_id, msg, msglen);
}

long send_msg(int q_id, const char *msg, size_t msglen) {
    return syscall(__NR_send_msg, q_id, msg, msglen);
}

int main(int argc, char *argv[]) {
    char message[RX_MSG_SIZE];
    const char *ack_message = "ack";
    int queue_id;
    
    if (argc == 2)
    	queue_id = atoi(argv[0]);
    else
    	queue_id = 0;

   // Receive a message
    if (recv_msg(queue_id, message, RX_MSG_SIZE) < 0) {
        perror("recv_msg failed");
        return EXIT_FAILURE;
    }

    printf("Message received: %s\n", message);

    // Send acknowledgment
    if (send_msg(queue_id, ack_message, strlen(ack_message)) < 0) {
        perror("send_msg failed");
        return EXIT_FAILURE;
    }

    printf("Acknowledgment sent: %s\n", ack_message);

    return EXIT_SUCCESS;
}