// recv_and_acknowledge.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>

#define RX_MSG_SIZE      10

#if 0
#define __NR_recv_msg    551
#define __NR_send_msg    550

long recv_msg(int q_id, char *msg, size_t msglen) {
    return syscall(__NR_recv_msg, q_id, msg, msglen);
}

long send_msg(int q_id, const char *msg, size_t msglen) {
    return syscall(__NR_send_msg, q_id, msg, msglen);
}
#endif

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <queue_id>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int queue_id = atoi(argv[1]);
    char message[RX_MSG_SIZE];
    const char *ack_message = "ack";

    // Receive the message from the specified queue
    if (recv_msg(queue_id, message, RX_MSG_SIZE) < 0) {
        perror("recv_msg failed");
        return EXIT_FAILURE;
    }

    printf("Received message: %s\n", message);

    // Send acknowledgment back to the queue
    if (send_msg(queue_id, ack_message, strlen(ack_message)) < 0) {
        perror("send_msg failed");
        return EXIT_FAILURE;
    }

    printf("Acknowledgment sent: %s\n", ack_message);

    return EXIT_SUCCESS;
}
