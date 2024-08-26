
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>

#if 0
#define __NR_init_queue  549
#define __NR_send_msg    550
#define __NR_recv_msg    551
#define __NR_destroy_queue 552
#endif

#define MAX_MSG_SZ       256
#define RX_MSG_SIZE      10

#if 0
long init_queue() {
    return syscall(__NR_init_queue);
}

long send_msg(int q_id, const char *msg, size_t msglen) {
    return syscall(__NR_send_msg, q_id, msg, msglen);
}

long recv_msg(int q_id, char *msg, size_t msglen) {
    return syscall(__NR_recv_msg, q_id, msg, msglen);
}

long destroy_queue(int q_id) {
    return syscall(__NR_destroy_queue, q_id);
}
#endif
int main() {
    char message[RX_MSG_SIZE] = {0};
    const char *init_message = "sheryar";
    const char *ack_message = "ack";
    pid_t pid;
    int status;

    // Initialize the queue
    long queue_id = init_queue();
    if (queue_id < 0) {
        perror("init_queue failed");
        return EXIT_FAILURE;
    }

    printf("Queue initialized with ID: %ld\n", queue_id);

    // Send a message to the specified queue
    if (send_msg(queue_id, init_message, strlen(init_message)) < 0) {
        perror("send_msg failed");
        return EXIT_FAILURE;
    }

    printf("Message sent: %s\n", init_message);

    // Fork a child process to handle receiving and acknowledging the message
    pid = fork();
    if (pid < 0) {
        perror("fork failed");
        return EXIT_FAILURE;
    }

    if (pid == 0) { // Child process
        char queue_id_str[20];
        snprintf(queue_id_str, sizeof(queue_id_str), "%ld", queue_id);
        execl("./server", "server", queue_id_str, NULL);
        perror("execl failed");
        exit(EXIT_FAILURE);
    } else { // Parent process
        printf("Waiting for acknowledgment...\n");

        // Wait for the child process to finish
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
            // Destroy the queue if acknowledgment is received
            if (destroy_queue(queue_id) < 0) {
                perror("destroy_queue failed");
                return EXIT_FAILURE;
            }

            printf("Queue destroyed\n");
        } else {
            printf("Child process failed\n");
        }
    }

    return EXIT_SUCCESS;
}
