#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>

#define __NR_init_queue  549
#define __NR_send_msg    550
#define __NR_recv_msg    551
#define __NR_destroy_queue 552

#define MAX_MSG_SZ       256
#define RX_MSG_SIZE      10

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

int main() {
    char message[RX_MSG_SIZE] = {0};
    const char *init_message = "sheryar";
    const char *ack_message = "ack";
    pid_t child_pid;

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

    // Fork a child process to run the second application
    child_pid = fork();
    if (child_pid < 0) {
        perror("fork failed");
        return EXIT_FAILURE;
    }

    if (child_pid == 0) {
        // In the child process, run the second application
        execl("./server 0", "server", NULL);
        perror("execl failed");
        exit(EXIT_FAILURE);
    } else {
        // In the parent process, wait for the child to finish
        waitpid(child_pid, NULL, 0);

        // Receive acknowledgment from the second program
        if (recv_msg(queue_id, message, RX_MSG_SIZE) < 0) {
            perror("recv_msg failed");
            return EXIT_FAILURE;
        }

        printf("Received acknowledgment: %s\n", message);

        if (strcmp(message, ack_message) == 0) {
            // Destroy the queue if acknowledgment is received
            if (destroy_queue(queue_id) < 0) {
                perror("destroy_queue failed");
                return EXIT_FAILURE;
            }

            printf("Queue destroyed\n");
        } else {
            printf("No acknowledgment received, queue not destroyed\n");
        }
    }

    return EXIT_SUCCESS;
}