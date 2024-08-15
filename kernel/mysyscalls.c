#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/uaccess.h> // For copy_from_user()
#include <linux/wait.h>    // For wait queues
#include <linux/sched.h>

// Below is test sys call
SYSCALL_DEFINE1(newcall, int, id)
{
        pr_info("new call in mysyscalls.c: %d\n", id);
        printk("new call printk: %d\n", id);

        return id;
}


// Define the maximum number of messages, queues, and message sizes
#define MAX_MSG      10
#define MAX_QUEUE    2
#define MAX_MSG_SZ   256
#define RX_MSG_SIZE  10

struct msg_queue {
    char msg[MAX_MSG][MAX_MSG_SZ];
    int head;
    int tail;
    int count;
    // Add locks
    spinlock_t lock;
    wait_queue_head_t wait;
};

struct msg_queue queue[MAX_QUEUE];

SYSCALL_DEFINE0(init_queue) {
    printk("init queue is called\n");
    int i;
    for (i = 0; i < MAX_QUEUE; i++) {
        if (queue[i].count == 0) {
            queue[i].head = 0;
            queue[i].tail = 0;
            queue[i].count = 0;
            spin_lock_init(&queue[i].lock);
            init_waitqueue_head(&queue[i].wait);
            printk("id : %d\n", i);
            return i;
        }
    }
    return -1; // no space available
}

SYSCALL_DEFINE3(send_msg, int, q_id, const char __user *, msg, size_t, msglen) {
    char *kernel_msg;
    struct msg_queue *queue_ptr;
    int ret = 0;

    if (q_id < 0 || q_id >= MAX_QUEUE) {
        printk("queue id not in range\n");
        return -EINVAL;
    }

    queue_ptr = &queue[q_id];

    spin_lock(&queue_ptr->lock);

    if (queue_ptr->count >= MAX_MSG) {
        printk(KERN_WARNING "queue is full\n");
        ret = -ENOSPC;
        goto out;
    }

    kernel_msg = kmalloc(msglen, GFP_KERNEL);
    if (!kernel_msg) {
        printk(KERN_ERR "Failed to allocate memory\n");
        ret = -ENOMEM;
        goto out;
    }

    if (copy_from_user(kernel_msg, msg, msglen)) {
        printk(KERN_WARNING "Failed to copy data from user space\n");
        kfree(kernel_msg);
        ret = -EFAULT;
        goto out;
    }

    if (msglen >= MAX_MSG_SZ) {
        printk(KERN_WARNING "Message length exceeds maximum size\n");
        kfree(kernel_msg);
        ret = -EINVAL;
        goto out;
    }
    kernel_msg[msglen] = '\0'; // Null-terminate string

    strncpy(queue_ptr->msg[queue_ptr->tail], kernel_msg, msglen);
    queue_ptr->msg[queue_ptr->tail][msglen] = '\0';
    queue_ptr->tail = (queue_ptr->tail + 1) % MAX_MSG;
    queue_ptr->count++;

    kfree(kernel_msg);
    wake_up_interruptible(&queue_ptr->wait);

out:
    spin_unlock(&queue_ptr->lock);
    return ret;
}

SYSCALL_DEFINE3(recv_msg, int, q_id, char __user *, rx_msg, size_t, msglen) {
    char kernel_msg[RX_MSG_SIZE];
    struct msg_queue *queue_ptr;
    int ret = 0;

    if (q_id < 0 || q_id >= MAX_QUEUE) {
        printk(KERN_WARNING "queue id not in range\n");
        return -EINVAL;
    }

    queue_ptr = &queue[q_id];

    spin_lock(&queue_ptr->lock);

    while (queue_ptr->count <= 0) {
        // Block the process until a message is available
        spin_unlock(&queue_ptr->lock);
        if (wait_event_interruptible(queue_ptr->wait, queue_ptr->count > 0)) {
            return -ERESTARTSYS;
        }
        spin_lock(&queue_ptr->lock);
    }

    strncpy(kernel_msg, queue_ptr->msg[queue_ptr->head], RX_MSG_SIZE);
    kernel_msg[RX_MSG_SIZE - 1] = '\0'; // Ensure null-termination

    if (copy_to_user(rx_msg, kernel_msg, RX_MSG_SIZE)) {
        ret = -EFAULT;
        goto out;
    }

    queue_ptr->head = (queue_ptr->head + 1) % MAX_MSG;
    queue_ptr->count--;

out:
    spin_unlock(&queue_ptr->lock);
    return ret;
}

SYSCALL_DEFINE1(destroy_queue, int, q_id) {
    struct msg_queue *queue_ptr;

    if (q_id < 0 || q_id >= MAX_QUEUE)
        return -1;

    queue_ptr = &queue[q_id];
    
    spin_lock(&queue_ptr->lock);

    if (queue_ptr->count > 0) {
        spin_unlock(&queue_ptr->lock);
        return -4; // queue not empty, elements are there
    }

    queue_ptr->count = -1; // means destroyed
    spin_unlock(&queue_ptr->lock);
    return 0;
}
