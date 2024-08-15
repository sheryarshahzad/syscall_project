#include "linux/kernel.h"
#include "linux/syscalls.h"
#include "linux/string.h"
#include <linux/uaccess.h> // For copy_from_user()
#include <linux/slab.h> // For kmalloc and kfree
#include <linux/spinlock.h> // For spinlocks


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
	spinlock_t lock;
};

static struct msg_queue queue[MAX_QUEUE];

SYSCALL_DEFINE0(init_queue)
{
	int i;
	printk("init queue is called\n");

	for (i = 0; i < MAX_QUEUE; i++) {
		if (queue[i].count == 0) {
			queue[i].head = 0;
			queue[i].tail = 0;
			queue[i].count = 0;
			spin_lock_init(&queue[i].lock);
			printk("id : %d\n", i);
			return i;
		}
	}
	return -1; //no space available
}

SYSCALL_DEFINE3(send_msg, int, q_id, const char __user *, msg, size_t, msglen)
{
	char *kernel_msg;
	int ret = 0;

	printk("q_id: %d\n", q_id);
	if (q_id < 0 || q_id >= MAX_QUEUE) {
		printk("queue id not in range\n");
		return -EINVAL;
	}

	struct msg_queue *queue_ptr = &queue[q_id];
	spin_lock(&queue_ptr->lock); // Acquire the lock

	if (queue_ptr->count >= MAX_MSG) {
		spin_unlock(&queue_ptr->lock); // Release the lock
		printk(KERN_WARNING "queue is full\n");
		return -ENOSPC;
	}

	kernel_msg = kmalloc(msglen, GFP_KERNEL);
	if (!kernel_msg) {
		spin_unlock(&queue_ptr->lock); // Release the lock
		printk(KERN_ERR "Failed to allocate memory\n");
		return -ENOMEM;
	}

    if (copy_from_user(kernel_msg, msg, msglen)) {
        kfree(kernel_msg);
        spin_unlock(&queue_ptr->lock); // Release the lock
        printk(KERN_WARNING "Failed to copy data from user space\n");
        return -EFAULT;
    }

    if (msglen >= MAX_MSG_SZ) {
        kfree(kernel_msg);
        spin_unlock(&queue_ptr->lock); // Release the lock
        printk(KERN_WARNING "Message length exceeds maximum size\n");
        return -EINVAL;
    }
    kernel_msg[msglen] = '\0'; // Null-terminate string

    strncpy(queue_ptr->msg[queue_ptr->tail], kernel_msg, msglen);
    queue_ptr->msg[queue_ptr->tail][msglen] = '\0'; // Ensure null-termination
    queue_ptr->tail = (queue_ptr->tail + 1) % MAX_MSG;
    queue_ptr->count++;

    kfree(kernel_msg);
    spin_unlock(&queue_ptr->lock); // Release the lock

    return ret;
}

SYSCALL_DEFINE3(recv_msg, int, q_id, char __user *, rx_msg, size_t, msglen)
{
    char kernel_msg[RX_MSG_SIZE];
    int ret = 0;

    printk(KERN_INFO "recv msg is called\n");
    if (q_id < 0 || q_id >= MAX_QUEUE) {
        printk(KERN_WARNING "queue id not in range\n");
        return -EINVAL;
    }

    struct msg_queue *queue_ptr = &queue[q_id];
    spin_lock(&queue_ptr->lock); // Acquire the lock

    if (queue_ptr->count <= 0) {
        spin_unlock(&queue_ptr->lock); // Release the lock
        printk(KERN_WARNING "queue is empty\n");
        return -ENOMSG;
    }

    if (msglen < RX_MSG_SIZE) {
        spin_unlock(&queue_ptr->lock); // Release the lock
        printk(KERN_WARNING "msglen is too small\n");
        return -EINVAL;
    }

    strncpy(kernel_msg, queue_ptr->msg[queue_ptr->head], RX_MSG_SIZE);
    kernel_msg[RX_MSG_SIZE - 1] = '\0'; // Ensure null-termination

    if (copy_to_user(rx_msg, kernel_msg, RX_MSG_SIZE)) {
        spin_unlock(&queue_ptr->lock); // Release the lock
        printk(KERN_WARNING "Failed to copy data to user space\n");
        return -EFAULT;
    }

    queue_ptr->head = (queue_ptr->head + 1) % MAX_MSG;
    queue_ptr->count--;

    spin_unlock(&queue_ptr->lock); // Release the lock

    return ret;
}

SYSCALL_DEFINE1(destroy_queue, int, q_id)
{
    printk("destroy queue is called\n");
    if (q_id < 0 || q_id >= MAX_QUEUE)
        return -1;

    struct msg_queue *queue_ptr = &queue[q_id];
    spin_lock(&queue_ptr->lock); // Acquire the lock

    if (queue_ptr->count > 0) {
        spin_unlock(&queue_ptr->lock); // Release the lock
        return -4; // Queue not empty, elements are there
    }

    queue_ptr->count = -1; // Mark as destroyed
    spin_unlock(&queue_ptr->lock); // Release the lock

    return 0;
}