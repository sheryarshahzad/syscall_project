#include "linux/kernel.h"
#include "linux/syscalls.h"
#include "linux/string.h"
/*#include "linux/types.h"*/
#include <linux/uaccess.h> // For copy_from_user()


// Below is test sys call
SYSCALL_DEFINE1(newcall, int, id)
{
        pr_info("new call in mysyscalls.c: %d\n", id);
        printk("new call printk: %d\n", id);

        return id;
}


#define MAX_MSG      10
#define MAX_QUEUE    2
#define MAX_MSG_SZ   256
#define RX_MSG_SIZE  10

struct msg_queue {
	char msg[MAX_MSG][MAX_MSG_SZ];
	int head;
	int tail;
	int count;
	//Add locks.
};

struct msg_queue queue[MAX_QUEUE];

SYSCALL_DEFINE0(init_queue)
{
	printk("init queue is called\n");
	int i;
	for (i = 0; i < MAX_QUEUE; i++) {
		if (queue[i].count == 0) {
			queue[i].head = 0;
			queue[i].tail = 0;
			queue[i].count = 0;
			printk("id : %d\n", i);
			return i;
			}
	}
	return -1; //no space available
}

SYSCALL_DEFINE3(send_msg, int, q_id, const char __user *, msg, size_t, msglen)
//asmlinkage long __x64_sys_send_msg(int q_id, char *msg, size_t msglen)
{
	char *kernel_msg;
	int ret = 0;

	printk("q_id: %d\n", q_id);
	if (q_id < 0 || q_id >= MAX_QUEUE) {
		printk("queue id not in range\n");
		return -EINVAL;
	}

	printk("reading struct\n");

	struct msg_queue *queue_ptr = &queue[q_id];

    	if (queue_ptr->count >= MAX_MSG) {
        	printk(KERN_WARNING "queue is full\n");
        	return -ENOSPC;
    	}

    	// Allocate memory for kernel buffer
    	kernel_msg = kmalloc(msglen, GFP_KERNEL);
    	if (!kernel_msg) {
        	printk(KERN_ERR "Failed to allocate memory\n");
        	return -ENOMEM;
    	}

	// Copy message from user space to kernel space
    	if (copy_from_user(kernel_msg, msg, msglen)) {
        	printk(KERN_WARNING "Failed to copy data from user space\n");
        	kfree(kernel_msg);
        	return -EFAULT;
    	}

    	// Ensure null-termination of the message
    	if (msglen >= MAX_MSG_SZ) {
        	printk(KERN_WARNING "Message length exceeds maximum size\n");
        	kfree(kernel_msg);
        	return -EINVAL;
    	}
    	kernel_msg[msglen] = '\0';  // Null-terminate string

    	printk(KERN_INFO "msg len: %lu\n", msglen);
	printk(KERN_INFO "Message: %s\n", kernel_msg);

    	// Copy message to queue
    	strncpy(queue_ptr->msg[queue_ptr->tail], kernel_msg, msglen);
    	queue_ptr->msg[queue_ptr->tail][msglen] = '\0';  // Ensure null-termination

    	// Update queue state
    	queue_ptr->tail = (queue_ptr->tail + 1) % MAX_MSG;
    	queue_ptr->count++;

    	// Clean up
    	kfree(kernel_msg);

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

    	if (queue_ptr->count <= 0) {
        	printk(KERN_WARNING "queue is empty\n");
        	return -ENOMSG;
    	}

    	// Ensure the provided msglen is enough to store the message
    	if (msglen < RX_MSG_SIZE) {
        	printk(KERN_WARNING "msglen is too small\n");
        	return -EINVAL;
    	}

    	// Copy message from the queue to kernel space buffer
    	strncpy(kernel_msg, queue_ptr->msg[queue_ptr->head], RX_MSG_SIZE);
    	kernel_msg[RX_MSG_SIZE - 1] = '\0';  // Ensure null-termination

    	// Copy message from kernel space to user space
    	if (copy_to_user(rx_msg, kernel_msg, RX_MSG_SIZE)) {
        	printk(KERN_WARNING "Failed to copy data to user space\n");
        	return -EFAULT;
    	}

    	// Update queue state
    	queue_ptr->head = (queue_ptr->head + 1) % MAX_MSG;
    	queue_ptr->count--;

    	return ret;
}


SYSCALL_DEFINE1(destroy_queue, int, q_id)
//asmlinkage long __x64_sys_destroy_queue(int q_id)
{
	printk("destroy queue is called \n");
	if (q_id < 0 || q_id >= MAX_QUEUE)
                return -1;

        struct msg_queue *queue_ptr = &queue[q_id];

        if (queue_ptr->count > 0)
                return -4; //queue not empty, elements are there

        queue_ptr->count = -1; //means destroyed
        return 0;
}