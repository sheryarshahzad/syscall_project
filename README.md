# System Call Implementation

## Adding system calls to linux kernel
1: Download source code for linux kernel. I have used v6.6 for this project.\
2: Add a file name "mysyscalls.c" in kernel directory.\
3: Define system calls and their handling in the file.\
4: Add entry for the system calls in system table at the following location.\
    ```./arch/x86/entry/syscalls/syscall_64.tbl```\
5: Include system call prototypes at the following location.\
    ```include/linux/syscalls.h```\
6: Add mysyscalls.c in kernel/Makefile for compiling. \

## Building the kernel
Go to kernel's main directory, run the following commands.\
   ```make defconfig```\
   ```make -j```\
   ```sudo make modules_install```\
   ```sudo make install```\
   ```sudo update-grub```\
   ```sudo reboot```\

## Testing the custom system calls.
1: Create two test applications, named as client.c and server.c\
2: Client app would initialize queue and get queue id.\
3: Client then sends a message "sheryar" to server and waits for an acknowledgement.\
4: When ack is received, it then destroys the queue.\
5: The server app receives a message from the client app, then it sends back the acknowledgement.\
6: For building the code, run the following.\
    ```gcc -o client client.c```\
    ```gcc -o server server.c```\
7: For running, do the following\
    ```./client```\
6: Run the code, and observe logs and dmesg for kernel prints.\

## Modifying glib to add new system call wrappers
1: Download the glibc. I have used v2.38 for this project. \
2: Create build and install directory. We will not modify our system's glibc. Instead we install it separately and link it statically in our code. This will be done in testapp -> Makefile.\
3: Add code for adding system calls in glibc. \
4: Go to build directory, run the following command to configure and build the glibc.\
   ```cd build```\
   ```../glibc-2.38/configure  --prefix=path/to/install/directory/in/glibc```\
   ```make -j(nproc)```\
   ```make install```\