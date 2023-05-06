#include "banzi.h"
#include <liburing.h>

void do_exploit() {
    struct io_uring ring;
    io_uring_queue_init(256, &ring, IORING_SETUP_IOPOLL);
    struct io_uring_sqe * sqe;
    struct io_uring_cqe * cqe;

    sqe = io_uring_get_sqe(&ring);
}

int main() {
    do_exploit();
}