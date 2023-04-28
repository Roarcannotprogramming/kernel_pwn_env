#!/bin/env bash
gdb \
    --ex "target remote :1234" \
    $WORKDIR/linux-5.10.116/vmlinux