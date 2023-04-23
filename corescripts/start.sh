#!/bin/sh

qemu-system-x86_64 -m 256M -kernel ./bzImage -initrd ./core_modied.cpio -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet nokaslr" -cpu qemu64,+smep,+smap -nographic -gdb tcp::1234 -monitor /dev/null
