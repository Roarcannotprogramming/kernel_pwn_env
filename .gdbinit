source /pwndbg/gdbinit.py
set auto-load safe-path /

target remote :1234

# dprintf *0xffffffff8148810a, "do_sys_poll_kmalloc_ret: rax=%#lx\n", $rax

# b *0xffffffff81407164
# commands 4
# silent
# printf "{\n"
# bt
# printf "__alloc_page_ret: rax=%#lx\n", ($rax-$vmemmap_base)*0x40+$virtual_base
# printf "}\n"
# c
# end