#!/usr/bin/env python3

import gdb

vmemmap_base = 0xffffea0000000000
virtual_base = 0xffff888000000000

def to_virt(page):
    return (page - vmemmap_base)*0x40 + virtual_base

def to_page(virt):
    return (virt - virtual_base)//0x40 + vmemmap_base

def to_uint64(x):
    return x % (2**64)

def container_of(member_ptr, parent_type, member_name):
    # 获取成员在父结构体中的偏移量
    parent_type = gdb.lookup_type(parent_type)
    member_offset = int(parent_type[member_name].bitpos / 8)

    # 计算结构体的起始地址
    parent_address = member_ptr.cast(gdb.lookup_type('uintptr_t')) - member_offset

    # 返回父结构体的对象
    return gdb.Value(parent_address).cast(parent_type.pointer()).dereference()

def per_cpu_ptr(ptr, cpu):
    # __per_cpu_offset can be found by `init_kmem_cache_cpus` (inlined in `__kmem_cache_create`)
    # 0xffffffff814538ae <__kmem_cache_create+974>:        add    rbx,QWORD PTR [r14*8-0x7d5af4c0]
    __per_cpu_offset = gdb.lookup_symbol('__per_cpu_offset')[0]
    if __per_cpu_offset is None:
        print("全局变量 '__per_cpu_offset' 未找到。")
        return None

    per_cpu_offset = __per_cpu_offset.value()
    
    per_cpu_base = per_cpu_offset[cpu].cast(gdb.lookup_type('uintptr_t'))
    return per_cpu_base + ptr
    # print(per_cpu_base)

def traverse_slab_caches(cb):
    # 查找全局变量 slab_caches
    slab_caches = gdb.lookup_symbol('slab_caches')[0]
    if slab_caches is None:
        print("全局变量 'slab_caches' 未找到。")
        return
    
    # 获取 slab_caches 的值
    slab_cache = slab_caches.value()
    if slab_cache is None:
        print("slab_caches 是空的。")
        return

    # 遍历链表
    node = slab_cache
    count = 0
    while node and node['next'].dereference() != slab_cache:
        cache = container_of(node, 'struct kmem_cache', 'list')

        cb(cache)
        
        if node['next']:
            node = node['next'].dereference()
        else:
            break

        count += 1

def find_slab_caches(name):
    # 查找全局变量 slab_caches
    slab_caches = gdb.lookup_symbol('slab_caches')[0]
    if slab_caches is None:
        print("全局变量 'slab_caches' 未找到。")
        return None
    
    # 获取 slab_caches 的值
    slab_cache = slab_caches.value()
    if slab_cache is None:
        print("slab_caches 是空的。")
        return None

    # 遍历链表
    node = slab_cache
    count = 0
    while node and node['next'].dereference() != slab_cache:
        cache = container_of(node, 'struct kmem_cache', 'list')

        if cache['name'].string() == name:
            return cache

        if node['next']:
            node = node['next'].dereference()
        else:
            break

        count += 1

    return None

class SlabFreeTracePoint(gdb.Breakpoint):
    def stop(self):
        pid = int(gdb.parse_and_eval("$lx_current()->pid"))
        cpu = int(gdb.parse_and_eval("$lx_current()->thread_info.cpu"))
        unix_cache = to_uint64(int(gdb.parse_and_eval("$cache_addr")))
        free_cache = to_uint64(int(gdb.parse_and_eval("$rdi")))
        slab = int(gdb.parse_and_eval("$rsi"))
        addr = int(gdb.parse_and_eval("$rdx"))
        # print("unix_cache: 0x{:x}\tfree_cache: 0x{:x}".format(unix_cache, free_cache))
        if pid < 600:
            return False
        if cpu != 0:
            return False
        if unix_cache != free_cache:
            return False
        if self.cnt > 0:
            self.cnt -= 1
            gdb.execute("bt")
        print("slab_free_unix\tpid: {}\tcpu: {}\tslab: 0x{:x}\taddr: 0x{:x}".format(pid, cpu, slab, addr))
        return False

class SlabInfo(gdb.Command):

    def __init__(self):
        super(SlabInfo, self).__init__("islab", gdb.COMMAND_USER)

    def invoke(self, slab_name, from_tty):
        if not slab_name:
            print("Usage: islab <slab_name>")
            return

        cache = find_slab_caches(slab_name)
        if cache is None:
            print("未找到指定的 slab_cache")
            return
        gdb.execute("set $cache = *(struct kmem_cache *) {}".format(cache.address))
        gdb.execute("set $cache_addr = (struct kmem_cache *) {}".format(cache.address))

        cpu_slab =  per_cpu_ptr(cache['cpu_slab'].cast(gdb.lookup_type('int')), 0).cast(gdb.lookup_type('struct kmem_cache_cpu').pointer()).dereference()
        if cpu_slab is None:
            print("cpu_slab 未初始化")
            return
        gdb.execute("set $cpu_slab = *(struct kmem_cache_cpu *) {}".format(cpu_slab.address))
        gdb.execute("set $cpu_slab_addr = (struct kmem_cache_cpu *) {}".format(cpu_slab.address))

        # node = cpu_slab['partial'].cast(gdb.lookup_type('struct slab').pointer()).dereference()
        # if node is None:
        #     print("slab_cache 未初始化")
        #     return

        # gdb.execute("set $node = *(struct slab *) {}".format(node.address))

class PageToVirt(gdb.Command):
    
    def __init__(self):
        super(PageToVirt, self).__init__("ptv", gdb.COMMAND_USER)
    
    def invoke(self, page, from_tty):
        if not page:
            print("Usage: ptv <page>")
            return
    
        addr = to_virt(int(page, 16))
        print("0x{:x}".format(addr))

class VirtToPage(gdb.Command):

    def __init__(self):
        super(VirtToPage, self).__init__("vtp", gdb.COMMAND_USER)

    def invoke(self, virt, from_tty):
        if not virt:
            print("Usage: vtp <virt>")
            return

        page = to_page(int(virt, 16))
        print("0x{:x}".format(page))

SlabInfo()
PageToVirt()
VirtToPage()
SlabFreeTracePoint("slab_free").silent = True

