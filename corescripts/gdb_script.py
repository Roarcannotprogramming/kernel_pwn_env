#!/usr/bin/env python3

import gdb

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


slab_unix = []
# name = 0xffff88800a662090 ":A-0001088",
def is_same_slab_unix(cache):
    if cache['kobj']['name'].string() == ':A-0001088':
        slab_unix.append(cache['name'].string())
        return True
    return False


# 在 GDB 中运行此函数
cache = find_slab_caches('UNIX')
cpu_slab =  per_cpu_ptr(cache['cpu_slab'].cast(gdb.lookup_type('int')), 0).cast(gdb.lookup_type('struct kmem_cache_cpu').pointer()).dereference()

print(cache)

node = cpu_slab['partial'].cast(gdb.lookup_type('struct slab').pointer()).dereference()
list = node['slab_list']
print(node)
