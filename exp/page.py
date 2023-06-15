virtual_base = 0xffff888000000000
vmemmap_base = 0xffffea0000000000
def virtual_to_page(virtual): 
    page_cnt = (virtual - virtual_base) // 0x1000 
    page = page_cnt*0x40 + vmemmap_base 
    return page

def page_to_virtual(page): 
    page_cnt = (page - vmemmap_base) // 0x40 
    virtual_addr = virtual_base + page_cnt * 0x1000 
    return virtual_addr 

def virtual_to_ptes(addr): 
    offset = addr & (2**12-1) 
    addr = addr >> 12 
    o4 = addr & (2**9-1) 
    addr = addr >> 9 
    o3 = addr & (2**9 -1) 
    addr = addr >> 9 
    o2 = addr & (2**9-1) 
    addr = addr >> 9 
    o1 = addr & (2**9-1) 
    return 8*o1, 8*o2, 8*o3, 8*o4, offset