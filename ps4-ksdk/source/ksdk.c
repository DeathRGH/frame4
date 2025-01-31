#include "ksdk.h"

uint64_t cached_kernel_base;

int(*printf)(const char *fmt, ... );
void *(*malloc)(uint64_t size, void *type, int flags);
void(*free)(void *addr, void *type);
void *(*memcpy)(void *dest, const void *src, uint64_t num);
void *(*memset)(void *ptr, int value, uint64_t num);
int(*memcmp)(const void *ptr1, const void *ptr2, uint64_t num);
void *(*kmem_alloc)(struct vm_map *map, uint64_t size);
uint64_t(*strlen)(const char *str);
char *(*strcpy)(char *dst, const char *src);
int(*create_thread)(struct thread *td, uint64_t ctx, void (*start_func)(void *), void *arg, char *stack_base, uint64_t stack_size, char *tls_base, long *child_tid, long *parent_tid, uint64_t flags, uint64_t rtp);
int(*kern_reboot)(int magic);
void(*vm_map_lock_read)(struct vm_map *map);
int(*vm_map_lookup_entry)(struct vm_map *map, uint64_t address, struct vm_map_entry **entries);
void(*vm_map_unlock_read)(struct vm_map *map);
int(*vm_map_delete)(struct vm_map *map, uint64_t start, uint64_t end);
int(*vm_map_protect)(struct vm_map *map, uint64_t start, uint64_t end, int new_prot, uint64_t set_max);
int(*vm_map_findspace)(struct vm_map *map, uint64_t start, uint64_t length, uint64_t *addr);
int(*vm_map_insert)(struct vm_map *map, uint64_t object, uint64_t offset, uint64_t start, uint64_t end, int prot, int max, int cow);
void(*vm_map_lock)(struct vm_map *map);
void(*vm_map_unlock)(struct vm_map *map);
int(*proc_rwmem)(struct proc *p, struct uio *uio);
uint64_t(*pmap_kextract)(uint64_t va);
void *(*pmap_mapdev)(uint64_t pa, uint64_t size);
void(*pmap_unmapdev)(uint64_t va, uint64_t size);

uint8_t *disable_console_output;
void *M_TEMP;
void **kernel_map;
void **prison0;
void **rootvnode;
void **allproc;
struct sysent *sysents;

uint64_t get_kernel_base() {
    uint32_t edx, eax;
    __asm__ ("rdmsr" : "=d"(edx), "=a"(eax) : "c"(0xC0000082));
    return ((((uint64_t)edx) << 32) | (uint64_t)eax) - __Xfast_syscall;
}

void init_505sdk(uint8_t *kbase) {
    printf = (void *)(kbase + 0x436040);
    malloc = (void *)(kbase + 0x10E250);
    free = (void *)(kbase + 0x10E460);
    memcpy = (void *)(kbase + 0x1EA530);
    memset = (void *)(kbase + 0x3205C0);
    memcmp = (void *)(kbase + 0x50AC0);
    kmem_alloc = (void *)(kbase + 0xFCC80);
    strlen = (void *)(kbase + 0x3B71A0);
    strcpy = (void *)(kbase + 0x8F250);
    create_thread = (void *)(kbase + 0x1BE1F0);
    kern_reboot = (void *)(kbase + 0x10D390);
    vm_map_lock_read = (void *)(kbase + 0x19F140);
    vm_map_lookup_entry = (void *)(kbase + 0x19F760);
    vm_map_unlock_read = (void *)(kbase + 0x19F190);
    vm_map_delete = (void *)(kbase + 0x1A19D0);
    vm_map_protect = (void *)(kbase + 0x1A3A50);
    vm_map_findspace = (void *)(kbase + 0x1A1F60);
    vm_map_insert = (void *)(kbase + 0x1A0280);
    vm_map_lock = (void *)(kbase + 0x19EFF0);
    vm_map_unlock = (void *)(kbase + 0x19F060);
    proc_rwmem = (void *)(kbase + 0x30D150);
    pmap_kextract = (void *)(kbase + 0x2E08F0);
    pmap_mapdev = (void *)(kbase + 0x2E9D90);
    pmap_unmapdev = (void *)(kbase + 0x2E9DB0);
    disable_console_output = (void *)(kbase + 0x19ECEB0);
    M_TEMP = (void *)(kbase + 0x14B4110);
    kernel_map = (void *)(kbase + 0x1AC60E0);
    prison0 = (void *)(kbase + 0x10986A0);
    rootvnode = (void *)(kbase + 0x22C1A70);
    allproc = (void *)(kbase + 0x2382FF8);
    sysents = (void *)(kbase + 0x107C610);
}

void init_672sdk(uint8_t *kbase) {
    printf = (void *)(kbase + 0x123280);
    malloc = (void *)(kbase + 0xD7A0);
    free = (void *)(kbase + 0xD9A0);
    memcpy = (void *)(kbase + 0x3C15B0);
    memset = (void *)(kbase + 0x1687D0);
    memcmp = (void *)(kbase + 0x207E40);
    kmem_alloc = (void *)(kbase + 0x250730);
    strlen = (void *)(kbase + 0x2433E0);
    strcpy = (void *)(kbase + 0x2390C0);
    create_thread = (void *)(kbase + 0x4A6FB0);
    kern_reboot = (void *)(kbase + 0x206D50);
    vm_map_lock_read = (void *)(kbase + 0x44CD40);
    vm_map_lookup_entry = (void *)(kbase + 0x44D330);
    vm_map_unlock_read = (void *)(kbase + 0x44CD90);
    vm_map_delete = (void *)(kbase + 0x44F8A0);
    vm_map_protect = (void *)(kbase + 0x451BF0);
    vm_map_findspace = (void *)(kbase + 0x44FE60);
    vm_map_insert = (void *)(kbase + 0x44DEF0);
    vm_map_lock = (void *)(kbase + 0x44CBF0);
    vm_map_unlock = (void *)(kbase + 0x44CC60);
    proc_rwmem = (void *)(kbase + 0x10EE10);
    pmap_kextract = (void *)(kbase + 0x4E790);
    pmap_mapdev = (void *)(kbase + 0x58FC0);
    pmap_unmapdev = (void *)(kbase + 0x58FE0);
    disable_console_output = (void *)(kbase + 0x1A6EB18);
    M_TEMP = (void *)(kbase + 0x1540EB0);
    kernel_map = (void *)(kbase + 0x220DFC0);
    prison0 = (void *)(kbase + 0x113E518);
    rootvnode = (void *)(kbase + 0x2300320);
    allproc = (void *)(kbase + 0x22BBE80);
    sysents = (void *)(kbase + 0x111E000);
}

void init_702sdk(uint8_t *kbase) {
    printf = (void *)(kbase + 0xBC730);
    malloc = (void *)(kbase + 0x301840);
    free = (void *)(kbase + 0x301A40);
    memcpy = (void *)(kbase + 0x2F040);
    memset = (void *)(kbase + 0x2DFC20);
    memcmp = (void *)(kbase + 0x207500);
    kmem_alloc = (void *)(kbase + 0x1170F0);
    strlen = (void *)(kbase + 0x93FF0);
    strcpy = (void *)(kbase + 0x2CC70);
    create_thread = (void *)(kbase + 0x842E0);
    kern_reboot = (void *)(kbase + 0x2CD780);
    vm_map_lock_read = (void *)(kbase + 0x25FB90);
    vm_map_lookup_entry = (void *)(kbase + 0x260190);
    vm_map_unlock_read = (void *)(kbase + 0x25FBE0);
    vm_map_delete = (void *)(kbase + 0x262700);
    vm_map_protect = (void *)(kbase + 0x264A50);
    vm_map_findspace = (void *)(kbase + 0x262CC0);
    vm_map_insert = (void *)(kbase + 0x260D60);
    vm_map_lock = (void *)(kbase + 0x25FA50);
    vm_map_unlock = (void *)(kbase + 0x25FAB0);
    proc_rwmem = (void *)(kbase + 0x43E80);
    pmap_kextract = (void *)(kbase + 0x3DF0A0);
    pmap_mapdev = (void *)(kbase + 0x3E9880);
    pmap_unmapdev = (void *)(kbase + 0x3E98A0);
    disable_console_output = (void *)(kbase + 0x1A6EAA0);
    M_TEMP = (void *)(kbase + 0x1A7AE50);
    kernel_map = (void *)(kbase + 0x21C8EE0);
    prison0 = (void *)(kbase + 0x113E398);
    rootvnode = (void *)(kbase + 0x22C5750);
    allproc = (void *)(kbase + 0x1B48318);
    sysents = (void *)(kbase + 0x1125660);
}

void init_900sdk(uint8_t *kbase) {
    printf = (void *)(kbase + 0xB7A30);
    malloc = (void *)(kbase + 0x301B20);
    free = (void *)(kbase + 0x301CE0);
    memcpy = (void *)(kbase + 0x2714B0);
    memset = (void *)(kbase + 0x1496C0);
    memcmp = (void *)(kbase + 0x271E20);
    kmem_alloc = (void *)(kbase + 0x37BE70);
    strlen = (void *)(kbase + 0x30F450);
    strcpy = (void *)(kbase + 0x189F80);
    create_thread = (void *)(kbase + 0x1ED670);
    kern_reboot = (void *)(kbase + 0x29A380);
    vm_map_lock_read = (void *)(kbase + 0x7BB80);
    vm_map_lookup_entry = (void *)(kbase + 0x7C1C0);
    vm_map_unlock_read = (void *)(kbase + 0x7BBD0);
    vm_map_delete = (void *)(kbase + 0x7E680);
    vm_map_protect = (void *)(kbase + 0x809C0);
    vm_map_findspace = (void *)(kbase + 0x7EC40);
    vm_map_insert = (void *)(kbase + 0x7CD80);
    vm_map_lock = (void *)(kbase + 0x7BA30);
    vm_map_unlock = (void *)(kbase + 0x7BAA0);
    proc_rwmem = (void *)(kbase + 0x41EB00);
    pmap_kextract = (void *)(kbase + 0x12D3B0);
    pmap_mapdev = (void *)(kbase + 0x1377A0);
    pmap_unmapdev = (void *)(kbase + 0x1377C0);
    disable_console_output = (void *)(kbase + 0x152BF60);
    M_TEMP = (void *)(kbase + 0x15621E0);
    kernel_map = (void *)(kbase + 0x2268D48);
    prison0 = (void *)(kbase + 0x111F870);
    rootvnode = (void *)(kbase + 0x21EFF20);
    allproc = (void *)(kbase + 0x1B946E0);
    sysents = (void *)(kbase + 0x1100310);
}

void init_1100sdk(uint8_t *kbase) {
    printf = (void *)(kbase + 0x2FCBD0);
    malloc = (void *)(kbase + 0x1A4220);
    free = (void *)(kbase + 0x1A43E0);
    memcpy = (void *)(kbase + 0x2DDDF0);
    memset = (void *)(kbase + 0x482D0);
    memcmp = (void *)(kbase + 0x948B0);
    kmem_alloc = (void *)(kbase + 0x245E10);
    strlen = (void *)(kbase + 0x21DC40);
    strcpy = (void *)(kbase + 0x1AA590);
    create_thread = (void *)(kbase + 0x295170);
    kern_reboot = (void *)(kbase + 0x198060);
    vm_map_lock_read = (void *)(kbase + 0x3578B0);
    vm_map_lookup_entry = (void *)(kbase + 0x357EF0);
    vm_map_unlock_read = (void *)(kbase + 0x357900);  
    vm_map_delete = (void *)(kbase + 0x35A3B0);
    vm_map_protect = (void *)(kbase + 0x35C710);  
    vm_map_findspace = (void *)(kbase + 0x35A970);
    vm_map_insert = (void *)(kbase + 0x358AB0);
    vm_map_lock = (void *)(kbase + 0x357760);
    vm_map_unlock = (void *)(kbase + 0x3577D0);
    proc_rwmem = (void *)(kbase + 0x3838A0);
    pmap_kextract = (void *)(kbase + 0x1145F0);
    pmap_mapdev = (void *)(kbase + 0x11E9A0);
    pmap_unmapdev = (void *)(kbase + 0x11E9C0);
    disable_console_output = (void *)(kbase + 0x152CFF8);
    M_TEMP = (void *)(kbase + 0x15415B0);
    kernel_map = (void *)(kbase + 0x21FF130);
    prison0 = (void *)(kbase + 0x111F830);
    rootvnode = (void *)(kbase + 0x2116640);
    allproc = (void *)(kbase + 0x22D0A98);
    sysents = (void *)(kbase + 0x1101760);
}

void init_ksdk() {
    cached_kernel_base = get_kernel_base();
    unsigned short firmwareVersion = kget_firmware_from_base(cached_kernel_base);
    switch(firmwareVersion) {
        case 505:
            init_505sdk((uint8_t *)cached_kernel_base);
            break;
        case 672:
            init_672sdk((uint8_t *)cached_kernel_base);
            break;
        case 702:
            init_702sdk((uint8_t *)cached_kernel_base);
            break;
        case 900:
            init_900sdk((uint8_t *)cached_kernel_base);
            break;
        case 1100:
            init_1100sdk((uint8_t *)cached_kernel_base);
            break;
    }
}
