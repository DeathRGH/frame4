#ifndef KSDK_H
#define KSDK_H

#include <stdint.h>
#include <stdarg.h>

#include "sparse.h"
#include "ksdk_util.h"
#include "ksdk_bsd.h"
#include "kfirmware.h"

#define __Xfast_syscall 0x1C0

extern uint64_t cached_kernel_base;

extern int(*printf)(const char *fmt, ... );
extern void *(*malloc)(uint64_t size, void *type, int flags);
extern void(*free)(void *addr, void *type);
extern void *(*memcpy)(void *dest, const void *src, uint64_t num);
extern void *(*memset)(void *ptr, int value, uint64_t num);
extern int(*memcmp)(const void *ptr1, const void *ptr2, uint64_t num);
extern void *(*kmem_alloc)(struct vm_map *map, uint64_t size);
extern uint64_t(*strlen)(const char *str);
extern char *(*strcpy)(char *dst, const char *src);
extern int(*create_thread)(struct thread *td, uint64_t ctx, void (*start_func)(void *), void *arg, char *stack_base, uint64_t stack_size, char *tls_base, long *child_tid, long *parent_tid, uint64_t flags, uint64_t rtp);
extern int(*kern_reboot)(int magic);
extern void(*vm_map_lock_read)(struct vm_map *map);
extern int(*vm_map_lookup_entry)(struct vm_map *map, uint64_t address, struct vm_map_entry **entries);
extern void(*vm_map_unlock_read)(struct vm_map *map);
extern int(*vm_map_delete)(struct vm_map *map, uint64_t start, uint64_t end);
extern int(*vm_map_protect)(struct vm_map *map, uint64_t start, uint64_t end, int new_prot, uint64_t set_max);
extern int(*vm_map_findspace)(struct vm_map *map, uint64_t start, uint64_t length, uint64_t *addr);
extern int(*vm_map_insert)(struct vm_map *map, uint64_t object, uint64_t offset, uint64_t start, uint64_t end, int prot, int max, int cow);
extern void(*vm_map_lock)(struct vm_map *map);
extern void(*vm_map_unlock)(struct vm_map *map);
extern int(*proc_rwmem)(struct proc *p, struct uio *uio);
extern uint64_t(*pmap_kextract)(uint64_t va);
extern void *(*pmap_mapdev)(uint64_t pa, uint64_t size);
extern void(*pmap_unmapdev)(uint64_t va, uint64_t size);

extern uint8_t *disable_console_output;
extern void *M_TEMP;
extern void **kernel_map;
extern void **prison0;
extern void **rootvnode;
extern void **allproc;
extern struct sysent *sysents;

extern uint64_t get_kernel_base();
extern void init_ksdk();

#endif
