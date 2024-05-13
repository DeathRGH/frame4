#ifndef KSDK_H
#define KSDK_H

#include <stdint.h>
#include <stdarg.h>

#include "sparse.h"
#include "ksdk_util.h"
#include "ksdk_bsd.h"
#include "kfirmware.h"

#define __Xfast_syscall 0x1C0

extern uint64_t cachedKernelBase;

extern void(*Xfast_syscall)(void);
extern int(*copyin)(const void *uaddr, void *kaddr, uint64_t len);
extern int(*copyout)(const void *kaddr, void *uaddr, uint64_t len);
extern int(*printf)(const char *fmt, ... );
extern int(*vprintf)(const char *fmt, va_list arg);
extern void *(*malloc)(uint64_t size, void *type, int flags);
extern void(*free)(void *addr, void *type);
extern void *(*memcpy)(void *dest, const void *src, uint64_t num);
extern void *(*memset)(void *ptr, int value, uint64_t num);
extern int(*memcmp)(const void *ptr1, const void *ptr2, uint64_t num);
extern void *(*kmem_alloc)(struct vm_map *map, uint64_t size);
extern uint64_t(*strlen)(const char *str);
extern char *(*strcpy)(char *dst, const char *src);
extern char *(*strncmp)(char *dst, const char *src, uint64_t len);
extern void(*pause)(const char *wmesg, int timo);
extern int(*kthread_add)(void (*func)(void *), void *arg, struct proc *procp, struct thread **newtdpp, int flags, int pages, const char *fmt, ...);
extern void(*kthread_exit)(void);
extern void(*sched_prio)(struct thread *td, uint16_t prio);
extern void(*sched_add)(struct thread *td, uint64_t cpuset);
extern void(*kern_yield)(uint64_t p);
extern int(*fill_regs)(struct thread *td, struct reg *rg);
extern int(*set_regs)(struct thread *td, struct reg *rg);
extern int(*create_thread)(struct thread *td, uint64_t ctx, void (*start_func)(void *), void *arg, char *stack_base, uint64_t stack_size, char *tls_base, long *child_tid, long *parent_tid, uint64_t flags, uint64_t rtp);
extern int(*kproc_create)(void (*func)(void *), void *arg, struct proc **newpp, int flags, int pages, const char *fmt, ...);
extern void(*kthread_set_affinity)(const char *tdname, uint64_t prio, uint64_t cpuset, uint64_t unknown);
extern void(*kthread_suspend_check)(void);
extern int(*kproc_kthread_add)(void (*func)(void *), void *arg, struct proc **procptr, struct thread **tdptr, int flags, int pages, char *procname, const char *fmt, ...);
extern void(*sx_init_flags)(struct sx *sx, const char *description, int opts);
extern void(*sx_xlock)(struct sx *sx);
extern void(*sx_xunlock)(struct sx *sx);
extern void(*mtx_init)(struct mtx *mutex, const char *name, const char *type, int opts);
extern void(*mtx_lock_spin_flags)(struct mtx *mutex, int flags);
extern void(*mtx_unlock_spin_flags)(struct mtx *mutex, int flags);
extern void(*mtx_lock_sleep)(struct mtx *mutex, int flags);
extern void(*mtx_unlock_sleep)(struct mtx *mutex, int flags);
extern int(*kern_reboot)(int magic);
extern void(*vm_map_lock_read)(struct vm_map *map);
extern int(*vm_map_lookup_entry)(struct vm_map *map, uint64_t address, struct vm_map_entry **entries);
extern void(*vm_map_unlock_read)(struct vm_map *map);
extern struct vmspace *(*vmspace_acquire_ref)(struct proc *p);
extern void(*vmspace_free)(struct vmspace *vm);
extern int(*vm_map_delete)(struct vm_map *map, uint64_t start, uint64_t end);
extern int(*vm_map_protect)(struct vm_map *map, uint64_t start, uint64_t end, int new_prot, uint64_t set_max);
extern int(*vm_map_findspace)(struct vm_map *map, uint64_t start, uint64_t length, uint64_t *addr);
extern int(*vm_map_insert)(struct vm_map *map, uint64_t object, uint64_t offset, uint64_t start, uint64_t end, int prot, int max, int cow);
extern void(*vm_map_lock)(struct vm_map *map);
extern void(*vm_map_unlock)(struct vm_map *map);
extern int(*proc_rwmem)(struct proc *p, struct uio *uio);

extern uint8_t *disable_console_output;
extern void *M_TEMP;
extern void **kernel_map;
extern void **prison0;
extern void **rootvnode;
extern void **allproc;
extern struct sysent *sysents;

extern uint64_t get_kbase();
extern void init_ksdk();

#endif
