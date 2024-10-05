#include "installer.h"

#include "syscall.h"

extern uint8_t kernelelf[];
extern int32_t kernelelf_size;

extern uint8_t debuggerbin[];
extern int32_t debuggerbin_size;

void ascii_art() {
	printf("\n\n");
	printf("___________                               _____  \n");
	printf("\\_   _____/___________    _____   ____   /  |  | \n");
	printf(" |    __) \\_  __ \\__  \\  /     \\_/ __ \\ /   |  |_\n");
	printf(" |     \\   |  | \\// __ \\|  Y Y  \\  ___//    ^   /\n");
	printf(" \\___  /   |__|  (____  /__|_|  /\\___  >____   | \n");
	printf("     \\/               \\/      \\/     \\/     |__| \n");
	printf("                                                       \n");
}

void patch_505(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t *)(kernbase + 0x1EA53D) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void *)(kernbase + 0x11730), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void *)(kernbase + 0x117B0), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void *)(kernbase + 0x117C0), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t *)(kernbase + 0x7673E0) = 0xC3;

	// self patches
	memcpy((void *)(kernbase + 0x13F03F), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void *)(kernbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t *)(kernbase + 0x30D9AA) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void *)(kernbase + 0x30DE01), "\xE9\xD0\x00\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t *)(kernbase + 0x194875) = 0x9090;

	// patch kmem_alloc
	*(uint8_t *)(kernbase + 0xFCD48) = VM_PROT_ALL;
	*(uint8_t *)(kernbase + 0xFCD56) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t *)(kernbase + 0x1A439D) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t *)(kernbase + 0x1EA767) = 0x9090;
	*(uint16_t *)(kernbase + 0x1EA682) = 0x9090;

	// patch copyinstr
	*(uint16_t *)(kernbase + 0x1EAB93) = 0x9090;
	*(uint16_t *)(kernbase + 0x1EABC3) = 0x9090;

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void *)(kernbase + 0x2A4EB3), "\x90\x90\x90\x90\x90\x90", 6);

	// patch blkno spam caused by aio bug (5.05 only)
	memcpy((void *)(kernbase + 0x68F188), "\x90\x90\x90\x90\x90", 5);
}

void patch_672(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t *)(kernbase + 0x3C15BD) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void *)(kernbase + 0x233BD0), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void *)(kernbase + 0x233C40), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void *)(kernbase + 0x233C50), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t *)(kernbase + 0x784120) = 0xC3;

	// self patches
	memcpy((void *)(kernbase + 0xAD2E4), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void *)(kernbase + 0x451DB8), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t *)(kernbase + 0x10F879) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void *)(kernbase + 0x10FD22), "\xE9\xE2\x02\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint8_t *)(kernbase + 0x3CECE1) = 0xEB;

	// patch kmem_alloc
	*(uint8_t *)(kernbase + 0x2507F5) = VM_PROT_ALL;
	*(uint8_t *)(kernbase + 0x250803) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t *)(kernbase + 0x45255D) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t *)(kernbase + 0x3C17F7) = 0x9090;
	memcpy((void *)(kernbase + 0x3C1803), "\x90\x90\x90", 3);
	*(uint16_t *)(kernbase + 0x3C1702) = 0x9090;
	memcpy((void *)(kernbase + 0x3C170E), "\x90\x90\x90", 3);

	// patch copyinstr
	*(uint16_t *)(kernbase + 0x3C1CA3) = 0x9090;
	*(uint16_t *)(kernbase + 0x3C1CE0) = 0x9090;
	memcpy((void *)(kernbase + 0x3C1CAF), "\x90\x90\x90", 3);

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void *)(kernbase + 0xBC8F6), "\x90\x90\x90\x90\x90\x90", 6);
	
	// patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
	memcpy((void *)(kernbase + 0x459763), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_70X(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t *)(kernbase + 0x2F04D) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void *)(kernbase + 0x1CB880), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void *)(kernbase + 0x1CB8F0), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void *)(kernbase + 0x1CB910), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t *)(kernbase + 0x7889E0) = 0xC3;

	// self patches
	memcpy((void *)(kernbase + 0x1D40BB), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void *)(kernbase + 0x264C08), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t *)(kernbase + 0x448D5) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void *)(kernbase + 0x44DAF), "\xE9\x7C\x02\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint8_t *)(kernbase + 0xC1F9A) = 0xEB;

	// patch kmem_alloc
	*(uint8_t *)(kernbase + 0x1171BE) = VM_PROT_ALL;
	*(uint8_t *)(kernbase + 0x1171C6) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t *)(kernbase + 0x2653D6) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t *)(kernbase + 0x2F287) = 0x9090;
	memcpy((void *)(kernbase + 0x2F293), "\x90\x90\x90", 3);
	*(uint16_t *)(kernbase + 0x2F192) = 0x9090;
	memcpy((void *)(kernbase + 0x2F19E), "\x90\x90\x90", 3);

	// patch copyinstr
	*(uint16_t *)(kernbase + 0x2F733) = 0x9090;
	*(uint16_t *)(kernbase + 0x2F770) = 0x9090;
	memcpy((void *)(kernbase + 0x2F73F), "\x90\x90\x90", 3);

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void *)(kernbase + 0x2BF756), "\x90\x90\x90\x90\x90\x90", 6);
	
	// patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
	memcpy((void *)(kernbase + 0x26C5F3), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_7XX(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t*)(kernbase + 0x28f80d) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void*)(kernbase + 0x364cd0), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void*)(kernbase + 0x364d40), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void*)(kernbase + 0x364d60), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t*)(kernbase + 0x77f960) = 0xC3;

	// self patches
	memcpy((void*)(kernbase + 0xdceb1), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void*)(kernbase + 0x3014c8), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t*)(kernbase + 0x361cf5) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void*)(kernbase + 0x3621cf), "\xE9\x7C\x02\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t*)(kernbase + 0x218AA2) = 0x9090;

	// patch kmem_alloc
	*(uint8_t*)(kernbase + 0x1754ac) = VM_PROT_ALL;
	*(uint8_t*)(kernbase + 0x1754b4) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t*)(kernbase + 0x301cc3) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t*)(kernbase + 0x28fa47) = 0x9090;
	memcpy((void*)(kernbase + 0x28fa53), "\x90\x90\x90", 3);
	*(uint16_t*)(kernbase + 0x28f952) = 0x9090;
	memcpy((void*)(kernbase + 0x28f95e), "\x90\x90\x90", 3);

	// patch copyinstr
	*(uint16_t*)(kernbase + 0x28fef3) = 0x9090;
	*(uint16_t*)(kernbase + 0x28ff30) = 0x9090;
	memcpy((void*)(kernbase + 0x28feff), "\x90\x90\x90", 3);

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void*)(kernbase + 0x003df2a6), "\x90\x90\x90\x90\x90\x90", 6);

	// patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
	memcpy((void*)(kernbase + 0x308f1e), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_755(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t*)(kernbase + 0x28f80d) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void*)(kernbase + 0x364cd0), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void*)(kernbase + 0x364d40), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void*)(kernbase + 0x364d60), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t*)(kernbase + 0x77f9a0) = 0xC3;

	// self patches
	memcpy((void*)(kernbase + 0xdceb1), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void*)(kernbase + 0x3014c8), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t*)(kernbase + 0x361cf5) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void*)(kernbase + 0x3621cf), "\xE9\x7C\x02\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t*)(kernbase + 0x218AA2) = 0x9090;

	// patch kmem_alloc
	*(uint8_t*)(kernbase + 0x1754ac) = VM_PROT_ALL;
	*(uint8_t*)(kernbase + 0x1754b4) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t*)(kernbase + 0x301cc3) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t*)(kernbase + 0x28fa47) = 0x9090;
	memcpy((void*)(kernbase + 0x28fa53), "\x90\x90\x90", 3);
	*(uint16_t*)(kernbase + 0x28f952) = 0x9090;
	memcpy((void*)(kernbase + 0x28f95e), "\x90\x90\x90", 3);

	// patch copyinstr
	*(uint16_t*)(kernbase + 0x28fef3) = 0x9090;
	*(uint16_t*)(kernbase + 0x28ff30) = 0x9090;
	memcpy((void*)(kernbase + 0x28feff), "\x90\x90\x90", 3);

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void*)(kernbase + 0x003df2a6), "\x90\x90\x90\x90\x90\x90", 6);

	// patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
	memcpy((void*)(kernbase + 0x308f1e), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_80X(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t*)(kernbase + 0x25e1cd) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void*)(kernbase + 0x1d5710), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void*)(kernbase + 0x1d5780), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void*)(kernbase + 0x1d57a0), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t*)(kernbase + 0x766df0) = 0xC3;

	// self patches
	memcpy((void*)(kernbase + 0xfed61), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void*)(kernbase + 0x3ec68b), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t*)(kernbase + 0x174155) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void*)(kernbase + 0x174173), "\xE9\x7C\x02\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t*)(kernbase + 0x2856f4) = 0x9090;

	// patch kmem_alloc
	*(uint8_t*)(kernbase + 0x1b4bc) = VM_PROT_ALL;
	*(uint8_t*)(kernbase + 0x1b4c4) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t*)(kernbase + 0x3ece76) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t*)(kernbase + 0x25e407) = 0x9090;
	memcpy((void*)(kernbase + 0x25e413), "\x90\x90\x90", 3);
	*(uint16_t*)(kernbase + 0x25e312) = 0x9090;
	memcpy((void*)(kernbase + 0x25e31e), "\x90\x90\x90", 3);

	// patch copyinstr
	*(uint16_t*)(kernbase + 0x25e8b3) = 0x9090;
	*(uint16_t*)(kernbase + 0x25e8f0) = 0x9090;
	memcpy((void*)(kernbase + 0x25e8bf), "\x90\x90\x90", 3);

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void*)(kernbase + 0x11eb86), "\x90\x90\x90\x90\x90\x90", 6);

	// patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
	memcpy((void*)(kernbase + 0x3f3fbe), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_8XX(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t*)(kernbase + 0x3a40fd) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void*)(kernbase + 0x2935e0), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void*)(kernbase + 0x293650), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void*)(kernbase + 0x293670), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t*)(kernbase + 0x76ceb0) = 0xC3;

	// self patches
	memcpy((void*)(kernbase + 0x84411), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void*)(kernbase + 0x14d6db), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t*)(kernbase + 0x132535) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void*)(kernbase + 0x132A0F), "\xE9\x7C\x02\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t*)(kernbase + 0x215154) = 0x9090;

	// patch kmem_alloc
	*(uint8_t*)(kernbase + 0x219a6c) = VM_PROT_ALL;
	*(uint8_t*)(kernbase + 0x219a74) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t*)(kernbase + 0x14dec6) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t*)(kernbase + 0x3a4337) = 0x9090;
	memcpy((void*)(kernbase + 0x3a4343), "\x90\x90\x90", 3);
	*(uint16_t*)(kernbase + 0x3a4242) = 0x9090;
	memcpy((void*)(kernbase + 0x3a424e), "\x90\x90\x90", 3);

	// patch copyinstr
	*(uint16_t*)(kernbase + 0x3a47e3) = 0x9090;
	*(uint16_t*)(kernbase + 0x3a4820) = 0x9090;
	memcpy((void*)(kernbase + 0x3a47ef), "\x90\x90\x90", 3);

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void*)(kernbase + 0x2773a6), "\x90\x90\x90\x90\x90\x90", 6);

	// patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
	memcpy((void*)(kernbase + 0x15500e), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_900(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t *)(kernbase + 0x2714BD) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void *)(kernbase + 0x8BC20), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void *)(kernbase + 0x8BC90), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void *)(kernbase + 0x8BCB0), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t *)(kernbase + 0x767E30) = 0xC3;

	// self patches
	memcpy((void *)(kernbase + 0x168051), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void *)(kernbase + 0x80B8B), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t *)(kernbase + 0x41F4E5) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void *)(kernbase + 0x41F9D1), "\xE9\x7C\x02\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t *)(kernbase + 0x5F824) = 0x9090;

	// patch kmem_alloc
	*(uint8_t *)(kernbase + 0x37BF3C) = VM_PROT_ALL;
	*(uint8_t *)(kernbase + 0x37BF44) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t *)(kernbase + 0x81376) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t *)(kernbase + 0x2716F7) = 0x9090;
	memcpy((void *)(kernbase + 0x271703), "\x90\x90\x90", 3);
	*(uint16_t *)(kernbase + 0x271602) = 0x9090;
	memcpy((void *)(kernbase + 0x27160E), "\x90\x90\x90", 3);

	// patch copyinstr
	*(uint16_t *)(kernbase + 0x271BA3) = 0x9090;
	*(uint16_t *)(kernbase + 0x271BE0) = 0x9090;
	memcpy((void *)(kernbase + 0x271BAF), "\x90\x90\x90", 3);

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void *)(kernbase + 0x152966), "\x90\x90\x90\x90\x90\x90", 6);

	// patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
	memcpy((void *)(kernbase + 0x884BE), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_90X(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t*)(kernbase + 0x27113d) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void*)(kernbase + 0x8bc20), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void*)(kernbase + 0x8bc90), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void*)(kernbase + 0x8bcb0), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t*)(kernbase + 0x765df0) = 0xC3;

	// self patches
	memcpy((void*)(kernbase + 0x168001), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void*)(kernbase + 0x80b8b), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t*)(kernbase + 0x41d455) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void*)(kernbase + 0x41d941), "\xE9\x7C\x02\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t*)(kernbase + 0x5f824) = 0x9090;

	// patch kmem_alloc
	*(uint8_t*)(kernbase + 0x37a13c) = VM_PROT_ALL;
	*(uint8_t*)(kernbase + 0x37a144) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t*)(kernbase + 0x81376) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t*)(kernbase + 0x271377) = 0x9090;
	memcpy((void*)(kernbase + 0x271383), "\x90\x90\x90", 3);
	*(uint16_t*)(kernbase + 0x271282) = 0x9090;
	memcpy((void*)(kernbase + 0x27128e), "\x90\x90\x90", 3);

	// patch copyinstr
	*(uint16_t*)(kernbase + 0x271823) = 0x9090;
	*(uint16_t*)(kernbase + 0x271860) = 0x9090;
	memcpy((void*)(kernbase + 0x27182f), "\x90\x90\x90", 3);

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void*)(kernbase + 0x152916), "\x90\x90\x90\x90\x90\x90", 6);

	// patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
	memcpy((void*)(kernbase + 0x884be), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_9XX(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t*)(kernbase + 0x201ccd) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void*)(kernbase + 0x32590), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void*)(kernbase + 0x32600), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void*)(kernbase + 0x32620), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t*)(kernbase + 0x7603c0) = 0xC3;

	// self patches
	memcpy((void*)(kernbase + 0x124aa1), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void*)(kernbase + 0x196d3b), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t*)(kernbase + 0x47a005) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void*)(kernbase + 0x47a4f1), "\xE9\x7C\x02\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t*)(kernbase + 0x29ae74) = 0x9090;

	// patch kmem_alloc
	*(uint8_t*)(kernbase + 0x188a9c) = VM_PROT_ALL;
	*(uint8_t*)(kernbase + 0x188aa4) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t*)(kernbase + 0x197526) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t*)(kernbase + 0x201f07) = 0x9090;
	memcpy((void*)(kernbase + 0x201f13), "\x90\x90\x90", 3);
	*(uint16_t*)(kernbase + 0x201e12) = 0x9090;
	memcpy((void*)(kernbase + 0x201e1e), "\x90\x90\x90", 3);

	// patch copyinstr
	*(uint16_t*)(kernbase + 0x2023b3) = 0x9090;
	*(uint16_t*)(kernbase + 0x2023f0) = 0x9090;
	memcpy((void*)(kernbase + 0x2023bf), "\x90\x90\x90", 3);

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void*)(kernbase + 0x2c9ca6), "\x90\x90\x90\x90\x90\x90", 6);

	// patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
	memcpy((void*)(kernbase + 0x19e66e), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_100X(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t*)(kernbase + 0x472d2d) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void*)(kernbase + 0xa5c60), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void*)(kernbase + 0xa5cd0), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void*)(kernbase + 0xa5cf0), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t*)(kernbase + 0x765620) = 0xC3;

	// self patches
	memcpy((void*)(kernbase + 0xef2c1), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void*)(kernbase + 0x39207b), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t*)(kernbase + 0x44e625) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void*)(kernbase + 0x44eb11), "\xE9\x7C\x02\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t*)(kernbase + 0x3bf3a4) = 0x9090;

	// patch kmem_alloc
	*(uint8_t*)(kernbase + 0x33b10c) = VM_PROT_ALL;
	*(uint8_t*)(kernbase + 0x33b114) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t*)(kernbase + 0x392866) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t*)(kernbase + 0x472f67) = 0x9090;
	memcpy((void*)(kernbase + 0x472f73), "\x90\x90\x90", 3);
	*(uint16_t*)(kernbase + 0x472e72) = 0x9090;
	memcpy((void*)(kernbase + 0x472e7e), "\x90\x90\x90", 3);

	// patch copyinstr
	*(uint16_t*)(kernbase + 0x473413) = 0x9090;
	*(uint16_t*)(kernbase + 0x473450) = 0x9090;
	memcpy((void*)(kernbase + 0x47341f), "\x90\x90\x90", 3);

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void*)(kernbase + 0x42cec6), "\x90\x90\x90\x90\x90\x90", 6);

	// patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
	memcpy((void*)(kernbase + 0x3999ae), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_10XX(uint64_t kernbase) {
	// patch memcpy first
	*(uint8_t*)(kernbase + 0xd737d) = 0xEB;

	// patch sceSblACMgrIsAllowedSystemLevelDebugging
	memcpy((void*)(kernbase + 0x1f4470), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrHasMmapSelfCapability
	memcpy((void*)(kernbase + 0x1f44e0), "\x31\xC0\xFF\xC0\xC3", 5);

	// patch sceSblACMgrIsAllowedToMmapSelf
	memcpy((void*)(kernbase + 0x1f4500), "\x31\xC0\xFF\xC0\xC3", 5);

	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t*)(kernbase + 0x7673d0) = 0xC3;

	// self patches
	memcpy((void*)(kernbase + 0x19e151), "\x31\xC0\x90\x90\x90", 5);

	// patch vm_map_protect check
	memcpy((void*)(kernbase + 0x47b2ec), "\x90\x90\x90\x90\x90\x90", 6);

	// patch ptrace, thanks 2much4u
	*(uint8_t*)(kernbase + 0x424e85) = 0xEB;

	// remove all these bullshit checks from ptrace, by golden
	memcpy((void*)(kernbase + 0x425371), "\xE9\x7C\x02\x00\x00", 5);

	// patch ASLR, thanks 2much4u
	*(uint16_t*)(kernbase + 0x345e04) = 0x9090;

	// patch kmem_alloc
	*(uint8_t*)(kernbase + 0x428a2c) = VM_PROT_ALL;
	*(uint8_t*)(kernbase + 0x428a34) = VM_PROT_ALL;

	// patch kernel elf loading, thanks to DeathRGH
	*(uint8_t*)(kernbase + 0x47bc1e) = 0xEB;

	// patch copyin/copyout to allow userland + kernel addresses in both params
	*(uint16_t*)(kernbase + 0xd75b7) = 0x9090;
	memcpy((void*)(kernbase + 0xd75c3), "\x90\x90\x90", 3);
	*(uint16_t*)(kernbase + 0xd74c2) = 0x9090;
	memcpy((void*)(kernbase + 0xd74ce), "\x90\x90\x90", 3);

	// patch copyinstr
	*(uint16_t*)(kernbase + 0xd7a63) = 0x9090;
	*(uint16_t*)(kernbase + 0xd7aa0) = 0x9090;
	memcpy((void*)(kernbase + 0xd7a6f), "\x90\x90\x90", 3);

	// patch to remove vm_fault: fault on nofault entry, addr %llx
	memcpy((void*)(kernbase + 0x303fa6), "\x90\x90\x90\x90\x90\x90", 6);

	// patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
	memcpy((void*)(kernbase + 0x482d4e), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_1100(uint64_t kernbase) {
	// patch memcpy first
    *(uint8_t *)(kernbase + 0x2DDDFD) = 0xEB;

    // patch sceSblACMgrIsAllowedSystemLevelDebugging
    memcpy((void *)(kernbase + 0x3D0DE0), "\x31\xC0\xFF\xC0\xC3", 5);

    // patch sceSblACMgrHasMmapSelfCapability
    memcpy((void *)(kernbase + 0x3D0E50), "\x31\xC0\xFF\xC0\xC3", 5);

    // patch sceSblACMgrIsAllowedToMmapSelf
    memcpy((void *)(kernbase + 0x3D0E70), "\x31\xC0\xFF\xC0\xC3", 5);

    // disable sysdump_perform_dump_on_fatal_trap
    // will continue execution and give more information on crash, such as rip
    *(uint8_t *)(kernbase + 0x76D210) = 0xC3;

    // self patches
    memcpy((void *)(kernbase + 0x157F91), "\x31\xC0\x90\x90\x90", 5);

    // patch vm_map_protect check
    memcpy((void *)(kernbase + 0x35C8EC), "\x90\x90\x90\x90\x90\x90", 6);

    // patch ptrace, thanks 2much4u
    *(uint8_t *)(kernbase + 0x384285) = 0xEB;

    // remove all these bullshit checks from ptrace, by golden
    memcpy((void *)(kernbase + 0x384771), "\xE9\x7C\x02\x00\x00", 5);

    // patch ASLR, thanks 2much4u
    *(uint16_t *)(kernbase + 0x3B11A4) = 0x9090;

    // patch kmem_alloc
    *(uint8_t *)(kernbase + 0x245EDC) = VM_PROT_ALL;
    *(uint8_t *)(kernbase + 0x245EE4) = VM_PROT_ALL;

    // patch kernel elf loading, thanks to DeathRGH
    *(uint8_t *)(kernbase + 0x35D221) = 0xEB;

    // patch copyin/copyout to allow userland + kernel addresses in both params
    *(uint16_t *)(kernbase + 0x2DE037) = 0x9090;
    memcpy((void *)(kernbase + 0x2DE043), "\x90\x90\x90", 3);
    *(uint16_t *)(kernbase + 0x2DDF42) = 0x9090;
    memcpy((void *)(kernbase + 0x2DDF4E), "\x90\x90\x90", 3);

    // patch copyinstr
    *(uint16_t *)(kernbase + 0x2DE4E3) = 0x9090;
    *(uint16_t *)(kernbase + 0x2DE520) = 0x9090;
    memcpy((void *)(kernbase + 0x2DE4EF), "\x90\x90\x90", 3);

    // patch to remove vm_fault: fault on nofault entry, addr %llx
    memcpy((void *)(kernbase + 0x31E8A6), "\x90\x90\x90\x90\x90\x90", 6);

    // patch 2mpage budget kernel panic after injecting an elf and quitting a newer game
    memcpy((void *)(kernbase + 0x36434E), "\x90\x90\x90\x90\x90\x90", 6);
}

void patch_kernel() {
	uint64_t kernbase = get_kbase();

	cpu_disable_wp();

	switch (cachedFirmware) {
	case 505:
		patch_505(kernbase);
		break;
	case 672:
		patch_672(kernbase);
		break;
	case 700:
		patch_70X(kernbase);
		break;
	case 701:
		patch_70X(kernbase);
		break;
	case 702:
		patch_70X(kernbase);
		break;
	case 750:
		patch_7XX(kernbase);
		break;
	case 751:
		patch_7XX(kernbase);
		break;
	case 755:
		patch_755(kernbase);
		break;
	case 800:
		patch_80X(kernbase);
		break;
	case 801:
		patch_80X(kernbase);
		break;
	case 803:
		patch_80X(kernbase);
		break;
	case 850:
		patch_8XX(kernbase);
		break;
	case 852:
		patch_8XX(kernbase);
		break;
	case 900:
		patch_900(kernbase);
		break;
	case 903:
		patch_90X(kernbase);
		break;
	case 904:
		patch_90X(kernbase);
		break;
	case 950:
		patch_9XX(kernbase);
		break;
	case 951:
		patch_9XX(kernbase);
		break;
	case 960:
		patch_9XX(kernbase);
		break;
	case 1000:
		patch_100X(kernbase);
		break;
	case 1001:
		patch_100X(kernbase);
		break;
	case 1050:
		patch_10XX(kernbase);
		break;
	case 1070:
		patch_10XX(kernbase);
		break;
	case 1071:
		patch_10XX(kernbase);
		break;
	case 1100:
		patch_1100(kernbase);
		break;
	}

	cpu_enable_wp();
}

int patch_shellcore() {
	struct proc *p = proc_find_by_name("SceShellCore");
	if(!p) {
		printf("[Frame4] <patch_shellcore> could not find SceShellCore process!\n");
		return 1;
	}

	printf("[Frame4] <patch_shellcore> SceShellCore found, pid = %i\n", p->pid);

	struct vmspace *vm;
	struct vm_map *map;
	struct vm_map_entry *entry;
	struct sys_proc_vm_map_args args;

	memset(&args, NULL, sizeof(struct sys_proc_vm_map_args));

	vm = p->p_vmspace;
	map = &vm->vm_map;
	args.num = map->nentries;

	uint64_t size = args.num * sizeof(struct proc_vm_map_entry);
	args.maps = (struct proc_vm_map_entry *)malloc(size, M_TEMP, 2);

	vm_map_lock_read(map);
    
	if (vm_map_lookup_entry(map, NULL, &entry)) {
		vm_map_unlock_read(map);
		return 1;
	}

	for (int i = 0; i < args.num; i++) {
		args.maps[i].start = entry->start;
		args.maps[i].end = entry->end;
		args.maps[i].offset = entry->offset;
		args.maps[i].prot = entry->prot & (entry->prot >> 8);
		memcpy(args.maps[i].name, entry->name, sizeof(args.maps[i].name));
            
		if (!(entry = entry->next)) {
			break;
		}
	}

	vm_map_unlock_read(map);
	
	uint64_t mountPatchOffset = 0;
	uint64_t mountPatchOffset2 = 0;
	uint64_t disableCoreDumpPatch = 0;
	uint64_t fwCheckPatch = 0;

	switch (cachedFirmware) {
		case 505:
			mountPatchOffset = 0x31CA2A;
			// mountPatchOffset2 (check did not exist on 5.05 yet)
			fwCheckPatch = 0x3CCB79;
			// @TODO: core dump
			break;
		case 672:
			mountPatchOffset = 0x33C475;
			// mountPatchOffset2 (check did not exist on 6.72 yet)
			fwCheckPatch = 0x3DB6F8;
			// @TODO: core dump
			break;
		case 702:
			mountPatchOffset = 0x31BBBB;
			// mountPatchOffset2 (check did not exist on 7.02 yet)
			fwCheckPatch = 0x3B3B38;
			// @TODO: core dump
			break;
		case 900:
			mountPatchOffset = 0x3232C8;
			mountPatchOffset2 = 0x3232C0;
			fwCheckPatch = 0x3C5EA7;
			disableCoreDumpPatch = 0x2EFC1B;
			break;
		case 1100:
			mountPatchOffset = 0x3210C6;
			mountPatchOffset2 = 0x3210BC;
			fwCheckPatch = 0x3C41A7;
			disableCoreDumpPatch = 0x2ECF2B;
			break;
		default:
			break;
	}

	// mount /user on any process sandbox with read/write perm
	uint64_t nop_slide = 0x9090909090909090;
	if (mountPatchOffset)
		proc_rw_mem(p, (void *)(args.maps[1].start + mountPatchOffset), 6, &nop_slide, 0, 1);
	if (mountPatchOffset2)
		proc_rw_mem(p, (void *)(args.maps[1].start + mountPatchOffset2), 6, &nop_slide, 0, 1);

	// other patches
	if (fwCheckPatch)
		proc_rw_mem(p, (void *)(args.maps[1].start + fwCheckPatch), 1, (void *)"\xEB", 0, 1); // always jump
	if (disableCoreDumpPatch) // thanks to osm
		proc_rw_mem(p, (void *)(args.maps[1].start + disableCoreDumpPatch), 5, (void *)"\x41\xC6\x45\x0C\x00", 0, 1); // mov byte ptr [r13 + 0x0C], 0

	return 0;
}

void *rwx_alloc(uint64_t size) {
	uint64_t alignedSize = (size + 0x3FFFull) & ~0x3FFFull;
	return (void *)kmem_alloc(*kernel_map, alignedSize);
}

int load_kdebugger() {
	uint64_t mapsize;
	void *kmemory;
	int (*payload_entry)(void *p);

	// calculate mapped size
	if (elf_mapped_size(kernelelf, &mapsize)) {
		printf("[Frame4] invalid kdebugger elf!\n");
		return 1;
	}

	// allocate memory
	kmemory = rwx_alloc(mapsize);
	if (!kmemory) {
		printf("[Frame4] could not allocate memory for kdebugger!\n");
		return 1;
	}

	// load the elf
	if (load_elf(kernelelf, kernelelf_size, kmemory, mapsize, (void **)&payload_entry)) {
		printf("[Frame4] could not load kdebugger elf!\n");
		return 1;
	}

	// call entry
	if (payload_entry(NULL)) {
		return 1;
	}

	return 0;
}

int load_debugger() {
	struct proc *p;
	struct vmspace *vm;
	struct vm_map *map;
	int r;

	p = proc_find_by_name("SceShellCore");
	if (!p) {
		printf("[Frame4] <load_debugger> could not find SceShellCore process!\n");
		return 1;
	}

	printf("[Frame4] <load_debugger> SceShellCore found, pid = %i\n", p->pid);

	vm = p->p_vmspace;
	map = &vm->vm_map;

	// allocate some memory
	vm_map_lock(map);
	r = vm_map_insert(map, NULL, NULL, PAYLOAD_BASE, PAYLOAD_BASE + PAYLOAD_SIZE, VM_PROT_ALL, VM_PROT_ALL, 0);
	vm_map_unlock(map);
	if (r) {
		printf("[Frame4] failed to allocate payload memory, removing previous allocations...\n");
		r = 0;

		vm_map_lock(map);
		r = vm_map_delete(map, PAYLOAD_BASE, PAYLOAD_BASE + PAYLOAD_SIZE);
		vm_map_unlock(map);

		if (r) {
			printf("[Frame4] failed to remove previous allocations, restart your console and try again!\n");
			return r;
		}

		printf("[Frame4] previous allocations removed, reallocating payload memory...\n");
		vm_map_lock(map);
		r = vm_map_insert(map, NULL, NULL, PAYLOAD_BASE, PAYLOAD_BASE + PAYLOAD_SIZE, VM_PROT_ALL, VM_PROT_ALL, 0);
		vm_map_unlock(map);
		if (r) {
			printf("[Frame4] failed to reallocate payload memory, restart your console and try again!\n");
		}
	}

	// write the payload
	r = proc_write_mem(p, (void *)PAYLOAD_BASE, debuggerbin_size, debuggerbin, NULL);
	if (r) {
		printf("[Frame4] failed to write payload!\n");
		return r;
	}

	// create a thread
	r = proc_create_thread(p, PAYLOAD_BASE);
	if (r) {
		printf("[Frame4] failed to create payload thread!\n");
		return r;
	}

	return 0;
}

int runinstaller() {
	init_ksdk();

	// enable uart
	*disable_console_output = 0;

	ascii_art();

	// patch the kernel
	printf("[Frame4] patching kernel...\n");
	patch_kernel();

	printf("[Frame4] loading kdebugger...\n");
	if (load_kdebugger()) {
		return 1;
	}

	printf("[Frame4] loading debugger...\n");
	if (load_debugger()) {
		return 1;
	}

	printf("[Frame4] patching shellcore...\n");
	patch_shellcore();

	printf("[Frame4] Frame4 loaded!\n");

	return 0;
}
