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
		case 900:
			patch_900(kernbase);
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
			// core dump did not cause issues on 5.05
			// could be added in the future anyways
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
