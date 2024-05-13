#include "afr.h"

#include "hooks.h"

int sys_open_hook(struct thread *td, struct syscall_open *args) { // this entire hook must NOT be rip dependent
	uint32_t edx, eax;
    __asm__ ("rdmsr" : "=d"(edx), "=a"(eax) : "c"(0xC0000082));
	uint8_t* ptrKernel = (uint8_t *)((((uint64_t)edx) << 32) | (uint64_t)eax) - __Xfast_syscall;

	struct hook_data *data = (struct hook_data *)( *(uint64_t*)ptrKernel );
	struct proc_505 *castedProc = (struct proc_505 *)td->td_proc;
    struct ucred *cred = td->td_proc->p_ucred; // doesn't need a check as 5.05 is the same
	
	int(*_printf)(const char *fmt, ...);
	uint64_t(*_strlen)(const char *s);
	char *(*_strcpy)(char *dst, const char *src);
	char *(*_strncmp)(char *dst, const char *src, uint64_t len);
	int(*_sys_stat)(struct thread *td, void *args);
	int(*original_call)(struct thread *td, void *args);

	_printf = (void *)0;
	_strlen = (void *)0;
	_strcpy = (void *)0;
	_strncmp = (void *)0;
	_sys_stat = (void *)0;
	original_call = (void *)0;

	switch (data->cachedFw) {
		case 505:
			_printf = (void *)&ptrKernel[0x436040];
			_strlen = (void *)&ptrKernel[0x3B71A0];
			_strcpy = (void *)&ptrKernel[0x8F250];
			_strncmp = (void *)&ptrKernel[0x1B8FE0];
			_sys_stat = (void *)&ptrKernel[0x33DFE0];
			original_call = (void *)&ptrKernel[0x33B990];
			break;
		case 900:
			_printf = (void *)&ptrKernel[0xB7A30];
			_strlen = (void *)&ptrKernel[0x30F450];
			_strcpy = (void *)&ptrKernel[0x189F80];
			_strncmp = (void *)&ptrKernel[0x124750];
			_sys_stat = (void *)&ptrKernel[0x1DC4F0];
			original_call = (void *)&ptrKernel[0x1D9EC0];
			break;
		case 1100:
			_printf = (void *)&ptrKernel[0x2FCBD0];
			_strlen = (void *)&ptrKernel[0x21DC40];
			_strcpy = (void *)&ptrKernel[0x1AA590];
			_strncmp = (void *)&ptrKernel[0x313B10];
			_sys_stat = (void *)&ptrKernel[0xE8960];
			original_call = (void *)&ptrKernel[0xE6330];
			break;
		default:
			break;
	}

	int ret = -1;
	char possible_path[500];
	char statStruct[500];
	const char *real_path = args->path;
	
	//if (cred->cr_uid == 1)
	//if (!_strncmp(cachedFirmware == 505 ? castedProc->titleid : td->td_proc->titleid, data->cusa, 4))
		//_printf(data->print_debug1, cred->cr_uid, cachedFirmware == 505 ? castedProc->titleid : td->td_proc->titleid, args->path, ret);
	
	if (cred->cr_uid == 0 || _strncmp(cachedFirmware == 505 ? castedProc->titleid : td->td_proc->titleid, data->cusa, 4) != 0)
		goto original;

	_strcpy(possible_path, data->data_path);
	_strcpy(possible_path + _strlen(possible_path), cachedFirmware == 505 ? castedProc->titleid : td->td_proc->titleid);
	_strcpy(possible_path + _strlen(possible_path), args->path);
	
	data->statData->path = possible_path;
	data->statData->sb = &statStruct;
	int retVal = _sys_stat(td, data->statData);

	//if ((*(uint32_t *)((uint64_t)data->statData->sb + 0x08) & 0170000) != 0100000 || retVal != 0) // st_mode & 0170000 == 0100000 would be a file //... == 0040000 is a dir;
	if ((*(uint32_t *)((uint64_t)data->statData->sb + 0x08) & 0040000) || retVal != 0) // #define S_IFDIR  0040000
		goto original;

	args->path = possible_path;
	ret = original_call(td, args);

	//_printf(data->print_debug2, args->path, ret);

	if (ret > 0) {
		original:
		args->path = real_path;
		ret = original_call(td, args);

		//_printf(data->print_debug1, cred->cr_uid, cachedFirmware == 505 ? castedProc->titleid : td->td_proc->titleid, args->path, ret);
	}
	else {
		_printf(data->print_debug2, args->path, ret);
	}

	return ret;
}

int sys_openat_hook(struct thread *td, struct syscall_openat *args) { // this entire hook must NOT be rip dependent
	uint32_t edx, eax;
    __asm__ ("rdmsr" : "=d"(edx), "=a"(eax) : "c"(0xC0000082));
	uint8_t *ptrKernel = (uint8_t *)((((uint64_t)edx) << 32) | (uint64_t)eax) - __Xfast_syscall;

	struct hook_data *data = (struct hook_data *)(*(uint64_t *)ptrKernel);
	struct proc_505 *castedProc = (struct proc_505 *)td->td_proc;
    struct ucred *cred = td->td_proc->p_ucred; // doesn't need a check as 5.05 is the same
	
	int(*_printf)(const char *fmt, ...);
	uint64_t(*_strlen)(const char *s);
	char *(*_strcpy)(char *dst, const char *src);
	char *(*_strncmp)(char *dst, const char *src, uint64_t len);
	int(*_sys_stat)(struct thread *td, void *args);
	int(*original_call)(struct thread *td, void *args);

	_printf = (void *)0;
	_strlen = (void *)0;
	_strcpy = (void *)0;
	_strncmp = (void *)0;
	_sys_stat = (void *)0;
	original_call = (void *)0;

	switch (data->cachedFw) {
		case 505:
			_printf = (void *)&ptrKernel[0x436040];
			_strlen = (void *)&ptrKernel[0x3B71A0];
			_strcpy = (void *)&ptrKernel[0x8F250];
			_strncmp = (void *)&ptrKernel[0x1B8FE0];
			_sys_stat = (void *)&ptrKernel[0x33DFE0];
			original_call = (void *)&ptrKernel[0x33B9D0];
			break;
		case 900:
			_printf = (void *)&ptrKernel[0xB7A30];
			_strlen = (void *)&ptrKernel[0x30F450];
			_strcpy = (void *)&ptrKernel[0x189F80];
			_strncmp = (void *)&ptrKernel[0x124750];
			_sys_stat = (void *)&ptrKernel[0x1DC4F0];
			original_call = (void *)&ptrKernel[0x1D9F00];
			break;
		case 1100:
			_printf = (void *)&ptrKernel[0x2FCBD0];
			_strlen = (void *)&ptrKernel[0x21DC40];
			_strcpy = (void *)&ptrKernel[0x1AA590];
			_strncmp = (void *)&ptrKernel[0x313B10];
			_sys_stat = (void *)&ptrKernel[0xE8960];
			original_call = (void *)&ptrKernel[0xE6370];
			break;
		default:
			break;
	}

	int ret = -1;
	char possible_path[500];
	char statStruct[500];
	const char *real_path = args->path;
	
	if (cred->cr_uid == 1)
	//if (!_strncmp(cachedFirmware == 505 ? castedProc->titleid : td->td_proc->titleid, data->cusa, 4))
		_printf(data->print_debug1, cred->cr_uid, cachedFirmware == 505 ? castedProc->titleid : td->td_proc->titleid, args->path, 11111111);
	
	if (cred->cr_uid == 0 || _strncmp(cachedFirmware == 505 ? castedProc->titleid : td->td_proc->titleid, data->cusa, 4) != 0)
		goto original;

	_strcpy(possible_path, data->data_path);
	_strcpy(possible_path + _strlen(possible_path), cachedFirmware == 505 ? castedProc->titleid : td->td_proc->titleid);
	_strcpy(possible_path + _strlen(possible_path), args->path);
	
	data->statData_at->path = possible_path;
	data->statData_at->sb = &statStruct;
	int retVal = _sys_stat(td, data->statData_at);

	//if ((*(uint32_t *)((uint64_t)data->statData_at->sb + 0x08) & 0170000) != 0100000 || retVal != 0) // st_mode & 0170000 == 0100000 would be a file //... == 0040000 is a dir;
	if ((*(uint32_t *)((uint64_t)data->statData_at->sb + 0x08) & 0040000) || retVal != 0) // #define S_IFDIR  0040000
		goto original;

	args->path = possible_path;
	ret = original_call(td, args);

	//_printf(data->print_debug2, args->path, ret);

	if (ret > 0) {
		original:
		args->path = real_path;
		ret = original_call(td, args);

		//_printf(data->print_debug1, cred->cr_uid, cachedFirmware == 505 ? castedProc->titleid : td->td_proc->titleid, args->path, ret);
	} else {
		_printf(data->print_debug2, args->path, ret);
	}

	return ret;
}

void *rwx_alloc(uint64_t size) {
    uint64_t alignedSize = (size + 0x3FFFull) & ~0x3FFFull;
    return (void *)kmem_alloc(*kernel_map, alignedSize);
}

int install_afr_hooks() {
	// sys_open afr hook
	printf("[Frame4] <AFR> loading application file redirector...\n");

	struct hook_data *data = (struct hook_data *)rwx_alloc(sizeof(struct hook_data));
	//printf("[Frame4] <AFR> hook_data alloc done\n");
	data->statData = (struct syscall_stat *)rwx_alloc(sizeof(struct syscall_stat));
	data->statData_at = (struct syscall_stat *)rwx_alloc(sizeof(struct syscall_stat));
	//printf("[Frame4] <AFR> data->statData / data->statData_at alloc done\n");
	data->cachedFw = cachedFirmware;
	strcpy(data->data_path, "/user/data/");
	strcpy(data->cusa, "CUSA");
	strcpy(data->print_debug1, "[Frame4] <AFR> cred->cr_uid: %i, %s, %s (%i)\n");
	strcpy(data->print_debug2, "[Frame4] <AFR> Redirected: %s (%i)\n");

	//printf("[Frame4] <AFR> hook_data fully done\n");

	void *hook_ptr = (void *)rwx_alloc(0x10000);
	//printf("[Frame4] <AFR> hook_ptr alloc done\n");
	memcpy(hook_ptr, sys_open_hook, 0x1000);
	//printf("[Frame4] <AFR> hook_ptr memcpy done\n");

	void *hook_ptr_at = (void *)rwx_alloc(0x10000);
	//printf("[Frame4] <AFR> hook_ptr_at alloc done\n");
	memcpy(hook_ptr_at, sys_openat_hook, 0x1000);
	//printf("[Frame4] <AFR> hook_ptr_at memcpy done\n");

	cpu_disable_wp();
	*(uint64_t *)cachedKernelBase = (uint64_t)data;
	sysents[5].sy_call = hook_ptr; // sys_open
	sysents[499].sy_call = hook_ptr_at; // sys_openat
	cpu_enable_wp();
	//printf("[Frame4] <AFR> data ptr written to kernelbase\n");
	//printf("[Frame4] <AFR> sysents[5].sy_call assigned\n");
	//printf("[Frame4] <AFR> sysents[499].sy_call assigned\n");
	
	struct proc *p;
	p = proc_find_by_name("SceShellCore");
	if(!p) {
		printf("[Frame4] <AFR> could not find SceShellCore process!\n");
		return 1;
	}

	printf("[Frame4] <AFR> SceShellCore found, pid = %i\n", p->pid);

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
	
	uint8_t always_jump = 0xEB;
	uint64_t nop_slide = 0x9090909090909090;
	uint64_t mountPatchOffset = 0;
	uint64_t mountPatchOffset2 = 0;
	uint64_t disableCoreDumpPatch = 0;

	uint64_t fwCheckPatch = 0;

	switch (cachedFirmware) {
		case 505:
			mountPatchOffset = 0x31CA2A;
			fwCheckPatch = 0x3CCB79;
			break;
		case 900:
			mountPatchOffset = 0x3232C8;
			mountPatchOffset2 = 0x3232C0; // 9.00 specific check
			fwCheckPatch = 0x3C5EA7;
			disableCoreDumpPatch = 0x2EFC1B;
			break;
		case 1100:
			mountPatchOffset = 0x3210C6;
			mountPatchOffset2 = 0x3210BC; // 11.00 specific check
			fwCheckPatch = 0x3C41A7;
			disableCoreDumpPatch = 0x2ECF2B;
			break;
		default:
			break;
	}

	// mount /user on any process sandbox with read/write perm
	if (mountPatchOffset)
		proc_rw_mem(p, (void *)(args.maps[1].start + mountPatchOffset), 6, &nop_slide, 0, 1);
	if (mountPatchOffset2)
		proc_rw_mem(p, (void *)(args.maps[1].start + mountPatchOffset2), 6, &nop_slide, 0, 1);
	// other patches
	if (fwCheckPatch)
		proc_rw_mem(p, (void *)(args.maps[1].start + fwCheckPatch), 1, &always_jump, 0, 1);
	if (disableCoreDumpPatch) // thanks to osm
		proc_rw_mem(p, (void *)(args.maps[1].start + disableCoreDumpPatch), 5, (void *)"\x41\xC6\x45\x0C\x00", 0, 1); // mov byte ptr [r13 + 0x0C], 0

	return 0;
}
