#include "proc.h"
#include "search.h"

int proc_list_handle(int fd, struct cmd_packet *packet) {
	void *data;
	uint64_t num;
	uint32_t length;

	sys_proc_list(NULL, &num);

	if (num > 0) {
		length = sizeof(struct proc_list_entry) * num;
		data = pfmalloc(length);
		if (!data) {
			net_send_status(fd, CMD_DATA_NULL);
			return 1;
		}

		sys_proc_list(data, &num);

		net_send_status(fd, CMD_SUCCESS);
		net_send_data(fd, &num, sizeof(uint32_t));
		net_send_data(fd, data, length);

		free(data);
		return 0;
	}

	net_send_status(fd, CMD_DATA_NULL);
	return 1;
}

int proc_read_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_read_packet *rp;
	void *data;
	uint64_t left;
	uint64_t address;

	rp = (struct cmd_proc_read_packet *)packet->data;

	if (rp) {
		// allocate a small buffer
		data = pfmalloc(NET_MAX_LENGTH);
		if (!data) {
			net_send_status(fd, CMD_DATA_NULL);
			return 0;
		}

		net_send_status(fd, CMD_SUCCESS);

		left = rp->length;
		address = rp->address;

		// send by chunks
		while (left > 0) {
			memset(data, NULL, NET_MAX_LENGTH);

			if (left > NET_MAX_LENGTH) {
				sys_proc_rw(rp->pid, address, data, NET_MAX_LENGTH, 0);
				net_send_data(fd, data, NET_MAX_LENGTH);

				address += NET_MAX_LENGTH;
				left -= NET_MAX_LENGTH;
			}
			else {
				sys_proc_rw(rp->pid, address, data, left, 0);
				net_send_data(fd, data, left);

				address += left;
				left -= left;
			}
		}

		free(data);
		return 0;
	}

	net_send_status(fd, CMD_DATA_NULL);
	return 1;
}

int proc_write_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_write_packet *wp;
	void *data;
	uint64_t left;
	uint64_t address;

	wp = (struct cmd_proc_write_packet *)packet->data;

	if (wp) {
		// only allocate a small buffer
		data = pfmalloc(NET_MAX_LENGTH);
		if (!data) {
			net_send_status(fd, CMD_DATA_NULL);
			return 1;
		}

		net_send_status(fd, CMD_SUCCESS);

		left = wp->length;
		address = wp->address;

		// write in chunks
		while (left > 0) {
			if (left > NET_MAX_LENGTH) {
				net_recv_data(fd, data, NET_MAX_LENGTH, 1);
				sys_proc_rw(wp->pid, address, data, NET_MAX_LENGTH, 1);

				address += NET_MAX_LENGTH;
				left -= NET_MAX_LENGTH;
			}
			else {
				net_recv_data(fd, data, left, 1);
				sys_proc_rw(wp->pid, address, data, left, 1);

				address += left;
				left -= left;
			}
		}

		net_send_status(fd, CMD_SUCCESS);

		free(data);
		return 0;
	}

	net_send_status(fd, CMD_DATA_NULL);
	return 1;
}

int proc_maps_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_maps_packet *mp;
	struct sys_proc_vm_map_args args;
	uint32_t size;
	uint32_t num;

	mp = (struct cmd_proc_maps_packet *)packet->data;

	if (mp) {
		memset(&args, NULL, sizeof(args));

		if (sys_proc_cmd(mp->pid, SYS_PROC_VM_MAP, &args)) {
			net_send_status(fd, CMD_ERROR);
			return 1;
		}

		size = args.num * sizeof(struct proc_vm_map_entry);

		args.maps = (struct proc_vm_map_entry *)pfmalloc(size); // need to chunk this
		if (!args.maps) {
			net_send_status(fd, CMD_DATA_NULL);
			return 1;
		}

		if (sys_proc_cmd(mp->pid, SYS_PROC_VM_MAP, &args)) {
			free(args.maps);
			net_send_status(fd, CMD_ERROR);
			return 1;
		}

		net_send_status(fd, CMD_SUCCESS);
		num = (uint32_t)args.num;
		net_send_data(fd, &num, sizeof(uint32_t));
		net_send_data(fd, args.maps, size);

		free(args.maps);
		return 0;
	}

	net_send_status(fd, CMD_ERROR);
	return 1;
}

int proc_install_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_install_packet *ip;
	struct sys_proc_install_args args;
	struct cmd_proc_install_response resp;

	ip = (struct cmd_proc_install_packet *)packet->data;

	if (!ip) {
		net_send_status(fd, CMD_DATA_NULL);
		return 1;
	}

	args.stubentryaddr = NULL;
	sys_proc_cmd(ip->pid, SYS_PROC_INSTALL, &args);

	if (!args.stubentryaddr) {
		net_send_status(fd, CMD_DATA_NULL);
		return 1;
	}

	resp.rpcstub = args.stubentryaddr;

	net_send_status(fd, CMD_SUCCESS);
	net_send_data(fd, &resp, CMD_PROC_INSTALL_RESPONSE_SIZE);

	return 0;
}

int proc_call_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_call_packet *cp;
	struct sys_proc_call_args args;
	struct cmd_proc_call_response resp;

	cp = (struct cmd_proc_call_packet *)packet->data;

	if (!cp) {
		net_send_status(fd, CMD_DATA_NULL);
		return 1;
	}

	// copy over the arguments for the call
	args.pid = cp->pid;
	args.rpcstub = cp->rpcstub;
	args.rax = NULL;
	args.rip = cp->rpc_rip;
	args.rdi = cp->rpc_rdi;
	args.rsi = cp->rpc_rsi;
	args.rdx = cp->rpc_rdx;
	args.rcx = cp->rpc_rcx;
	args.r8 = cp->rpc_r8;
	args.r9 = cp->rpc_r9;

	sys_proc_cmd(cp->pid, SYS_PROC_CALL, &args);

	resp.pid = cp->pid;
	resp.rpc_rax = args.rax;

	net_send_status(fd, CMD_SUCCESS);
	net_send_data(fd, &resp, CMD_PROC_CALL_RESPONSE_SIZE);

	return 0;
}

int proc_elf_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_elf_packet *ep;
	struct sys_proc_elf_args args;
	struct cmd_proc_elf_response resp;
	void *elf;

	ep = (struct cmd_proc_elf_packet *)packet->data;

	if (ep) {
		elf = pfmalloc(ep->length);
		if (!elf) {
			net_send_status(fd, CMD_DATA_NULL);
			return 1;
		}

		net_send_status(fd, CMD_SUCCESS);

		net_recv_data(fd, elf, ep->length, 1);

		args.elf = elf;

		if (sys_proc_cmd(ep->pid, SYS_PROC_ELF, &args)) {
			free(elf);
			net_send_status(fd, CMD_ERROR);
			return 1;
		}

		free(elf);

		resp.entry = args.entry;

		net_send_status(fd, CMD_SUCCESS);
		net_send_data(fd, &resp, CMD_PROC_ELF_RESPONSE_SIZE);

		return 0;
	}

	net_send_status(fd, CMD_ERROR);

	return 1;
}

int proc_protect_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_protect_packet *pp;
	struct sys_proc_protect_args args;

	pp = (struct cmd_proc_protect_packet *)packet->data;

	if (pp) {
		args.address = pp->address;
		args.length = pp->length;
		args.prot = pp->newprot;
		sys_proc_cmd(pp->pid, SYS_PROC_PROTECT, &args);

		net_send_status(fd, CMD_SUCCESS);
	}

	net_send_status(fd, CMD_DATA_NULL);

	return 0;
}

size_t proc_scan_getSizeOfValueType(cmd_proc_scan_valuetype valType) {
	switch (valType) {
	case valTypeUInt8:
	case valTypeInt8:
		return 1;
	case valTypeUInt16:
	case valTypeInt16:
		return 2;
	case valTypeUInt32:
	case valTypeInt32:
	case valTypeFloat:
		return 4;
	case valTypeUInt64:
	case valTypeInt64:
	case valTypeDouble:
		return 8;
	case valTypeArrBytes:
	case valTypeString:
	default:
		return NULL;
	}
}

bool proc_scan_compareValues(cmd_proc_scan_comparetype cmpType, cmd_proc_scan_valuetype valType, size_t valTypeLength, unsigned char *pScanValue, unsigned char *pMemoryValue, unsigned char *pExtraValue) {
	switch (cmpType) {
	case cmpTypeExactValue: {
		bool isFound = false;
		for (size_t j = 0; j < valTypeLength; j++) {
			isFound = (pScanValue[j] == pMemoryValue[j]);
			if (!isFound) {
				break;
			}
		}
		return isFound;
	}
	case cmpTypeFuzzyValue: {
		if (valType == valTypeFloat) {
			float diff = *(float *)pScanValue - *(float *)pMemoryValue;
			return diff < 1.0f && diff > -1.0f;
		}
		else if (valType == valTypeDouble) {
			double diff = *(double *)pScanValue - *(double *)pMemoryValue;
			return diff < 1.0 && diff > -1.0;
		}
		else {
			return false;
		}
	}
	case cmpTypeBiggerThan: {
		switch (valType) {
		case valTypeUInt8:
			return *pMemoryValue > *pScanValue;
		case valTypeInt8:
			return *(int8_t *)pMemoryValue > *(int8_t *)pScanValue;
		case valTypeUInt16:
			return *(uint16_t *)pMemoryValue > *(uint16_t *)pScanValue;
		case valTypeInt16:
			return *(int16_t *)pMemoryValue > *(int16_t *)pScanValue;
		case valTypeUInt32:
			return *(uint32_t *)pMemoryValue > *(uint32_t *)pScanValue;
		case valTypeInt32:
			return *(int32_t *)pMemoryValue > *(int32_t *)pScanValue;
		case valTypeUInt64:
			return *(uint64_t *)pMemoryValue > *(uint64_t *)pScanValue;
		case valTypeInt64:
			return *(int64_t *)pMemoryValue > *(int64_t *)pScanValue;
		case valTypeFloat:
			return *(float *)pMemoryValue > *(float *)pScanValue;
		case valTypeDouble:
			return *(double *)pMemoryValue > *(double *)pScanValue;
		case valTypeArrBytes:
		case valTypeString:
			return false;
		}
	}
	case cmpTypeSmallerThan: {
		switch (valType) {
		case valTypeUInt8:
			return *pMemoryValue < *pScanValue;
		case valTypeInt8:
			return *(int8_t *)pMemoryValue < *(int8_t *)pScanValue;
		case valTypeUInt16:
			return *(uint16_t *)pMemoryValue < *(uint16_t *)pScanValue;
		case valTypeInt16:
			return *(int16_t *)pMemoryValue < *(int16_t *)pScanValue;
		case valTypeUInt32:
			return *(uint32_t *)pMemoryValue < *(uint32_t *)pScanValue;
		case valTypeInt32:
			return *(int32_t *)pMemoryValue < *(int32_t *)pScanValue;
		case valTypeUInt64:
			return *(uint64_t *)pMemoryValue < *(uint64_t *)pScanValue;
		case valTypeInt64:
			return *(int64_t *)pMemoryValue < *(int64_t *)pScanValue;
		case valTypeFloat:
			return *(float *)pMemoryValue < *(float *)pScanValue;
		case valTypeDouble:
			return *(double *)pMemoryValue < *(double *)pScanValue;
		case valTypeArrBytes:
		case valTypeString:
			return false;
		}
	}
	case cmpTypeValueBetween: {
		switch (valType) {
		case valTypeUInt8:
			if (*pExtraValue > *pScanValue)
				return *pMemoryValue > *pScanValue && *pMemoryValue < *pExtraValue;
			return *pMemoryValue<*pScanValue && * pMemoryValue> * pExtraValue;
		case valTypeInt8:
			if (*(int8_t *)pExtraValue > *(int8_t *)pScanValue)
				return *(int8_t *)pMemoryValue > *(int8_t *)pScanValue && *(int8_t *)pMemoryValue < *(int8_t *)pExtraValue;
			return (*(int8_t *)pMemoryValue < *(int8_t *)pScanValue) && (*(int8_t *)pMemoryValue > *(int8_t *)pExtraValue);
		case valTypeUInt16:
			if (*(uint16_t *)pExtraValue > *(uint16_t *)pScanValue)
				return *(uint16_t *)pMemoryValue > *(uint16_t *)pScanValue && *(uint16_t *)pMemoryValue < *(uint16_t *)pExtraValue;
			return (*(uint16_t *)pMemoryValue < *(uint16_t *)pScanValue) && (*(uint16_t *)pMemoryValue > *(uint16_t *)pExtraValue);
		case valTypeInt16:
			if (*(int16_t *)pExtraValue > *(int16_t *)pScanValue)
				return *(int16_t *)pMemoryValue > *(int16_t *)pScanValue && *(int16_t *)pMemoryValue < *(int16_t *)pExtraValue;
			return (*(int16_t *)pMemoryValue < *(int16_t *)pScanValue) && (*(int16_t *)pMemoryValue > *(int16_t *)pExtraValue);
		case valTypeUInt32:
			if (*(uint32_t *)pExtraValue > *(uint32_t *)pScanValue)
				return *(uint32_t *)pMemoryValue > *(uint32_t *)pScanValue && *(uint32_t *)pMemoryValue < *(uint32_t *)pExtraValue;
			return (*(uint32_t *)pMemoryValue < *(uint32_t *)pScanValue) && (*(uint32_t *)pMemoryValue > *(uint32_t *)pExtraValue);
		case valTypeInt32:
			if (*(int32_t *)pExtraValue > *(int32_t *)pScanValue)
				return *(int32_t *)pMemoryValue > *(int32_t *)pScanValue && *(int32_t *)pMemoryValue < *(int32_t *)pExtraValue;
			return (*(int32_t *)pMemoryValue < *(int32_t *)pScanValue) && (*(int32_t *)pMemoryValue > *(int32_t *)pExtraValue);
		case valTypeUInt64:
			if (*(uint64_t *)pExtraValue > *(uint64_t *)pScanValue)
				return *(uint64_t *)pMemoryValue > *(uint64_t *)pScanValue && *(uint64_t *)pMemoryValue < *(uint64_t *)pExtraValue;
			return (*(uint64_t *)pMemoryValue < *(uint64_t *)pScanValue) && (*(uint64_t *)pMemoryValue > *(uint64_t *)pExtraValue);
		case valTypeInt64:
			if (*(int64_t *)pExtraValue > *(int64_t *)pScanValue)
				return *(int64_t *)pMemoryValue > *(int64_t *)pScanValue && *(int64_t *)pMemoryValue < *(int64_t *)pExtraValue;
			return (*(int64_t *)pMemoryValue < *(int64_t *)pScanValue) && (*(int64_t *)pMemoryValue > *(int64_t *)pExtraValue);
		case valTypeFloat:
			if (*(float *)pExtraValue > *(float *)pScanValue)
				return *(float *)pMemoryValue > *(float *)pScanValue && *(float *)pMemoryValue < *(float *)pExtraValue;
			return (*(float *)pMemoryValue < *(float *)pScanValue) && (*(float *)pMemoryValue > *(float *)pExtraValue);
		case valTypeDouble:
			if (*(double *)pExtraValue > *(double *)pScanValue)
				return *(double *)pMemoryValue > *(double *)pScanValue && *(double *)pMemoryValue < *(double *)pExtraValue;
			return (*(double *)pMemoryValue < *(double *)pScanValue) && (*(double *)pMemoryValue > *(double *)pExtraValue);
		case valTypeArrBytes:
		case valTypeString:
			return false;
		}
	}
	case cmpTypeIncreasedValue: {
		switch (valType) {
		case valTypeUInt8:
			return *pMemoryValue > *pScanValue; // was pExtraValue
		case valTypeInt8:
			return *(int8_t *)pMemoryValue > *(int8_t *)pScanValue;
		case valTypeUInt16:
			return *(uint16_t *)pMemoryValue > *(uint16_t *)pScanValue;
		case valTypeInt16:
			return *(int16_t *)pMemoryValue > *(int16_t *)pScanValue;
		case valTypeUInt32:
			return *(uint32_t *)pMemoryValue > *(uint32_t *)pScanValue;
		case valTypeInt32:
			return *(int32_t *)pMemoryValue > *(int32_t *)pScanValue;
		case valTypeUInt64:
			return *(uint64_t *)pMemoryValue > *(uint64_t *)pScanValue;
		case valTypeInt64:
			return *(int64_t *)pMemoryValue > *(int64_t *)pScanValue;
		case valTypeFloat:
			return *(float *)pMemoryValue > *(float *)pScanValue;
		case valTypeDouble:
			return *(double *)pMemoryValue > *(double *)pScanValue;
		case valTypeArrBytes:
		case valTypeString:
			return false;
		}
	}
	case cmpTypeIncreasedValueBy: {
		switch (valType) {
		case valTypeUInt8:
			return *pMemoryValue == (*pExtraValue + *pScanValue);
		case valTypeInt8:
			return *(int8_t *)pMemoryValue == (*(int8_t *)pExtraValue + *(int8_t *)pScanValue);
		case valTypeUInt16:
			return *(uint16_t *)pMemoryValue == (*(uint16_t *)pExtraValue + *(uint16_t *)pScanValue);
		case valTypeInt16:
			return *(int16_t *)pMemoryValue == (*(int16_t *)pExtraValue + *(int16_t *)pScanValue);
		case valTypeUInt32:
			return *(uint32_t *)pMemoryValue == (*(uint32_t *)pExtraValue + *(uint32_t *)pScanValue);
		case valTypeInt32:
			return *(int32_t *)pMemoryValue == (*(int32_t *)pExtraValue + *(int32_t *)pScanValue);
		case valTypeUInt64:
			return *(uint64_t *)pMemoryValue == (*(uint64_t *)pExtraValue + *(uint64_t *)pScanValue);
		case valTypeInt64:
			return *(int64_t *)pMemoryValue == (*(int64_t *)pExtraValue + *(int64_t *)pScanValue);
		case valTypeFloat:
			return *(float *)pMemoryValue == (*(float *)pExtraValue + *(float *)pScanValue);
		case valTypeDouble:
			return *(double *)pMemoryValue == (*(double *)pExtraValue + *(float *)pScanValue);
		case valTypeArrBytes:
		case valTypeString:
			return false;
		}
	}
	case cmpTypeDecreasedValue: {
		switch (valType) {
		case valTypeUInt8:
			return *pMemoryValue < *pScanValue; // was pExtraValue
		case valTypeInt8:
			return *(int8_t *)pMemoryValue < *(int8_t *)pScanValue;
		case valTypeUInt16:
			return *(uint16_t *)pMemoryValue < *(uint16_t *)pScanValue;
		case valTypeInt16:
			return *(int16_t *)pMemoryValue < *(int16_t *)pScanValue;
		case valTypeUInt32:
			return *(uint32_t *)pMemoryValue < *(uint32_t *)pScanValue;
		case valTypeInt32:
			return *(int32_t *)pMemoryValue < *(int32_t *)pScanValue;
		case valTypeUInt64:
			return *(uint64_t *)pMemoryValue < *(uint64_t *)pScanValue;
		case valTypeInt64:
			return *(int64_t *)pMemoryValue < *(int64_t *)pScanValue;
		case valTypeFloat:
			return *(float *)pMemoryValue < *(float *)pScanValue;
		case valTypeDouble:
			return *(double *)pMemoryValue < *(double *)pScanValue;
		case valTypeArrBytes:
		case valTypeString:
			return false;
		}
	}
	case cmpTypeDecreasedValueBy: {
		switch (valType) {
		case valTypeUInt8:
			return *pMemoryValue == (*pScanValue - *pExtraValue);
		case valTypeInt8:
			return *(int8_t *)pMemoryValue == (*(int8_t *)pScanValue - *(int8_t *)pExtraValue);
		case valTypeUInt16:
			return *(uint16_t *)pMemoryValue == (*(uint16_t *)pScanValue - *(uint16_t *)pExtraValue);
		case valTypeInt16:
			return *(int16_t *)pMemoryValue == (*(int16_t *)pScanValue - *(int16_t *)pExtraValue);
		case valTypeUInt32:
			return *(uint32_t *)pMemoryValue == (*(uint32_t *)pScanValue - *(uint32_t *)pExtraValue);
		case valTypeInt32:
			return *(int32_t *)pMemoryValue == (*(int32_t *)pScanValue - *(int32_t *)pExtraValue);
		case valTypeUInt64:
			return *(uint64_t *)pMemoryValue == (*(uint64_t *)pScanValue - *(uint64_t *)pExtraValue);
		case valTypeInt64:
			return *(int64_t *)pMemoryValue == (*(int64_t *)pScanValue - *(int64_t *)pExtraValue);
		case valTypeFloat:
			return *(float *)pMemoryValue == (*(float *)pScanValue - *(float *)pExtraValue);
		case valTypeDouble:
			return *(double *)pMemoryValue == (*(double *)pScanValue - *(float *)pExtraValue);
		case valTypeArrBytes:
		case valTypeString:
			return false;
		}
	}
	case cmpTypeChangedValue: {
		switch (valType) {
		case valTypeUInt8:
			return *pMemoryValue != *pScanValue; // was pExtraValue
		case valTypeInt8:
			return *(int8_t *)pMemoryValue != *(int8_t *)pScanValue;
		case valTypeUInt16:
			return *(uint16_t *)pMemoryValue != *(uint16_t *)pScanValue;
		case valTypeInt16:
			return *(int16_t *)pMemoryValue != *(int16_t *)pScanValue;
		case valTypeUInt32:
			return *(uint32_t *)pMemoryValue != *(uint32_t *)pScanValue;
		case valTypeInt32:
			return *(int32_t *)pMemoryValue != *(int32_t *)pScanValue;
		case valTypeUInt64:
			return *(uint64_t *)pMemoryValue != *(uint64_t *)pScanValue;
		case valTypeInt64:
			return *(int64_t *)pMemoryValue != *(int64_t *)pScanValue;
		case valTypeFloat:
			return *(float *)pMemoryValue != *(float *)pScanValue;
		case valTypeDouble:
			return *(double *)pMemoryValue != *(double *)pScanValue;
		case valTypeArrBytes:
		case valTypeString:
			return false;
		}
	}
	case cmpTypeUnchangedValue: {
		switch (valType) {
		case valTypeUInt8:
			return *pMemoryValue == *pScanValue; // was pExtraValue
		case valTypeInt8:
			return *(int8_t *)pMemoryValue == *(int8_t *)pScanValue;
		case valTypeUInt16:
			return *(uint16_t *)pMemoryValue == *(uint16_t *)pScanValue;
		case valTypeInt16:
			return *(int16_t *)pMemoryValue == *(int16_t *)pScanValue;
		case valTypeUInt32:
			return *(uint32_t *)pMemoryValue == *(uint32_t *)pScanValue;
		case valTypeInt32:
			return *(int32_t *)pMemoryValue == *(int32_t *)pScanValue;
		case valTypeUInt64:
			return *(uint64_t *)pMemoryValue == *(uint64_t *)pScanValue;
		case valTypeInt64:
			return *(int64_t *)pMemoryValue == *(int64_t *)pScanValue;
		case valTypeFloat:
			return *(float *)pMemoryValue == *(float *)pScanValue;
		case valTypeDouble:
			return *(double *)pMemoryValue == *(double *)pScanValue;
		case valTypeArrBytes:
		case valTypeString:
			return false;
		}
	}
	case cmpTypeUnknownInitialValue:
		return true;
	}
	return false;
}

struct saved_section {
	uint64_t start;
	uint64_t end;
	int fileId;
};

struct saved_section_list {
	struct saved_section *sections;
	uint64_t count;
};

struct saved_section_list savedSectionList;

bool scan_requires_last_value(uint8_t type) {
	if (type == cmpTypeIncreasedValue ||
		type == cmpTypeIncreasedValueBy ||
		type == cmpTypeDecreasedValue ||
		type == cmpTypeDecreasedValueBy ||
		type == cmpTypeChangedValue ||
		type == cmpTypeUnchangedValue)
		return true;
	else
		return false;
}

void *addressBuffer;

// "address_is_in_list" is still broken
// exact value seems to be fine
// last broke on unchanged value
// maybe also check "proc_scan_compareValues"
// ~DeathRGH 19.09.2020
uint64_t lastMatch = 0;
bool the_nameless_variable_previously_known_as_verkackt = false;
int address_is_in_list(int fileHandle, uint64_t totalResultCount_lastScan, uint64_t address) {
	if (lastMatch >= totalResultCount_lastScan)
		return 0;

	for (uint64_t j = lastMatch; j < totalResultCount_lastScan; j++) {
		if (!the_nameless_variable_previously_known_as_verkackt)
			read(fileHandle, addressBuffer, sizeof(uint64_t));

		if (*(uint64_t *)addressBuffer == address) {
			lastMatch = j + 1;
			the_nameless_variable_previously_known_as_verkackt = false;
			break;
		}
		else if (*(uint64_t *)addressBuffer > address) {
			the_nameless_variable_previously_known_as_verkackt = true;
			break;
		}
		else
			the_nameless_variable_previously_known_as_verkackt = false;
	}

	if (!the_nameless_variable_previously_known_as_verkackt)
		return 1;
	else
		return 0;
}

// not fully working yet
int proc_scan_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_scan_packet *sp = (struct cmd_proc_scan_packet *)packet->data;

	if (!sp) {
		net_send_status(fd, CMD_DATA_NULL);
		return 1;
	}

	size_t valueLength = proc_scan_getSizeOfValueType(sp->valueType);
	if (!valueLength)
		valueLength = sp->lenData;

	unsigned char *data = (unsigned char *)pfmalloc(sp->lenData);
	if (!data) {
		net_send_status(fd, CMD_DATA_NULL);
		return 1;
	}

	net_send_status(fd, CMD_SUCCESS);
	net_recv_data(fd, data, sp->lenData, 1);

	if (sp->firstScan == 1) {
		struct sys_proc_vm_map_args args;
		memset(&args, NULL, sizeof(struct sys_proc_vm_map_args));
		if (sys_proc_cmd(sp->pid, SYS_PROC_VM_MAP, &args)) {
			net_send_status(fd, CMD_ERROR);

			free(data);
			return 1;
		}

		size_t size = args.num * sizeof(struct proc_vm_map_entry);
		args.maps = (struct proc_vm_map_entry *)pfmalloc(size);
		if (!args.maps) {
			net_send_status(fd, CMD_DATA_NULL);

			free(data);
			return 1;
		}

		if (sys_proc_cmd(sp->pid, SYS_PROC_VM_MAP, &args)) {
			net_send_status(fd, CMD_ERROR);

			free(args.maps);
			free(data);
			return 1;
		}

		net_send_status(fd, CMD_SUCCESS);

		uint8_t *selectedSections = pfmalloc(args.num - 1);
		if (!selectedSections) {
			net_send_status(fd, CMD_DATA_NULL);

			free(data);
			free(args.maps);
			return 1;
		}

		net_recv_data(fd, selectedSections, args.num - 1, 1);

		uprintf("########## scan start");

		if (state == STARTED)
			free_results(&results);

		// allocate results memory
		allocate_results(&results, 0x1000);

		unsigned char *pExtraValue = valueLength == sp->lenData ? NULL : &data[valueLength];
		unsigned char *scanBuffer = (unsigned char *)pfmalloc(SCAN_MAX_LENGTH);
		if (!scanBuffer) {
			net_send_status(fd, CMD_DATA_NULL);

			free(data);
			free(args.maps);
			free(selectedSections);
			return 1;
		}

		if (savedSectionList.sections)
			free(savedSectionList.sections);

		savedSectionList.count = 0;
		savedSectionList.sections = (struct saved_section *)pfmalloc((args.num - 1) * sizeof(struct saved_section));
		memset(savedSectionList.sections, NULL, (args.num - 1) * sizeof(struct saved_section));

		if (!savedSectionList.sections) {
			net_send_status(fd, CMD_DATA_NULL);

			free(data);
			free(args.maps);
			free(selectedSections);
			free(scanBuffer);
			return 1;
		}

		for (size_t i = 1; i < args.num; i++) {
			if (selectedSections[i - 1] == 0) {
				uprintf("skipping: %s   0x%llX - 0x%llX   %iKB", args.maps[i].name, args.maps[i].start, args.maps[i].end, (args.maps[i].end - args.maps[i].start) / 1024);
				continue;
			}

			if ((args.maps[i].prot & PROT_READ) != PROT_READ) {
				uprintf("skipping: %s   0x%llX - 0x%llX   %iKB   (prot != PROT_READ)", args.maps[i].name, args.maps[i].start, args.maps[i].end, (args.maps[i].end - args.maps[i].start) / 1024);
				continue;
			}

			uprintf("scanning: %s   0x%llX - 0x%llX   %iKB", args.maps[i].name, args.maps[i].start, args.maps[i].end, (args.maps[i].end - args.maps[i].start) / 1024);

			char tempBufInit[32];
			snprintf(tempBufInit, sizeof(tempBufInit), "/data/scan_temp/init/%i", i - 1);
			char tempBufCur[32];
			snprintf(tempBufCur, sizeof(tempBufCur), "/data/scan_temp/cur/%i", i - 1);

			struct saved_section section;
			section.start = args.maps[i].start;
			section.end = args.maps[i].end;
			section.fileId = i - 1;

			savedSectionList.sections[savedSectionList.count] = section;
			savedSectionList.count++;

			int fileHandleInit;
			int mode = O_CREAT | O_RDWR | O_TRUNC;
			if ((fileHandleInit = open(tempBufInit, mode, 0777)) < 0) {
				net_send_status(fd, CMD_ERROR);

				free(data);
				free(args.maps);
				free(selectedSections);
				free(scanBuffer);
				free(savedSectionList.sections);

				return 1;
			}

			int fileHandleCur;
			if ((fileHandleCur = open(tempBufCur, mode, 0777)) < 0) {
				net_send_status(fd, CMD_ERROR);

				free(data);
				free(args.maps);
				free(selectedSections);
				free(scanBuffer);
				free(savedSectionList.sections);

				return 1;
			}

			size_t sectionLength = args.maps[i].end - args.maps[i].start;
			uint64_t curAddress = args.maps[i].start;
			uint64_t bytesLeft = sectionLength;

			while (bytesLeft > 0) {
				memset(scanBuffer, NULL, SCAN_MAX_LENGTH);

				if (bytesLeft > SCAN_MAX_LENGTH) {
					sys_proc_rw(sp->pid, curAddress, scanBuffer, SCAN_MAX_LENGTH, 0);
					write(fileHandleInit, scanBuffer, SCAN_MAX_LENGTH);
					write(fileHandleCur, scanBuffer, SCAN_MAX_LENGTH);

					for (uint64_t j = 0; j < SCAN_MAX_LENGTH; j += valueLength) {
						if (proc_scan_compareValues(sp->compareType, sp->valueType, valueLength, data, scanBuffer + j, pExtraValue))
							add_result(&results, curAddress + j);
					}

					curAddress += SCAN_MAX_LENGTH;
					bytesLeft -= SCAN_MAX_LENGTH;
				}
				else {
					sys_proc_rw(sp->pid, curAddress, scanBuffer, bytesLeft, 0);
					write(fileHandleInit, scanBuffer, bytesLeft);
					write(fileHandleCur, scanBuffer, bytesLeft);

					for (uint64_t j = 0; j < bytesLeft; j += valueLength) {
						if (proc_scan_compareValues(sp->compareType, sp->valueType, valueLength, data, scanBuffer + j, pExtraValue))
							add_result(&results, curAddress + j);
					}

					curAddress += bytesLeft;
					bytesLeft -= bytesLeft;
				}
			}

			close(fileHandleInit);
			close(fileHandleCur);
		}

		write_pending_results_to_file();

		net_send_status(fd, CMD_SUCCESS);
		uprintf("########## scan done");

		free(data);
		free(args.maps);
		free(selectedSections);
		free(scanBuffer);
	}
	else {
		uprintf("########## next scan start");

		rename("/data/scan_temp/results", "/data/scan_temp/results_old");
		lastMatch = 0; // reset lastMatch of function "address_is_in_list"
		the_nameless_variable_previously_known_as_verkackt = false; // dont even ask

		unsigned char *pExtraValue = valueLength == sp->lenData ? NULL : &data[valueLength];

		void *valueBuffer = pfmalloc(valueLength);
		if (!valueBuffer) {
			net_send_status(fd, CMD_DATA_NULL);
			return 1;
		}

		addressBuffer = pfmalloc(sizeof(uint64_t));
		if (!addressBuffer) {
			net_send_status(fd, CMD_DATA_NULL);

			free(valueBuffer);
			return 1;
		}

		memset(addressBuffer, NULL, sizeof(uint64_t));

		void *resultAddressBuffer = pfmalloc(sizeof(uint64_t));
		if (!resultAddressBuffer) {
			net_send_status(fd, CMD_DATA_NULL);

			free(valueBuffer);
			free(addressBuffer);
			return 1;
		}

		int fileHandle_resultsOld;
		if ((fileHandle_resultsOld = open("/data/scan_temp/results_old", O_RDONLY, 0)) < 0) {
			net_send_status(fd, CMD_ERROR);

			free(valueBuffer);
			free(addressBuffer);
			free(resultAddressBuffer);
			return 1;
		}

		uint64_t totalResultCount = results.countTotal;
		results.countTotal = 0;

		if (totalResultCount <= 0 /*1000000*/) { // 1 million takes ~11sec
			// do this when there are only a few results left
			for (uint32_t index = 0; index < totalResultCount; index++) {
				if (index % 10000 == 0)
					uprintf("%lli/%lli done", index, totalResultCount);

				read(fileHandle_resultsOld, resultAddressBuffer, sizeof(uint64_t));
				sys_proc_rw(sp->pid, *(uint64_t *)resultAddressBuffer, valueBuffer, valueLength, 0);

				if (sp->compareType == cmpTypeIncreasedValue ||
					sp->compareType == cmpTypeIncreasedValueBy ||
					sp->compareType == cmpTypeDecreasedValue ||
					sp->compareType == cmpTypeDecreasedValueBy ||
					sp->compareType == cmpTypeChangedValue ||
					sp->compareType == cmpTypeUnchangedValue) {
					// TODO:
					// add dumping for sections here aswell
					// after that uncomment the 1 million in if statement
				}

				if (proc_scan_compareValues(sp->compareType, sp->valueType, valueLength, data, valueBuffer, pExtraValue))
					add_result(&results, *(uint64_t *)resultAddressBuffer);
			}

			write_pending_results_to_file();
		}
		else {
			unsigned char *scanBuffer = (unsigned char *)pfmalloc(SCAN_MAX_LENGTH);
			if (!scanBuffer) {
				net_send_status(fd, CMD_DATA_NULL);

				free(valueBuffer);
				free(addressBuffer);
				free(resultAddressBuffer);
				return 1;
			}

			unsigned char *fileBuffer = (unsigned char *)pfmalloc(SCAN_MAX_LENGTH);
			if (!fileBuffer) {
				net_send_status(fd, CMD_DATA_NULL);

				free(valueBuffer);
				free(addressBuffer);
				free(resultAddressBuffer);
				return 1;
			}

			for (int sectionIndex = 0; sectionIndex < savedSectionList.count; sectionIndex++) {
				uprintf("saved section index %i", savedSectionList.sections[sectionIndex].fileId);

				char tempBufCur[32];
				snprintf(tempBufCur, sizeof(tempBufCur), "/data/scan_temp/cur/%i", savedSectionList.sections[sectionIndex].fileId);
				char tempBufOld[32];
				snprintf(tempBufOld, sizeof(tempBufOld), "/data/scan_temp/old/%i", savedSectionList.sections[sectionIndex].fileId);

				rename(tempBufCur, tempBufOld);

				int fileHandleCur;
				int mode = O_CREAT | O_RDWR | O_TRUNC;
				if ((fileHandleCur = open(tempBufCur, mode, 0777)) < 0) {
					net_send_status(fd, CMD_ERROR);

					free(valueBuffer);
					free(addressBuffer);
					free(resultAddressBuffer);
					free(scanBuffer);
					free(fileBuffer);

					return 1;
				}

				int fileHandleOld;
				if ((fileHandleOld = open(tempBufOld, O_RDONLY, 0)) < 0) {
					net_send_status(fd, CMD_ERROR);

					close(fileHandleCur);
					free(valueBuffer);
					free(addressBuffer);
					free(resultAddressBuffer);
					free(scanBuffer);
					free(fileBuffer);

					return 1;
				}

				uint64_t curAddress = savedSectionList.sections[sectionIndex].start;

				if (curAddress <= 0) {
					uprintf("skipping saved section %i because the scan value was not found in it", savedSectionList.sections[sectionIndex].fileId);

					close(fileHandleCur);
					close(fileHandleOld);

					continue;
				}

				uprintf("saved section %i is beeing processed", savedSectionList.sections[sectionIndex].fileId);

				int foundValueInCurrentSection = 0;
				uint64_t bytesLeft = savedSectionList.sections[sectionIndex].end - savedSectionList.sections[sectionIndex].start;

				while (bytesLeft > 0) {
					memset(scanBuffer, NULL, SCAN_MAX_LENGTH);
					memset(fileBuffer, NULL, SCAN_MAX_LENGTH);

					if (bytesLeft > SCAN_MAX_LENGTH) {
						sys_proc_rw(sp->pid, curAddress, scanBuffer, SCAN_MAX_LENGTH, 0);
						write(fileHandleCur, scanBuffer, SCAN_MAX_LENGTH);

						if (scan_requires_last_value(sp->compareType))
							read(fileHandleOld, fileBuffer, SCAN_MAX_LENGTH);

						for (uint64_t j = 0; j < SCAN_MAX_LENGTH; j += valueLength) {
							if (proc_scan_compareValues(sp->compareType, sp->valueType, valueLength, scan_requires_last_value(sp->compareType) ? (fileBuffer + j) : data, scanBuffer + j, pExtraValue) && address_is_in_list(fileHandle_resultsOld, totalResultCount, curAddress + j)) {
								add_result(&results, curAddress + j);
								foundValueInCurrentSection = 1;
							}
						}

						curAddress += SCAN_MAX_LENGTH;
						bytesLeft -= SCAN_MAX_LENGTH;
					}
					else {
						sys_proc_rw(sp->pid, curAddress, scanBuffer, bytesLeft, 0);
						write(fileHandleCur, scanBuffer, bytesLeft);

						if (scan_requires_last_value(sp->compareType))
							read(fileHandleOld, fileBuffer, bytesLeft);

						for (uint64_t j = 0; j < bytesLeft; j += valueLength) {
							if (proc_scan_compareValues(sp->compareType, sp->valueType, valueLength, scan_requires_last_value(sp->compareType) ? (fileBuffer + j) : data, scanBuffer + j, pExtraValue) && address_is_in_list(fileHandle_resultsOld, totalResultCount, curAddress + j)) {
								add_result(&results, curAddress + j);
								foundValueInCurrentSection = 1;
							}
						}

						curAddress += bytesLeft;
						bytesLeft -= bytesLeft;
					}
				}

				close(fileHandleCur);
				close(fileHandleOld);

				if (!foundValueInCurrentSection)
					savedSectionList.sections[sectionIndex].start = 0;
			}

			write_pending_results_to_file();

			free(scanBuffer);
			free(fileBuffer);

			uprintf("results.countTotal:  %lli", results.countTotal);
			uprintf("totalResultCount:    %lli", totalResultCount);
		}

		close(fileHandle_resultsOld);

		net_send_status(fd, CMD_SUCCESS);
		uprintf("########## next scan done");

		free(valueBuffer);
		free(addressBuffer);
		free(resultAddressBuffer);
	}

	return 0;
}

int proc_info_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_info_packet *ip;
	struct sys_proc_info_args args;
	struct cmd_proc_info_response resp;

	ip = (struct cmd_proc_info_packet *)packet->data;

	if (ip) {
		sys_proc_cmd(ip->pid, SYS_PROC_INFO, &args);

		resp.pid = args.pid;
		memcpy(resp.name, args.name, sizeof(resp.name));
		memcpy(resp.path, args.path, sizeof(resp.path));
		memcpy(resp.titleid, args.titleid, sizeof(resp.titleid));
		memcpy(resp.contentid, args.contentid, sizeof(resp.contentid));

		net_send_status(fd, CMD_SUCCESS);
		net_send_data(fd, &resp, CMD_PROC_INFO_RESPONSE_SIZE);
		return 0;
	}

	net_send_status(fd, CMD_DATA_NULL);

	return 0;
}

int proc_alloc_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_alloc_packet *ap;
	struct sys_proc_alloc_args args;
	struct cmd_proc_alloc_response resp;

	ap = (struct cmd_proc_alloc_packet *)packet->data;

	if (ap) {
		args.length = ap->length;
		sys_proc_cmd(ap->pid, SYS_PROC_ALLOC, &args);

		resp.address = args.address;

		net_send_status(fd, CMD_SUCCESS);
		net_send_data(fd, &resp, CMD_PROC_ALLOC_RESPONSE_SIZE);
		return 0;
	}

	net_send_status(fd, CMD_DATA_NULL);

	return 0;
}

int proc_free_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_free_packet *fp;
	struct sys_proc_free_args args;

	fp = (struct cmd_proc_free_packet *)packet->data;

	if (fp) {
		args.address = fp->address;
		args.length = fp->length;
		sys_proc_cmd(fp->pid, SYS_PROC_FREE, &args);

		net_send_status(fd, CMD_SUCCESS);
		return 0;
	}

	net_send_status(fd, CMD_DATA_NULL);

	return 0;
}

int proc_scan_get_results_handle(int fd, struct cmd_packet *packet) {
	if (state == ENDED)
		return 1;

	void *data = pfmalloc(NET_MAX_LENGTH);
	if (!data) {
		net_send_status(fd, CMD_DATA_NULL);
		return 1;
	}

	int fileHandle;
	if ((fileHandle = open("/data/scan_temp/results", O_RDONLY, 0)) < 0) {
		net_send_status(fd, CMD_DATA_NULL);

		free(data);
		return 1;
	}

	net_send_status(fd, CMD_SUCCESS);

	uint64_t bytesLeft = sizeof(uint64_t) * results.countTotal;

	while (bytesLeft > 0) {
		memset(data, NULL, NET_MAX_LENGTH);

		if (bytesLeft > NET_MAX_LENGTH) {
			read(fileHandle, data, NET_MAX_LENGTH);

			net_send_data(fd, data, NET_MAX_LENGTH);

			bytesLeft -= NET_MAX_LENGTH;
		}
		else {
			read(fileHandle, data, bytesLeft);

			net_send_data(fd, data, bytesLeft);

			bytesLeft -= bytesLeft;
		}
	}

	close(fileHandle);
	free(data);

	return 0;
}

int proc_scan_count_results_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_scan_count_results_packet *pack;
	struct cmd_proc_scan_count_results_response resp;

	pack = (struct cmd_proc_scan_count_results_packet *)packet->data;

	if (pack) {
		resp.count = state == STARTED ? results.countTotal : 0;

		net_send_status(fd, CMD_SUCCESS);
		net_send_data(fd, &resp, CMD_SCAN_COUNT_RESULTS_RESPONSE_SIZE);
		return 0;
	}

	net_send_status(fd, CMD_DATA_NULL);
	return 0;
}

int proc_prx_load_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_prx_load_response resp;
	void *data;
	void *data2;

	data = pfmalloc(32);
	if (!data) {
		net_send_status(fd, CMD_DATA_NULL);
		return 0;
	}
	memset(data, NULL, 32);
	net_recv_data(fd, data, 32, 1);

	data2 = pfmalloc(100);
	if (!data2) {
		net_send_status(fd, CMD_DATA_NULL);
		return 0;
	}
	memset(data2, NULL, 100);	
	net_recv_data(fd, data2, 100, 1);

	int handle = sys_sdk_proc_prx_load(data, data2);
	if (handle <= 0) {
		net_send_status(fd, CMD_DATA_NULL);
		return 0;
	}

	resp.prx_handle = handle;

	net_send_status(fd, CMD_SUCCESS);
	net_send_data(fd, &resp, CMD_PROC_PRX_LOAD_RESPONSE_SIZE);

	free(data);
	free(data2);

	return 0;
}

int proc_prx_unload_handle(int fd, struct cmd_packet *packet) {
	struct cmd_proc_prx_unload_packet *unloadpack;
	void *data;

	unloadpack = (struct cmd_proc_prx_unload_packet *)packet->data;

	if (unloadpack) {
		data = pfmalloc(32);
		if (!data) {
			net_send_status(fd, CMD_DATA_NULL);
			return 0;
		}
		memset(data, NULL, 32);
		net_recv_data(fd, data, 32, 1);

		sys_sdk_proc_prx_unload(data, unloadpack->prx_handle);

		net_send_status(fd, CMD_SUCCESS);

		free(data);

		return 0;
	}

	net_send_status(fd, CMD_DATA_NULL);
	return 0;
}

int proc_handle(int fd, struct cmd_packet *packet) {
	switch (packet->cmd) {
	case CMD_PROC_LIST:
		return proc_list_handle(fd, packet);
	case CMD_PROC_READ:
		return proc_read_handle(fd, packet);
	case CMD_PROC_WRITE:
		return proc_write_handle(fd, packet);
	case CMD_PROC_MAPS:
		return proc_maps_handle(fd, packet);
	case CMD_PROC_INTALL:
		return proc_install_handle(fd, packet);
	case CMD_PROC_CALL:
		return proc_call_handle(fd, packet);
	case CMD_PROC_ELF:
		return proc_elf_handle(fd, packet);
	case CMD_PROC_PROTECT:
		return proc_protect_handle(fd, packet);
	case CMD_PROC_INFO:
		return proc_info_handle(fd, packet);
	case CMD_PROC_ALLOC:
		return proc_alloc_handle(fd, packet);
	case CMD_PROC_FREE:
		return proc_free_handle(fd, packet);
	case CMD_PROC_SCAN:
		return proc_scan_handle(fd, packet);
	case CMD_PROC_SCAN_GET_RESULTS:
		return proc_scan_get_results_handle(fd, packet);
	case CMD_PROC_SCAN_COUNT_RESULTS:
		return proc_scan_count_results_handle(fd, packet);
	case CMD_PROC_PRX_LOAD:
		return proc_prx_load_handle(fd, packet);
	case CMD_PROC_PRX_UNLOAD:
		return proc_prx_unload_handle(fd, packet);
	}

	return 1;
}
