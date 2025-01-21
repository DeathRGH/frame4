#ifndef _KFIRMWARE_H
#define _KFIRMWARE_H

#include "ksdk.h"

extern unsigned short cached_firmware;
extern unsigned short kget_firmware_from_base(uint64_t kernbase);

#endif
