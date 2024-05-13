#ifndef _INSTALLER_H
#define _INSTALLER_H

#include <ksdk.h>
#include "proc.h"

#define PAYLOAD_BASE 0x926600000
#define PAYLOAD_SIZE 0x400000

int runinstaller();

#endif
