#include "kfirmware.h"

unsigned short cachedFirmware;

int streq(const char *s1, const char *s2) {
	while (*s1 == *s2 && *s1) {
		s1++;
		s2++;
	}

	return *s1 == *s2;
}

unsigned short kget_firmware_from_base(uint64_t kernbase) {
	if (cachedFirmware) {
		return cachedFirmware;
	}

    char *firmwareString = "firmware";
    
    char *fw0505 = (char *)(kernbase + 0x7C7350);
    char *fw0900 = (char *)(kernbase + 0x7E1127);
	char *fw1100 = (char *)(kernbase + 0x8011AE);

    if (streq(fw0505, firmwareString)) {
        cachedFirmware = 505;
        return 505;
    }

    if (streq(fw0900, firmwareString)) {
        cachedFirmware = 900;
        return 900;
    }

	if (streq(fw1100, firmwareString)) {
        cachedFirmware = 1100;
        return 1100;
    }

    return 0;
}
