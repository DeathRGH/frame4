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
    char *fw0672 = (char *)(kernbase + 0x827FB9);
    char *fw0700 = (char *)(kernbase + 0x827145);
    char *fw0701 = (char *)(kernbase + 0x827145);
    char *fw0702 = (char *)(kernbase + 0x827145);
    char *fw0750 = (char *)(kernbase + 0x7B5F4C);
    char *fw0751 = (char *)(kernbase + 0x7B5F4C);
    char *fw0755 = (char *)(kernbase + 0x7B5F4C);
    char *fw0800 = (char *)(kernbase + 0x7A0C60);
    char *fw0801 = (char *)(kernbase + 0x7A0C60);
    char *fw0803 = (char *)(kernbase + 0x7A0C60);
    char *fw0850 = (char *)(kernbase + 0x7C8B78);
    char *fw0852 = (char *)(kernbase + 0x7C8B78);
    char *fw0900 = (char *)(kernbase + 0x7E1127);
    char *fw0903 = (char *)(kernbase + 0x7DEF17);
    char *fw0904 = (char *)(kernbase + 0x7DEF17);
    char *fw0950 = (char *)(kernbase + 0x7A719C);
    char *fw0951 = (char *)(kernbase + 0x7A719C);
    char *fw0960 = (char *)(kernbase + 0x7A719C);
    char *fw1000 = (char *)(kernbase + 0x7A96F8);
    char *fw1001 = (char *)(kernbase + 0x7A96F8);
    char *fw1050 = (char *)(kernbase + 0x79E4D8);
    char *fw1070 = (char *)(kernbase + 0x79E4D8);
    char *fw1071 = (char *)(kernbase + 0x79E4D8);
    char *fw1100 = (char *)(kernbase + 0x8011AE);

    if (streq(fw0505, firmwareString)) {
        cachedFirmware = 505;
        return 505;
    }

    if (streq(fw0672, firmwareString)) {
        cachedFirmware = 672;
        return 672;
    }

    if (streq(fw0700, firmwareString)) {
        cachedFirmware = 700;
        return 700;
    }

    if (streq(fw0701, firmwareString)) {
        cachedFirmware = 701;
        return 701;
    }

    if (streq(fw0702, firmwareString)) {
        cachedFirmware = 702;
        return 702;
    }

    if (streq(fw0750, firmwareString)) {
        cachedFirmware = 750;
        return 750;
    }

    if (streq(fw0751, firmwareString)) {
        cachedFirmware = 751;
        return 751;
    }

    if (streq(fw0755, firmwareString)) {
        cachedFirmware = 755;
        return 755;
    }

    if (streq(fw0800, firmwareString)) {
        cachedFirmware = 800;
        return 800;
    }

    if (streq(fw0801, firmwareString)) {
        cachedFirmware = 801;
        return 801;
    }

    if (streq(fw0803, firmwareString)) {
        cachedFirmware = 803;
        return 803;
    }

    if (streq(fw0850, firmwareString)) {
        cachedFirmware = 850;
        return 850;
    }

    if (streq(fw0852, firmwareString)) {
        cachedFirmware = 852;
        return 852;
    }

    if (streq(fw0900, firmwareString)) {
        cachedFirmware = 900;
        return 900;
    }

    if (streq(fw0903, firmwareString)) {
        cachedFirmware = 903;
        return 903;
    }

    if (streq(fw0904, firmwareString)) {
        cachedFirmware = 904;
        return 904;
    }

    if (streq(fw0950, firmwareString)) {
        cachedFirmware = 950;
        return 950;
    }

    if (streq(fw0951, firmwareString)) {
        cachedFirmware = 951;
        return 951;
    }

    if (streq(fw0960, firmwareString)) {
        cachedFirmware = 960;
        return 960;
    }

    if (streq(fw1000, firmwareString)) {
        cachedFirmware = 1000;
        return 1000;
    }

    if (streq(fw1001, firmwareString)) {
        cachedFirmware = 1001;
        return 1001;
    }

    if (streq(fw1050, firmwareString)) {
        cachedFirmware = 1050;
        return 1050;
    }

    if (streq(fw1070, firmwareString)) {
        cachedFirmware = 1070;
        return 1070;
    }

    if (streq(fw1071, firmwareString)) {
        cachedFirmware = 1071;
        return 1071;
    }

	if (streq(fw1100, firmwareString)) {
        cachedFirmware = 1100;
        return 1100;
    }

    return 0;
}
