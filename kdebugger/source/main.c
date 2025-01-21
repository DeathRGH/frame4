#include <ksdk.h>
#include "hooks.h"

int _main(void) {
    init_ksdk();

    printf("[Frame4] kernel base 0x%llX\n", get_kbase());

    if (install_hooks()) {
        printf("[Frame4] failed to install hooks\n");
        return 1;
    }

    return 0;
}
