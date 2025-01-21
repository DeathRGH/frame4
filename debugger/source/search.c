#include "search.h"

#include "kdbg.h"
#include "net.h"
#include "proc.h"

struct inputSearchStart {
    uint32_t processId;
    uint64_t startAddress;
    uint64_t endAddress;
    uint32_t length;
} __attribute__((packed));

struct inputSearchRescan {
    uint32_t processId;
    uint32_t length;
} __attribute__((packed));

enum SearchState state;

struct searchResults results;

void write_pending_results_to_file() {
    int fileHandle;
    int mode = O_CREAT | O_RDWR | O_APPEND;

    if ((fileHandle = open("/data/scan_temp/results", mode, 0777)) < 0) {
        return;
    }

    //for (uint64_t i = 0; i < results.count; i++)
    write(fileHandle, (void *)results.items, sizeof(uint64_t) * results.count);
    close(fileHandle);

    results.count = 0;
}

void allocate_results(struct searchResults *sResults, size_t initialSize) {
    // if state has started, return as it's already allocated
    if (state == STARTED) {
        return;
    }

    sResults->items = (uint64_t *)malloc(initialSize * sizeof(uint64_t));
    sResults->count = 0;
    sResults->countTotal = 0;
    sResults->size = initialSize;

    int fileHandle;
    int mode = O_CREAT | O_RDWR | O_TRUNC;
    if ((fileHandle = open("/data/scan_temp/results", mode, 0777)) < 0) {
        return;
    }

    write(fileHandle, NULL, 0);
    close(fileHandle);

    state = STARTED;
}

void add_result(struct searchResults *sResults, uint64_t result) {
    // if state has ended, return as it's not allocated
    if (state == ENDED) {
        return;
    }

    // if we have hit the buffer size limit write them to the file
    if (sResults->count == sResults->size) {
        int fileHandle;
        int mode = O_CREAT | O_RDWR | O_APPEND;

        if ((fileHandle = open("/data/scan_temp/results", mode, 0777)) < 0) {
            return;
        }

        write(fileHandle, (void *)results.items, sizeof(uint64_t) * results.count);

        close(fileHandle);

        results.count = 0;
    }
    //sResults->items[sResults->count++] = result;

    results.items[results.count] = result;
    results.count++;
    results.countTotal++;
}

void remove_result(struct searchResults *sResults, uint32_t index) {
    // if state has ended, return as it's not allocated
    if (state == ENDED) {
        return;
    }

    sResults->items[index] = NULL;
    sResults->count--;
}

void clean_results(struct searchResults *sResults) {
    // if state has ended, return as it's not allocated
    if (state == ENDED) {
        return;
    }

    uint32_t validResults = 0;
    uint32_t index = 0;
    while (validResults < sResults->count && index < sResults->size) {
        if (sResults->items[index] != NULL) {
            sResults->items[validResults] = sResults->items[index];
            validResults++;
        }
        index++;
    }
}

void free_results(struct searchResults *sResults) {
    // if state has ended, return as it's not allocated
    if (state == ENDED) {
        return;
    }

    free(sResults->items);
    sResults->items = NULL;
    sResults->count = 0;
    sResults->countTotal = 0;
    sResults->size = 0;
    state = ENDED;
}
