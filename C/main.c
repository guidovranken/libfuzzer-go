#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef long long GoInt64;
typedef GoInt64 GoInt;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;
extern void fuzzer_init(void* coverTabPtr, uint64_t coverTabSize, void* memcmpCBPtr);
extern void fuzzer_run(GoSlice p0);
extern void libFuzzerCustomMemcmp(void *caller_pc, const void *s1, const void *s2, size_t n);

uint8_t CoverTab[65536];

static void ResetCoverTab(void) {
    memset(CoverTab, 0, sizeof(CoverTab));
}

static uint64_t CalcCoverage(void) {
    size_t coverage = 0;

    for (size_t i = 0; i < sizeof(CoverTab); i++) {
        coverage += CoverTab[i] ? 1 : 0;
    }

    return coverage;
}

int LLVMFuzzerInitialize(int *_argc, char ***_argv) {
    (void)_argc;
    (void)_argv;

    fuzzer_init(CoverTab, sizeof(CoverTab), libFuzzerCustomMemcmp);

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    uint8_t* datacopy = malloc(size);
    memcpy(datacopy, data, size);
    GoSlice p = {(void*)datacopy, size, size};

    ResetCoverTab();
    fuzzer_run(p);

    free(datacopy);

    return CalcCoverage();
}
