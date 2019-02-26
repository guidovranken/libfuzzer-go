#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef long long GoInt64;
typedef GoInt64 GoInt;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;
extern void fuzzer_init(void* coverTabPtr, uint64_t coverTabSize, void* memcmpCBPtr);
extern void fuzzer_run(GoSlice p0);

#ifdef __linux__
__attribute__((section("__libfuzzer_extra_counters")))
#endif
static uint8_t Counters[65536];

int LLVMFuzzerInitialize(int *_argc, char ***_argv) {
    (void)_argc;
    (void)_argv;
    fuzzer_init(Counters, sizeof(Counters), NULL);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    uint8_t* datacopy = malloc(size);
    memcpy(datacopy, data, size);
    GoSlice p = {(void*)datacopy, size, size};

    fuzzer_run(p);

    free(datacopy);

    return 0;
}
