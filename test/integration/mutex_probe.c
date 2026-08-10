// LD_PRELOAD interposer for reload_lock.sh, reporting every
// pthread_mutex_init() whose target lives in a shared mapping.
//
// app/main.c:init_logger() is the only thing that initializes a mutex in the
// region init_shmem() maps, so counting those is how a test sees whether a
// reload re-initialized the logger's write lock. Mutexes on the heap, which
// are OpenSSL's, are ignored: they come and go with each probe context and
// would drown the one being counted.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

// MAP_SHARED|MAP_ANONYMOUS appears in /proc/self/maps as an rw-s mapping of
// "/dev/zero (deleted)", which is what distinguishes it from the heap.
static int in_shared_mapping(const void *addr) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL)
        return 0;

    char line[512];
    int found = 0;
    while (!found && fgets(line, sizeof line, maps) != NULL) {
        unsigned long lo, hi;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perms) != 3)
            continue;
        if (perms[3] != 's')
            continue;
        unsigned long a = (unsigned long)addr;
        found = a >= lo && a < hi;
    }

    fclose(maps);
    return found;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *at) {
    static int (*real)(pthread_mutex_t *, const pthread_mutexattr_t *);
    if (real == NULL)
        real = dlsym(RTLD_NEXT, "pthread_mutex_init");

    if (in_shared_mapping(mutex))
        dprintf(2, "shared_mutex_init pid=%d mutex=%p\n", getpid(),
                (void *)mutex);

    return real(mutex, at);
}
