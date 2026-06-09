#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned int la_version(unsigned int version) {
    return LAV_CURRENT;
}

unsigned int la_objopen(struct link_map *lmp, Lmid_t lmid, uintptr_t *cookie) {
    if (lmp && lmp->l_name && lmp->l_name[0] != '\0') {
        // Log loaded library to stderr in JSON or plain text format. We will output:
        // {"type":"lib-load","target":"/path/to/lib.so"}
        // This format is easy to parse. We'll write directly to fd 2 (stderr).
        char buf[1024];
        int len = snprintf(buf, sizeof(buf), "{\"type\":\"lib-load\",\"target\":\"%s\"}\n", lmp->l_name);
        if (len > 0) {
            write(2, buf, len);
        }
    }
    return 0;
}
