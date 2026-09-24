#define _GNU_SOURCE
#include <errno.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Events go to a dedicated descriptor that the engine duplicates from its own
// stderr and names in SAFER_EXEC_LIBLOAD_FD. Writing to fd 2 would put them
// into whatever the traced program redirected its stderr to (corrupting that
// output and hiding the loads from the engine). fd 2 is used only when the
// variable is absent, for older engines.
static int out_fd = 2;
static dev_t out_dev;
static ino_t out_ino;
static int out_checked;

static void init_out_fd(void) {
    const char *v = getenv("SAFER_EXEC_LIBLOAD_FD");
    if (!v || !*v) {
        return;
    }
    char *end = NULL;
    long fd = strtol(v, &end, 10);
    struct stat st;
    if (end == v || *end != '\0' || fd < 3 || fd > 65535 || fstat((int)fd, &st) != 0) {
        // Named but unusable: drop events rather than write into stderr.
        out_fd = -1;
        return;
    }
    out_fd = (int)fd;
    out_dev = st.st_dev;
    out_ino = st.st_ino;
    out_checked = 1;
}

// The program may close the descriptor and reuse its number for its own file;
// only write while it still refers to the file the engine handed over.
static int out_fd_valid(void) {
    if (out_fd < 0) {
        return 0;
    }
    if (!out_checked) {
        return 1;
    }
    struct stat st;
    return fstat(out_fd, &st) == 0 && st.st_dev == out_dev && st.st_ino == out_ino;
}

static void write_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        buf += n;
        len -= (size_t)n;
    }
}

unsigned int la_version(unsigned int version) {
    init_out_fd();
    return LAV_CURRENT;
}

unsigned int la_objopen(struct link_map *lmp, Lmid_t lmid, uintptr_t *cookie) {
    if (!lmp || !lmp->l_name || lmp->l_name[0] == '\0' || !out_fd_valid()) {
        return 0;
    }
    // {"type":"lib-load","target":"/path/to/lib.so"}, one line per event and
    // written in a single write() so concurrent processes do not interleave.
    // The path is JSON-escaped; an over-long path is dropped rather than
    // truncated into an invalid line.
    char buf[4096];
    static const char prefix[] = "{\"type\":\"lib-load\",\"target\":\"";
    static const char suffix[] = "\"}\n";
    size_t pos = sizeof(prefix) - 1;
    memcpy(buf, prefix, pos);
    for (const unsigned char *p = (const unsigned char *)lmp->l_name; *p; p++) {
        if (pos + 6 + sizeof(suffix) >= sizeof(buf)) {
            return 0;
        }
        if (*p == '"' || *p == '\\') {
            buf[pos++] = '\\';
            buf[pos++] = (char)*p;
        } else if (*p < 0x20) {
            pos += (size_t)snprintf(buf + pos, 7, "\\u%04x", *p);
        } else {
            buf[pos++] = (char)*p;
        }
    }
    memcpy(buf + pos, suffix, sizeof(suffix) - 1);
    pos += sizeof(suffix) - 1;
    write_all(out_fd, buf, pos);
    return 0;
}
