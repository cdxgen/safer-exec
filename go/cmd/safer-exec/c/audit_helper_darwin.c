#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>

static void image_added(const struct mach_header *mh, intptr_t vmaddr_slide) {
    // Find image name
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        const struct mach_header *img_mh = _dyld_get_image_header(i);
        if (img_mh == mh) {
            if (name && name[0] != '\0') {
                char buf[1024];
                int len = snprintf(buf, sizeof(buf), "{\"type\":\"lib-load\",\"target\":\"%s\"}\n", name);
                if (len > 0) {
                    write(2, buf, len);
                }
            }
            break;
        }
    }
}

__attribute__((constructor))
static void register_callback(void) {
    _dyld_register_func_for_add_image(image_added);
}
