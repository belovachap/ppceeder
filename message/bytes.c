#include "bytes.h"

#include <stdlib.h>

void free_bytes(bytes_s bytes) {
    free(bytes.buffer);
}

