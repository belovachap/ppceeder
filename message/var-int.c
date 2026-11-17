#include "var-int.h"

#include <stdlib.h>
#include <string.h>

bytes_s serialize_var_int(var_int_s var_int) {
    int length;
    byte *buffer;
    byte *value = (byte *)&(var_int.value);
    if (var_int.value < 0xFD) {
        length = 1;
        buffer = malloc(length);
        buffer[0] = value[0];
    }
    else if (var_int.value <= 0xFFFF) {
        length = 3;
        buffer = malloc(length);
        buffer[0] = 0xFD;
        buffer[1] = value[0];
        buffer[2] = value[1];
    }
    else if (var_int.value <= 0xFFFFFFFF) {
        length = 5;
        buffer = malloc(length);
        buffer[0] = 0xFE;
        memcpy(buffer + 1, value, 4);
    }
    else {
        length = 9;
        buffer = malloc(length);
        buffer[0] = 0xFF;
        memcpy(buffer + 1, value, 8);
    }

    return (bytes_s){.buffer=buffer, .length=length};
}

parsed_var_int_s parse_var_int(bytes_s bytes) {
    int parsed_bytes;
    var_int_s var_int = {.value=0};
    byte *value = (byte *)&(var_int.value);
    if (bytes.buffer[0] < 0xFD) {
        parsed_bytes = 1;
        value[0] = bytes.buffer[0];
    }
    else if (bytes.buffer[0] == 0xFD) {
        parsed_bytes = 3;
        memcpy(value, bytes.buffer + 1, 2);
    }
    else if (bytes.buffer[0] == 0xFE) {
        parsed_bytes = 5;
        memcpy(value, bytes.buffer + 1, 4);
    }
    else {
        parsed_bytes = 9;
        memcpy(value, bytes.buffer + 1, 8);
    }

    return (parsed_var_int_s){.parsed_bytes=parsed_bytes, .var_int=var_int};
}
