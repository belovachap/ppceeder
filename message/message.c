#include "message.h"

message_s new_message(char *command, bytes_s payload) {
    message_s message = {
        .magic=MAGIC,
        .length=payload.length,
        .payload=payload.buffer
    };

    memset(message.command, 0, 12); // 0 pad the command
    strncpy(message.command, command, 12);

    byte obuf[SHA256_DIGEST_LENGTH];
    SHA256(payload.buffer, payload.length, obuf);
    SHA256(obuf, SHA256_DIGEST_LENGTH, obuf);
    memcpy(&message.checksum, obuf, 4);

    return message;
}

void free_message(message_s message) {
    free(message.payload);
}

bytes_s serialize_message(message_s message) {
    int length = HEADER_LENGTH + message.length;
    byte *buffer = malloc(length);
    write_u32_le(buffer, message.magic);
    memcpy(buffer + 4, message.command, 12);
    write_u32_le(buffer + 16, message.length);
    write_u32_le(buffer + 20, message.checksum);
    if (message.length > 0)
        memcpy(buffer + HEADER_LENGTH, message.payload, message.length);
    return (bytes_s){.buffer=buffer, .length=length};
}

parsed_message_s parse_message(bytes_s bytes) {
    message_s message;
    message.magic = read_u32_le(bytes.buffer);
    memcpy(message.command, bytes.buffer + 4, 12);
    message.length = read_u32_le(bytes.buffer + 16);
    message.checksum = read_u32_le(bytes.buffer + 20);
    if (message.length <= 0) {
        message.payload = NULL;
    }
    else {
        message.payload = malloc(message.length);
        memcpy(message.payload, bytes.buffer + HEADER_LENGTH, message.length);
    }

    return (parsed_message_s){.message=message, .parsed_bytes=(HEADER_LENGTH + message.length)};
}

parsed_message_s read_message(socketfd s) {
    message_s m;
    int read_bytes = 0;
    byte header[HEADER_LENGTH];
    while (read_bytes < HEADER_LENGTH) {
        int n = read(s, header + read_bytes, HEADER_LENGTH - read_bytes);
        if (n <= 0) return (parsed_message_s){.parsed_bytes=-1, .message=m};
        read_bytes += n;
    }

    m.magic = read_u32_le(header);
    memcpy(m.command, header + 4, 12);
    m.length = read_u32_le(header + 16);
    m.checksum = read_u32_le(header + 20);

    if (m.magic != MAGIC || m.length > MAX_PAYLOAD_LENGTH)
        return (parsed_message_s){.parsed_bytes=-1, .message=m};

    if (m.length > 0) {
        byte *payload = malloc(m.length);
        read_bytes = 0;
        while (read_bytes < m.length) {
            int n = read(s, payload + read_bytes, m.length - read_bytes);
            if (n <= 0) { free(payload); return (parsed_message_s){.parsed_bytes=-1, .message=m}; }
            read_bytes += n;
        }
        m.payload = payload;
    } else {
        m.payload = NULL;
    }

    return (parsed_message_s){.parsed_bytes=HEADER_LENGTH + m.length, .message=m};
}

void write_message(socketfd socket, message_s message) {
    bytes_s bytes = serialize_message(message);
    write(socket, bytes.buffer, bytes.length);
    free_bytes(bytes);
}
