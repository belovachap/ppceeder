#include "net-addr.h"

char *address_to_ip(char *address) {
    char obuf[4];
    if (inet_pton(AF_INET, address, obuf) != 1) return NULL;
    char *ip = malloc(16);
    memset(ip, 0, 12);
    ip[10] = 0xFF; ip[11] = 0xFF;
    memcpy(ip + 12, obuf, 4);
    return ip;
}

net_addr_s new_net_addr(uint32_t time, uint64_t services, char *ip, uint16_t port) {
    net_addr_s na = {.time=time, .services=services, .port=port};
    memcpy(na.ip, ip, 16);
    return na;
}

bytes_s serialize_net_addr(net_addr_s na, bool include_time) {
    int length = include_time ? NET_ADDR_LENGTH : NET_ADDR_LENGTH - 4;
    byte *buffer = malloc(length);
    int offset = 0;

    if (include_time) { write_u32_le(buffer, na.time); offset += 4; }
    write_u64_le(buffer + offset, na.services); offset += 8;
    memcpy(buffer + offset, na.ip, 16); offset += 16;
    write_u16_be(buffer + offset, na.port);

    return (bytes_s){.length=length, .buffer=buffer};
}

parsed_net_addr_s parse_net_addr(bytes_s bytes, bool include_time) {
    net_addr_s na = {.time=0};
    int parsed_bytes = 0;

    if (include_time) { na.time = read_u32_le(bytes.buffer); parsed_bytes += 4; }
    na.services = read_u64_le(bytes.buffer + parsed_bytes); parsed_bytes += 8;
    memcpy(na.ip, bytes.buffer + parsed_bytes, 16); parsed_bytes += 16;
    na.port = read_u16_be(bytes.buffer + parsed_bytes); parsed_bytes += 2;

    return (parsed_net_addr_s){.parsed_bytes=parsed_bytes, .net_addr=na};
}
