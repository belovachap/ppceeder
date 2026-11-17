#include "version-payload.h"

uint64_t random_nonce() {
    uint64_t out;
    byte *pout = (byte *)&out;
    for (int i = 0; i < 8; i++) {
        pout[i] = rand() % 16;
    }
    return out;
}

version_payload_s new_version_payload(net_addr_s addr_recv, net_addr_s addr_from, var_str_s user_agent) {
    return (version_payload_s){
        .version = 70018,
        .services = 0,
        .timestamp = time(NULL),
        .addr_recv = addr_recv,
        .addr_from = addr_from,
        .nonce = random_nonce(),
        .user_agent = user_agent,
        .start_height = 0,
        .relay = false,
    };
}

void free_version_payload(version_payload_s vp) {
    free_var_str(vp.user_agent);
}

bytes_s serialize_version_payload(version_payload_s vp) {
    bytes_s addr_recv_bytes = serialize_net_addr(vp.addr_recv, false);
    bytes_s addr_from_bytes = serialize_net_addr(vp.addr_from, false);
    bytes_s user_agent_bytes = serialize_var_str(vp.user_agent);

    int length = 4 + 8 + 8 + 8 + 4 + 1
               + addr_recv_bytes.length + addr_from_bytes.length + user_agent_bytes.length;
    byte *buffer = malloc(length);
    int offset = 0;

    write_i32_le(buffer + offset, vp.version); offset += 4;
    write_u64_le(buffer + offset, vp.services); offset += 8;
    write_i64_le(buffer + offset, vp.timestamp); offset += 8;

    memcpy(buffer + offset, addr_recv_bytes.buffer, addr_recv_bytes.length);
    offset += addr_recv_bytes.length;
    free_bytes(addr_recv_bytes);

    memcpy(buffer + offset, addr_from_bytes.buffer, addr_from_bytes.length);
    offset += addr_from_bytes.length;
    free_bytes(addr_from_bytes);

    write_u64_le(buffer + offset, vp.nonce); offset += 8;

    memcpy(buffer + offset, user_agent_bytes.buffer, user_agent_bytes.length);
    offset += user_agent_bytes.length;
    free_bytes(user_agent_bytes);

    write_i32_le(buffer + offset, vp.start_height); offset += 4;
    buffer[offset] = vp.relay;

    return (bytes_s){.length=length, .buffer=buffer};
}

parsed_version_payload_s parse_version_payload(bytes_s bytes) {
    version_payload_s vp;
    int parsed_bytes = 0;

    vp.version = read_i32_le(bytes.buffer + parsed_bytes); parsed_bytes += 4;
    vp.services = read_u64_le(bytes.buffer + parsed_bytes); parsed_bytes += 8;
    vp.timestamp = read_i64_le(bytes.buffer + parsed_bytes); parsed_bytes += 8;

    bytes_s window = {.length = bytes.length - parsed_bytes, .buffer = bytes.buffer + parsed_bytes};
    parsed_net_addr_s p_recv = parse_net_addr(window, false);
    vp.addr_recv = p_recv.net_addr; parsed_bytes += p_recv.parsed_bytes;

    window = (bytes_s){.length = bytes.length - parsed_bytes, .buffer = bytes.buffer + parsed_bytes};
    parsed_net_addr_s p_from = parse_net_addr(window, false);
    vp.addr_from = p_from.net_addr; parsed_bytes += p_from.parsed_bytes;

    vp.nonce = read_u64_le(bytes.buffer + parsed_bytes); parsed_bytes += 8;

    window = (bytes_s){.length = bytes.length - parsed_bytes, .buffer = bytes.buffer + parsed_bytes};
    parsed_var_str_s p_ua = parse_var_str(window);
    vp.user_agent = p_ua.var_str; parsed_bytes += p_ua.parsed_bytes;

    vp.start_height = read_i32_le(bytes.buffer + parsed_bytes); parsed_bytes += 4;
    vp.relay = bytes.buffer[parsed_bytes]; parsed_bytes += 1;

    return (parsed_version_payload_s){.parsed_bytes=parsed_bytes, .version_payload=vp};
}

void free_parsed_version_payload(parsed_version_payload_s p) {
    free_var_str(p.version_payload.user_agent);
}
