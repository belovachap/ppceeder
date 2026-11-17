#pragma once

#include "endianness.h"

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int address_to_ip(char *address, char out[16]);

static const int NET_ADDR_LENGTH = 30; // time + services + ip + port

typedef struct net_addr {
    uint32_t time; // not present in version message
    uint64_t services;
    char ip[16];
    uint16_t port; // host byte order
} net_addr_s;

net_addr_s new_net_addr(uint32_t, uint64_t, char *, uint16_t);

bytes_s serialize_net_addr(net_addr_s, bool);

typedef struct parsed_net_addr {
    net_addr_s net_addr;
    int parsed_bytes;
} parsed_net_addr_s;

parsed_net_addr_s parse_net_addr(bytes_s, bool);
