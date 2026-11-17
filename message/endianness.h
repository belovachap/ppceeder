#pragma once

#include "bytes.h"
#include <stdint.h>
#include <string.h>

static inline void write_u16_le(byte *buf, uint16_t v) {
    buf[0] = v & 0xFF; buf[1] = (v >> 8) & 0xFF;
}
static inline uint16_t read_u16_le(const byte *buf) {
    return (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
}

static inline void write_u16_be(byte *buf, uint16_t v) {
    buf[0] = (v >> 8) & 0xFF; buf[1] = v & 0xFF;
}
static inline uint16_t read_u16_be(const byte *buf) {
    return ((uint16_t)buf[0] << 8) | (uint16_t)buf[1];
}

static inline void write_u32_le(byte *buf, uint32_t v) {
    buf[0] = v & 0xFF; buf[1] = (v >> 8) & 0xFF;
    buf[2] = (v >> 16) & 0xFF; buf[3] = (v >> 24) & 0xFF;
}
static inline uint32_t read_u32_le(const byte *buf) {
    return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

static inline void write_i32_le(byte *buf, int32_t v) { write_u32_le(buf, (uint32_t)v); }
static inline int32_t read_i32_le(const byte *buf) { return (int32_t)read_u32_le(buf); }

static inline void write_u64_le(byte *buf, uint64_t v) {
    for (int i = 0; i < 8; i++) buf[i] = (v >> (i * 8)) & 0xFF;
}
static inline uint64_t read_u64_le(const byte *buf) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)buf[i] << (i * 8);
    return v;
}

static inline void write_i64_le(byte *buf, int64_t v) { write_u64_le(buf, (uint64_t)v); }
static inline int64_t read_i64_le(const byte *buf) { return (int64_t)read_u64_le(buf); }
