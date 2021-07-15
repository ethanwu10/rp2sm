#include "support.hpp"

static_assert(unhexlify("deadbeef") == std::array<uint8_t, 4>{0xde, 0xad, 0xbe, 0xef});
static_assert(unhexlify("0123456789abcdef") == std::array<uint8_t, 8>{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef});