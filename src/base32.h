#include <sys/types.h>
#include <stdint.h>

#ifndef BASE32_H
#define BASE32_H

ssize_t base32_decode(const char *encoded, uint8_t *dst, size_t len);
char *base32_encode(const uint8_t *buf, size_t len);

#endif
