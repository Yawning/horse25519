/*
 * NB: I stole this from obfsclient, which I stole from the "Public Domain"
 * bitpedia Java code.  This is somewhat tailored to how I want it to behave
 * for horse25519, so if you are not me, stealing it for the third time will
 * probably be a *really* bad idea.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "base32.h"

static uint8_t decode_char(uint8_t c);
static char encode_byte(uint8_t b);

static
uint8_t decode_char(uint8_t c)
{
  if (c >= 'a' && c <= 'z')
    c -= 32;

  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  else if (c >= '2' && c <= '7')
    return c - '2' + 26;
  else
    return 0xff;
}

static
char encode_byte(uint8_t b)
{
  /* The proposed onion format uses lower case. */
  if (b <= 25)
    return tolower('A' + b);
  else if (b <= 31)
    return '2' + (b - 26);
  else
    return 0xff;
}

ssize_t
base32_decode(const char *encoded, uint8_t *dst, size_t len)
{
  size_t offset = 0;
  size_t i, enc_len;
  int index = 0;

  if (encoded == NULL)
    return -1;
  if (dst == NULL)
    return -1;

  enc_len = strlen(encoded);
  if (enc_len * 5 > len * 8)
    return -1;
  memset(dst, 0, len);

  for (i = 0; i < enc_len; i++) {
    uint8_t c = decode_char(encoded[i]);
    if (c == 0xff)
      return -1;

    if (index <= 3) {
      index = (index + 5) & 0x07;
      if (index == 0) {
        dst[offset] |= c;
        offset++;
        if (offset >= len)
          return -1;
      } else
        dst[offset] |= c << (8 - index);
    } else {
      index = (index + 5) & 0x07;
      dst[offset] |= (c >> index);
      offset++;
      if (offset >= len)
        return -1;
      dst[offset] |= c << (8 - index);
    }
  }

  return offset;
}

char *
base32_encode(const uint8_t *buf, size_t len)
{
  char *ret;
  size_t i = 0;
  size_t index = 0;
  size_t enc_idx = 0;
  uint8_t digit = 0;
  uint8_t next_byte = 0;

  ret = calloc(1, (len + 7) * 8 / 5 + 1);

  while (i < len) {
    uint8_t currByte = buf[i];

    // Is the current digit going to span a byte boundary?
    if (index > 3) {
      if ((i + 1) < len)
        next_byte = buf[i + 1];
      else
        next_byte = 0;

      digit = currByte & (0xff >> index);
      index = (index + 5) & 0x07;
      digit <<= index;
      digit |= next_byte >> (8 - index);
      i++;
    } else {
      digit = (currByte >> (8 - (index + 5))) & 0x1f;
      index = (index + 5) & 0x07;
      if (index == 0)
        i++;
    }

    ret[enc_idx++] = encode_byte(digit);
  }

  /* Padding is for suckas. */

  return ret;
}
