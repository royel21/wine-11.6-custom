#pragma once

#include <stddef.h>
#include <stdint.h>

/* Deciphers a DAEMON Tools MDS version 2 descriptor (the whole .mds file) and returns it in the
 * Alcohol 120% version 1 layout, in a buffer to free(); NULL when it isn't one or can't be read. */
uint8_t *mdsv2_to_v1(const uint8_t *mds, size_t size, size_t *outSize);
