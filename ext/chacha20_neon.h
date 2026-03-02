#ifndef CHACHA20_NEON_H
#define CHACHA20_NEON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * chacha20_neon_encrypt — Generate ChaCha20 keystream, XOR with input,
 *                         write to output.
 *
 * Processes 4 blocks (256 bytes) per iteration using ARM NEON SIMD.
 *
 * Parameters:
 *   state  — ChaCha20 state (16 x uint32_t): constants, key, counter, nonce.
 *            state[12] is the starting block counter.
 *   out    — Output buffer (plaintext XOR keystream).
 *   in     — Input buffer  (plaintext).
 *   len    — Number of bytes to process.  MUST be a multiple of 256.
 */
void chacha20_neon_encrypt(
    const uint32_t state[16],
    uint8_t        *out,
    const uint8_t  *in,
    size_t          len);

#ifdef __cplusplus
}
#endif

#endif /* CHACHA20_NEON_H */
