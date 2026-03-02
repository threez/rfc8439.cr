/*
 * ChaCha20 NEON-accelerated 4-block parallel kernel for AArch64.
 *
 * Processes 4 ChaCha20 blocks (256 bytes) at a time using ARM NEON
 * 128-bit SIMD. Each uint32x4_t register holds the same word position
 * from 4 independent blocks, enabling full SIMD parallelism across the
 * quarter-round operations.
 *
 * Called from Crystal via FFI; the scalar Crystal code handles any
 * remaining blocks (0-3) that don't fill a 4-block chunk.
 */

#include "chacha20_neon.h"

#ifdef __aarch64__

#include <arm_neon.h>

/* ---- Rotate helpers -------------------------------------------------- */

/* Rotate left by 16: single instruction (rev32.8h) */
static inline uint32x4_t rotl16(uint32x4_t x) {
    return vreinterpretq_u32_u16(
        vrev32q_u16(vreinterpretq_u16_u32(x)));
}

/* Rotate left by 12: shift-right + shift-left-insert */
static inline uint32x4_t rotl12(uint32x4_t x) {
    return vsliq_n_u32(vshrq_n_u32(x, 20), x, 12);
}

/* Rotate left by 8: shift-right + shift-left-insert */
static inline uint32x4_t rotl8(uint32x4_t x) {
    return vsliq_n_u32(vshrq_n_u32(x, 24), x, 8);
}

/* Rotate left by 7: shift-right + shift-left-insert */
static inline uint32x4_t rotl7(uint32x4_t x) {
    return vsliq_n_u32(vshrq_n_u32(x, 25), x, 7);
}

/* ---- Quarter round --------------------------------------------------- */

#define QR(a, b, c, d)       \
    a = vaddq_u32(a, b);     \
    d = veorq_u32(d, a);     \
    d = rotl16(d);            \
    c = vaddq_u32(c, d);     \
    b = veorq_u32(b, c);     \
    b = rotl12(b);            \
    a = vaddq_u32(a, b);     \
    d = veorq_u32(d, a);     \
    d = rotl8(d);             \
    c = vaddq_u32(c, d);     \
    b = veorq_u32(b, c);     \
    b = rotl7(b);

/* ---- 4x4 matrix transpose ------------------------------------------- */

/*
 * Converts from word-major layout (each register = same word from 4 blocks)
 * to block-major layout  (each register = 4 consecutive words from 1 block).
 */
#define TRANSPOSE4(r0, r1, r2, r3) do {                               \
    uint32x4_t _t0 = vtrn1q_u32(r0, r1);                             \
    uint32x4_t _t1 = vtrn2q_u32(r0, r1);                             \
    uint32x4_t _t2 = vtrn1q_u32(r2, r3);                             \
    uint32x4_t _t3 = vtrn2q_u32(r2, r3);                             \
    r0 = vreinterpretq_u32_u64(                                       \
        vtrn1q_u64(vreinterpretq_u64_u32(_t0),                       \
                   vreinterpretq_u64_u32(_t2)));                      \
    r1 = vreinterpretq_u32_u64(                                       \
        vtrn1q_u64(vreinterpretq_u64_u32(_t1),                       \
                   vreinterpretq_u64_u32(_t3)));                      \
    r2 = vreinterpretq_u32_u64(                                       \
        vtrn2q_u64(vreinterpretq_u64_u32(_t0),                       \
                   vreinterpretq_u64_u32(_t2)));                      \
    r3 = vreinterpretq_u32_u64(                                       \
        vtrn2q_u64(vreinterpretq_u64_u32(_t1),                       \
                   vreinterpretq_u64_u32(_t3)));                      \
} while (0)

/* ---- Load-XOR-Store one 64-byte block -------------------------------- */

#define XOR_STORE_BLOCK(outp, inp, off, ks0, ks1, ks2, ks3) do {     \
    uint32x4_t _d0 = vld1q_u32((inp) + (off));                       \
    uint32x4_t _d1 = vld1q_u32((inp) + (off) + 4);                  \
    uint32x4_t _d2 = vld1q_u32((inp) + (off) + 8);                  \
    uint32x4_t _d3 = vld1q_u32((inp) + (off) + 12);                 \
    vst1q_u32((outp) + (off),      veorq_u32(_d0, ks0));            \
    vst1q_u32((outp) + (off) + 4,  veorq_u32(_d1, ks1));            \
    vst1q_u32((outp) + (off) + 8,  veorq_u32(_d2, ks2));            \
    vst1q_u32((outp) + (off) + 12, veorq_u32(_d3, ks3));            \
} while (0)

/* ---- Public API ------------------------------------------------------ */

void chacha20_neon_encrypt(
    const uint32_t state[16],
    uint8_t        *out,
    const uint8_t  *in,
    size_t          len)
{
    uint32_t ctr = state[12];
    const uint32x4_t ctr_inc = {0, 1, 2, 3};

    while (len >= 256) {
        /* Load state — each register holds 4 copies of one word */
        uint32x4_t s0  = vdupq_n_u32(state[0]);
        uint32x4_t s1  = vdupq_n_u32(state[1]);
        uint32x4_t s2  = vdupq_n_u32(state[2]);
        uint32x4_t s3  = vdupq_n_u32(state[3]);
        uint32x4_t s4  = vdupq_n_u32(state[4]);
        uint32x4_t s5  = vdupq_n_u32(state[5]);
        uint32x4_t s6  = vdupq_n_u32(state[6]);
        uint32x4_t s7  = vdupq_n_u32(state[7]);
        uint32x4_t s8  = vdupq_n_u32(state[8]);
        uint32x4_t s9  = vdupq_n_u32(state[9]);
        uint32x4_t s10 = vdupq_n_u32(state[10]);
        uint32x4_t s11 = vdupq_n_u32(state[11]);
        /* Counter lanes: ctr, ctr+1, ctr+2, ctr+3 */
        uint32x4_t s12 = vaddq_u32(vdupq_n_u32(ctr), ctr_inc);
        uint32x4_t s13 = vdupq_n_u32(state[13]);
        uint32x4_t s14 = vdupq_n_u32(state[14]);
        uint32x4_t s15 = vdupq_n_u32(state[15]);

        /*
         * Save only the counter — everything else can be reloaded from
         * state[] for the final addition.  This keeps register pressure
         * at 16 working + 1 saved + 1 ctr_inc ≤ 32, eliminating spills.
         */
        const uint32x4_t saved_ctr = s12;

        /* 20 rounds (10 double-rounds) */
        for (int i = 0; i < 10; i++) {
            /* Column rounds */
            QR(s0, s4,  s8,  s12);
            QR(s1, s5,  s9,  s13);
            QR(s2, s6,  s10, s14);
            QR(s3, s7,  s11, s15);
            /* Diagonal rounds */
            QR(s0, s5,  s10, s15);
            QR(s1, s6,  s11, s12);
            QR(s2, s7,  s8,  s13);
            QR(s3, s4,  s9,  s14);
        }

        /* Add original state — reload from memory (state[] is in L1) */
        s0  = vaddq_u32(s0,  vdupq_n_u32(state[0]));
        s1  = vaddq_u32(s1,  vdupq_n_u32(state[1]));
        s2  = vaddq_u32(s2,  vdupq_n_u32(state[2]));
        s3  = vaddq_u32(s3,  vdupq_n_u32(state[3]));
        s4  = vaddq_u32(s4,  vdupq_n_u32(state[4]));
        s5  = vaddq_u32(s5,  vdupq_n_u32(state[5]));
        s6  = vaddq_u32(s6,  vdupq_n_u32(state[6]));
        s7  = vaddq_u32(s7,  vdupq_n_u32(state[7]));
        s8  = vaddq_u32(s8,  vdupq_n_u32(state[8]));
        s9  = vaddq_u32(s9,  vdupq_n_u32(state[9]));
        s10 = vaddq_u32(s10, vdupq_n_u32(state[10]));
        s11 = vaddq_u32(s11, vdupq_n_u32(state[11]));
        s12 = vaddq_u32(s12, saved_ctr);
        s13 = vaddq_u32(s13, vdupq_n_u32(state[13]));
        s14 = vaddq_u32(s14, vdupq_n_u32(state[14]));
        s15 = vaddq_u32(s15, vdupq_n_u32(state[15]));

        /*
         * Transpose from word-major to block-major.
         *
         * Before: s_w = {block0_w, block1_w, block2_w, block3_w}
         * After:  group rows correspond to blocks, columns to consecutive words.
         *
         * Group A {s0-s3}  → block N words  0-3
         * Group B {s4-s7}  → block N words  4-7
         * Group C {s8-s11} → block N words  8-11
         * Group D {s12-s15}→ block N words 12-15
         */
        TRANSPOSE4(s0,  s1,  s2,  s3);
        TRANSPOSE4(s4,  s5,  s6,  s7);
        TRANSPOSE4(s8,  s9,  s10, s11);
        TRANSPOSE4(s12, s13, s14, s15);

        /* XOR input with keystream, write to output — 4 blocks (256 bytes) */
        const uint32_t *ip = (const uint32_t *)in;
        uint32_t *op = (uint32_t *)out;
        XOR_STORE_BLOCK(op, ip,  0, s0, s4, s8,  s12);  /* block 0 */
        XOR_STORE_BLOCK(op, ip, 16, s1, s5, s9,  s13);  /* block 1 */
        XOR_STORE_BLOCK(op, ip, 32, s2, s6, s10, s14);  /* block 2 */
        XOR_STORE_BLOCK(op, ip, 48, s3, s7, s11, s15);  /* block 3 */

        ctr += 4;
        in  += 256;
        out += 256;
        len -= 256;
    }
}

#endif /* __aarch64__ */
