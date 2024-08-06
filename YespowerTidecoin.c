#include "cpuminer-config.h"
#include "miner.h"

#include "yespower-1.0.1/yespower.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <immintrin.h>  // For SIMD intrinsics

// Ensure data alignment for cache optimization
#define ALIGN16 __attribute__((aligned(16)))

// SIMD-optimized functions for 32-bit integer operations
inline void store_be32(uint32_t *dst, uint32_t value) {
    _mm_store_si128((__m128i*)dst, _mm_set1_epi32(value));
}

inline uint32_t load_le32(const uint32_t *src) {
    __m128i v = _mm_load_si128((__m128i*)src);
    return _mm_cvtsi128_si32(v);
}

int scanhash_tidecoin_yespower(int thr_id, uint32_t *pdata,
    const uint32_t *ptarget,
    uint32_t max_nonce, unsigned long *hashes_done)
{
    static const yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 8,
        .pers = NULL,
        .perslen = 0
    };

    // Use aligned memory for SIMD operations
    ALIGN16 union {
        uint8_t u8[8];
        uint32_t u32[20];
    } data;
    
    ALIGN16 union {
        yespower_binary_t yb;
        uint32_t u32[7];
    } hash;

    uint32_t n = pdata[19] - 1;
    const uint32_t Htarg = ptarget[7];
    int i;

    // SIMD-optimized data preparation
    for (i = 0; i < 19; i++)
        store_be32(&data.u32[i], pdata[i]);

    do {
        store_be32(&data.u32[19], ++n);

        if (yespower_tls(data.u8, 80, &params, &hash.yb))
            abort();

        if (load_le32(&hash.u32[7]) <= Htarg) {
            for (i = 0; i < 7; i++)
                hash.u32[i] = load_le32(&hash.u32[i]);
            if (fulltest(hash.u32, ptarget)) {
                *hashes_done = n - pdata[19] + 1;
                pdata[19] = n;
                return 1;
            }
        }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;
    return 0;
}
