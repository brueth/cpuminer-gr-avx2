/*
 * Copyright 2021 Delgon
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "gr-gate.h"

#if defined(GR_4WAY)

#include "cryptonote/cryptonight.h"
bool vectorized = false;

#define CRYPTONIGHT_HASH(variant, way)                                         \
  if (vectorized) {                                                            \
    dintrlv_4x64_512(hash0, hash1, hash2, hash3, vhash);                       \
  }                                                                            \
  bool pref = true; 
  if (prefetch_l1) { pref = true;  } else { pref = false; }

  if (way == CN_4WAY) {                                                      \
    cryptonight_4way_hash<variant, pref>(hash0, hash1, hash2, hash3, 
                                        hash0,  hash1, hash2, hash3);        \
  } else if (way == CN_2WAY) {                                               \
    cryptonight_2way_hash<variant, pref>(hash0, hash1, hash0, hash1);        \
    cryptonight_2way_hash<variant, pref>(hash2, hash3, hash2, hash3);        \
  } else {                                                                   \
    cryptonight_hash<variant, pref>(hash0, hash0);                           \
    cryptonight_hash<variant, pref>(hash1, hash1);                           \
    cryptonight_hash<variant, pref>(hash2, hash2);                           \
    cryptonight_hash<variant, pref>(hash3, hash3);                           \
  }                                                                          \
                                                                          \
  vectorized = false;

int gr_4way_hash(void *output, const void *input, const int thr_id) {
  uint64_t hash0[10] __attribute__((aligned(64)));
  uint64_t hash1[10] __attribute__((aligned(64)));
  uint64_t hash2[10] __attribute__((aligned(64)));
  uint64_t hash3[10] __attribute__((aligned(64)));
  uint64_t vhash[10 * 4] __attribute__((aligned(128)));
  uint64_t vhashA[10 * 2] __attribute__((aligned(128)));
  uint64_t vhashB[10 * 2] __attribute__((aligned(128)));
  
  gr_4way_context_overlay ctx;
  memcpy(&ctx, &gr_4way_ctx, sizeof(ctx));
  // Start as vectorized from input.
  bool vectorized = true;

  for (int i = 1; i < 15 + 3; i++) 
  {
    const uint8_t algo = gr_hash_order[i];
    switch (algo) {
    case CNTurtlelite:
      CRYPTONIGHT_HASH(TURTLELITE, cn_config[Turtlelite]);
      break;
    case CNTurtle:
      CRYPTONIGHT_HASH(TURTLE, cn_config[Turtle]);
      break;
    case CNDarklite:
      CRYPTONIGHT_HASH(DARKLITE, cn_config[Darklite]);
      break;
    case CNDark:
      CRYPTONIGHT_HASH(DARK, cn_config[Dark]);
      break;
    case CNLite:
      CRYPTONIGHT_HASH(LITE, cn_config[Lite]);
      break;
    case CNFast:
      CRYPTONIGHT_HASH(FAST, cn_config[Fast]);
      break;
    }

    // Stop early. do not stop while benchmarking or tuning.
    if (work_restart[thr_id].restart) 
    {
      if (!(opt_benchmark || opt_tune))
      {
        if (opt_debug && !thr_id) 
        {
          applog(LOG_DEBUG, "Threads exit early.");
        }
        return 0;
      }
    }
  }
  memcpy(output, hash0, 32);
  memcpy(&((uint8_t *)output)[32], hash1, 32);
  memcpy(&((uint8_t *)output)[64], hash2, 32);
  memcpy(&((uint8_t *)output)[96], hash3, 32);

  return 1;
}

int scanhash_gr_4way(struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr) {
  uint32_t hash[8 * 4] __attribute__((aligned(64)));
  uint32_t vdata[20 * 4] __attribute__((aligned(64)));
  uint32_t edata[20] __attribute__((aligned(64)));
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  const uint32_t first_nonce = pdata[19];
  const uint32_t last_nonce = max_nonce - 4;
  const int thr_id = mythr->id;
  uint32_t n = first_nonce;
  uint32_t hashes = 1;
  __m256i *noncev = (__m256i *)vdata + 9; // aligned
  volatile uint8_t *restart = &(work_restart[thr_id].restart);

  if (opt_stress_test) {
    stress_test(pdata, thr_id);
  }

  if (!opt_tuned && opt_tune) {
    sleep(1);
    tune(pdata, thr_id);
    opt_tuned = true; // Tuned.
    opt_tune = false;
    return 0;
  }

  if (opt_benchmark) {
    sleep(1);
    if (thr_id == 0) {
      applog(LOG_BLUE, "Debut du benchmark. Ca va prendre %.0lfs pour finir",
             gr_benchmark_time / 1e6);
    }
    benchmark(pdata, thr_id, 0);
    if (thr_id == 0) {
      exit(0);
    }
  }

  mm256_bswap32_intrlv80_4x64(vdata, pdata);

  // Check if algorithm order changed.
  mm128_bswap32_80(edata, pdata);
  gr_getAlgoString((const uint8_t *)(&edata[1]), gr_hash_order);
  if (opt_debug && !thr_id) {
    char order[100];
    for (int i = 0; i < 15 + 3; i++) {
      sprintf(order + (i * 3), "%02d ", gr_hash_order[i]);
    }
    applog(LOG_DEBUG, "Hash order %s", order);
  }
  if (opt_tuned) {
    select_tuned_config(thr_id);
  }

  // Allocates hp_state for Cryptonight algorithms.
  // Needs to be run AFTER gr_hash_order is set!
  AllocateNeededMemory(true);

  *noncev = mm256_intrlv_blend_32(
      _mm256_set_epi32(n + 3, 0, n + 2, 0, n + 1, 0, n, 0), *noncev);

  // Check if current rotation is "disabled" by the user.
  if (is_rot_disabled()) {
    if (thr_id == 0) {
      applog(LOG_WARNING, "Detected disabled rotation %d. Waiting...",
             (get_config_id() / 2) + 1);
    }
    while (!(*restart)) {
      // sleep for 50ms
      // TODO
      // use pthread_cond instead.
      usleep(50000);
    }
    hashes_done = 0;
    return 0;
  }

  if (!is_thread_used(thr_id)) {
    while (!(*restart)) {
      // sleep for 50ms
      // TODO
      // use pthread_cond instead.
      usleep(50000);
    }
    hashes_done = 0;
    return 0;
  }

  while (likely((n < last_nonce) && !(*restart))) {
    if (gr_4way_hash(hash, vdata, thr_id)) {
      if (hashes % 50 != 0) {
        for (int i = 0; i < 4; i++) {
          if (unlikely(valid_hash(hash + (i << 3), ptarget))) {
            if (opt_debug) {
              applog(LOG_BLUE, "Solution found. Nonce: %u | Diff: %.10lf",
                     bswap_32(n + i), hash_to_diff(hash + (i << 3)));
            }
            pdata[19] = bswap_32(n + i);
            submit_solution(work, hash + (i << 3), mythr);
            check_prepared();
          }
        }
      }
    }
    *noncev = _mm256_add_epi32(*noncev, m256_const1_64(0x0000000400000000));
    n += 4;
    hashes += (enable_donation && donation_percent >= 1.75) ? 0 : 1;
  }
  pdata[19] = n;
  *hashes_done = n - first_nonce;
  return 0;
}

#endif // GR_4WAY
