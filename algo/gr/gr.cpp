/*
 * Copyright 2021 Delgon
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "gr-gate.h"

#include "cryptonote/cryptonight.h"

#define CRYPTONIGHT_HASH(variant, way)                                         \
  if (prefetch_l1) {                                                           \
    if (way == CN_2WAY) {                                                      \
      cryptonight_2way_hash<variant, true>(hash0, hash1, hash0, hash1);        \
    } else {                                                                   \
      cryptonight_hash<variant, true>(hash0, hash0);                           \
      cryptonight_hash<variant, true>(hash1, hash1);                           \
    }                                                                          \
  } else {                                                                     \
    if (way == CN_2WAY) {                                                      \
      cryptonight_2way_hash<variant, false>(hash0, hash1, hash0, hash1);       \
    } else {                                                                   \
      cryptonight_hash<variant, false>(hash0, hash0);                          \
      cryptonight_hash<variant, false>(hash1, hash1);                          \
    }                                                                          \
  }

#define CORE_HASH(hash, input, output, size)                                   \
  sph_##hash##512_init(&ctx.hash);                                             \
  sph_##hash##512(&ctx.hash, input, size);                                     \
  sph_##hash##512_close(&ctx.hash, output);

int gr_hash(void *output, const void *input0, const void *input1,
            const int thr_id) {
  uint64_t hash0[10] __attribute__((aligned(64)));
  uint64_t hash1[10] __attribute__((aligned(64)));
  gr_context_overlay ctx;
  memcpy(&ctx, &gr_ctx, sizeof(ctx));

  switch (gr_hash_order[0]) {
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

    // Stop early.
    if (work_restart[thr_id].restart && !(opt_benchmark || opt_tune)) {
      if (opt_debug && !thr_id) {
        applog(LOG_DEBUG, "Threads exit early.");
      }
      return 0;
    }
  }
  memcpy(output, hash0, 32);
  memcpy(&((uint8_t *)output)[32], hash1, 32);
  return 1;
}

int scanhash_gr(struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                struct thr_info *mythr) {
  uint32_t hash[2 * 8] __attribute__((aligned(64)));
  uint32_t edata0[20] __attribute__((aligned(64)));
  uint32_t edata1[20] __attribute__((aligned(64)));
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  const uint32_t first_nonce = pdata[19];
  const uint32_t last_nonce = max_nonce - 2;
  const int thr_id = mythr->id;
  uint32_t nonce = first_nonce;
  uint32_t hashes = 1;
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
      applog(LOG_BLUE, "Starting benchmark. Benchmark takes %.0lfs to complete",
             gr_benchmark_time / 1e6);
    }
    benchmark(pdata, thr_id, 0);
    if (thr_id == 0) {
      exit(0);
    }
  }

  mm128_bswap32_80(edata0, pdata);
  mm128_bswap32_80(edata1, pdata);

  gr_getAlgoString((const uint8_t *)(&edata0[1]), gr_hash_order);
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

  edata0[19] = nonce;
  edata1[19] = nonce + 1;

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

  while (likely((nonce < last_nonce) && !(*restart))) {
    if (gr_hash(hash, edata0, edata1, thr_id)) {
      if (hashes % 50 != 0) {
        for (int i = 0; i < 2; i++) {
          if (unlikely(valid_hash(hash + (i << 3), ptarget))) {
            if (opt_debug) {
              applog(LOG_BLUE, "Solution found. Nonce: %u | Diff: %.10lf",
                     bswap_32(nonce + i), hash_to_diff(hash + (i << 3)));
            }
            pdata[19] = bswap_32(nonce + i);
            submit_solution(work, hash + (i << 3), mythr);
            check_prepared();
          }
        }
      }
    }
    edata0[19] += 2;
    edata1[19] += 2;
    nonce += 2;
    hashes += (enable_donation && donation_percent >= 1.75) ? 0 : 1;
  }
  pdata[19] = nonce;
  *hashes_done = pdata[19] - first_nonce;
  return 0;
}
