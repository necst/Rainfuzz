/*
   american fuzzy lop++ - fuzze_one routines in different flavours
   ---------------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include "afl-fuzz-one.h"
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>

#include "cmplog.h"

afl_state_t* afl_global;

/* MOpt */

static int select_algorithm(afl_state_t *afl, u32 max_algorithm) {

  int i_puppet, j_puppet = 0, operator_number = max_algorithm;

  double range_sele =
      (double)afl->probability_now[afl->swarm_now][operator_number - 1];
  double sele = ((double)(rand_below(afl, 10000) * 0.0001 * range_sele));

  for (i_puppet = 0; i_puppet < operator_num; ++i_puppet) {

    if (unlikely(i_puppet == 0)) {

      if (sele < afl->probability_now[afl->swarm_now][i_puppet]) { break; }

    } else {

      if (sele < afl->probability_now[afl->swarm_now][i_puppet]) {

        j_puppet = 1;
        break;

      }

    }

  }

  if ((j_puppet == 1 &&
       sele < afl->probability_now[afl->swarm_now][i_puppet - 1]) ||
      (i_puppet + 1 < operator_num &&
       sele > afl->probability_now[afl->swarm_now][i_puppet + 1])) {

    FATAL("error select_algorithm");

  }

  return i_puppet;

}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(afl_state_t *afl, u32 limit) {

  if( limit == 0) return 0;
  u32 min_value, max_value;
  u32 rlim = MIN(afl->queue_cycle, (u32)3);

  if (unlikely(!afl->run_over10m)) { rlim = 1; }

  switch (rand_below(afl, rlim)) {

    case 0:
      min_value = 1;
      max_value = HAVOC_BLK_SMALL;
      break;

    case 1:
      min_value = HAVOC_BLK_SMALL;
      max_value = HAVOC_BLK_MEDIUM;
      break;

    default:

      if (likely(rand_below(afl, 10))) {

        min_value = HAVOC_BLK_MEDIUM;
        max_value = HAVOC_BLK_LARGE;

      } else {

        min_value = HAVOC_BLK_LARGE;
        max_value = HAVOC_BLK_XL;

      }

  }

  if (min_value >= limit) { min_value = 1; }

  return min_value + rand_below(afl, MIN(max_value, limit) - min_value + 1);

}

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val) {

  u32 sh = 0;

  if (!xor_val) { return 1; }

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) {

    ++sh;
    xor_val >>= 1;

  }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) { return 1; }

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) { return 0; }

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff) {

    return 1;

  }

  return 0;

}

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) { return 1; }

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; (u8)i < blen; ++i) {

    u8 a = old_val >> (8 * i), b = new_val >> (8 * i);

    if (a != b) {

      ++diffs;
      ov = a;
      nv = b;

    }

  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u8)(ov - nv) <= ARITH_MAX || (u8)(nv - ov) <= ARITH_MAX) { return 1; }

  }

  if (blen == 1) { return 0; }

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; (u8)i < blen / 2; ++i) {

    u16 a = old_val >> (16 * i), b = new_val >> (16 * i);

    if (a != b) {

      ++diffs;
      ov = a;
      nv = b;

    }

  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) {

      return 1;

    }

    ov = SWAP16(ov);
    nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) {

      return 1;

    }

  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) {

      return 1;

    }

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) {

      return 1;

    }

  }

  return 0;

}

/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

  u32 i, j;

  if (old_val == new_val) { return 1; }

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; ++i) {

    for (j = 0; j < sizeof(interesting_8); ++j) {

      u32 tval =
          (old_val & ~(0xff << (i * 8))) | (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval) { return 1; }

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) { return 0; }

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; (u8)i < blen - 1; ++i) {

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) { return 1; }

      /* Continue here only if blen > 2. */

      if (blen > 2) {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) { return 1; }

      }

    }

  }

  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

      if (new_val == (u32)interesting_32[j]) { return 1; }

    }

  }

  return 0;

}

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset.
   We use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; ++pos) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) { f_loc = pos; }
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}

#endif                                                     /* !IGNORE_FINDS */


/*
  Performs a deterministic mutation, by trying to flip every bit within the seed (out_buf)
  While doing so, it also tries to detect tokens that could be reused as dictionary tokens
  for future mutations (auto extras)
*/
int walking_bitflip_stage(afl_state_t* afl, u8* out_buf) {

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

  u32 len = afl->queue_cur->len; // length of the current seed
  
  u64 orig_hit_cnt, new_hit_cnt = 0;
  u64 prev_cksum, cksum;

  u32 a_len = 0; // length of the current auto token
  u8  a_collect[MAX_AUTO_EXTRA];

  /* Single walking bit. */

  afl->stage_short = "flip1";
  afl->stage_max = len << 3;
  afl->stage_name = "bitflip 1/1";

  LOG_MESSAGE("mutations: flip1\n");

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  prev_cksum = afl->queue_cur->exec_cksum;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {
    LOG_TIME("BEGIN flip1(): %ld\n");

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT1-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { return 1; }
    LOG_SEED("MUTATED_SEED: ", out_buf, len);

    FLIP_BIT(out_buf, afl->stage_cur);

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).

       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

    */


    cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    if (afl->stage_cur == afl->stage_max - 1 && cksum == prev_cksum) {

      /* If at end of file and we are still collecting a string, grab the
          final character and force output. */

      if (a_len < MAX_AUTO_EXTRA) {

        a_collect[a_len] = out_buf[afl->stage_cur >> 3];

      }

      ++a_len;

      if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA) {

        maybe_add_auto(afl, a_collect, a_len);

      }

    } else if (cksum != prev_cksum) {

      /* Otherwise, if the checksum has changed, see if we have something
          worthwhile queued up, and collect that if the answer is yes. */

      if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA) {

        maybe_add_auto(afl, a_collect, a_len);

      }

      a_len = 0;
      prev_cksum = cksum;

    }

    /* Continue collecting string, but only if the bit flip actually made
        any difference - we don't want no-op tokens. */

    if (cksum != afl->queue_cur->exec_cksum) {

      if (a_len < MAX_AUTO_EXTRA) {

        a_collect[a_len] = out_buf[afl->stage_cur >> 3];

      }

      ++a_len;

    }

    LOG_TIME("END flip1(): %ld\n");

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP1] += afl->stage_max;

  return 0;
  
}

void crash() {
  LOG_MESSAGE("ASDZXC\n");
  ABORT("TOO LONG");
}

int add_to_byte_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN add_to_byte_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: add8'\n");
  u8 orig = (*out_buf)[pos];
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  int val = rand_below(afl, ARITH_MAX);
  LOG_FS_MESSAGE("rand value: %d\n", val);

  afl->stage_name = "add8";
  afl->stage_short = "add8";
  afl->stage_cur_val = val;
  afl->stage_val_type = STAGE_VAL_LE;

  (*out_buf)[pos] = orig + val;

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur; TODO
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  (*out_buf)[pos] = orig;
  LOG_TIME("END add_to_byte_mutation(): %ld\n");
  return 0;
}

int assign_random_byte_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN assign_random_byte_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: rass8'\n");
  u8 orig = (*out_buf)[pos];
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  unsigned char val = rand_below(afl, 255);
  LOG_FS_MESSAGE("rand value: %d\n", val);

  afl->stage_name = "rass8";
  afl->stage_short = "rass8";
  afl->stage_cur_val = val;
  afl->stage_val_type = STAGE_VAL_LE;

  (*out_buf)[pos] = orig ^ (val + 1); 

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur; TODO
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  (*out_buf)[pos] = orig;
  LOG_TIME("END assign_random_byte_mutation(): %ld\n");
  return 0;
}

int piece_insert_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN piece_insert_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: pin'\n");
  u32 piece_len = choose_block_len(afl, MAX_FILE - old_len);
  if(piece_len > MAX_FILE - old_len) {
    piece_len = choose_block_len(afl, MAX_FILE - old_len);
  }

  
  u32 from = rand_below(afl, old_len - piece_len + 1);
  LOG_FS_MESSAGE("piece_len: %d\n", piece_len);
  LOG_FS_MESSAGE("from: %d\n", from);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  
  afl->stage_name = "pin";
  afl->stage_short = "pin";
  u8 rand_value = rand_below(afl, 256);
  LOG_FS_MESSAGE("rand value: %d\n", rand_value);
  afl->stage_val_type = STAGE_VAL_NONE;

  if(piece_len <= 0) {  
    return -1; 
  }

  u8* ex_tmp = afl_realloc(AFL_BUF_PARAM(ex), old_len + piece_len);
  if (unlikely(!ex_tmp)) { PFATAL("alloc"); }
  (*out_buf) = ex_tmp;
  
  /* Copy head */
  memcpy(ex_tmp, in_buf, pos);

  /* Copy tail */
  memcpy(ex_tmp + pos + piece_len, in_buf + pos, old_len - pos);

  /* Insert piece */
  memset(ex_tmp + pos, rand_value, piece_len);

  

  *new_len = old_len + piece_len;
  LOG_SEED("MUTATED_SEED: ", ex_tmp, *new_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, ex_tmp, *new_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  memcpy((*out_buf), in_buf, afl->queue_cur->len); //TODO: is this necessary / sufficient

  LOG_TIME("END piece_insert_mutation(): %ld\n");
  return 0;
  
}

int piece_overwrite_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN piece_overwrite_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: pov'\n");
  u32 piece_len = choose_block_len(afl, old_len);
  u32 from = rand_below(afl, old_len - piece_len + 1);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  
  afl->stage_name = "pov";
  afl->stage_short = "pov";
  u8 rand_value = rand_below(afl, 256);
  LOG_FS_MESSAGE("rand value: %d\n", rand_value);
  afl->stage_val_type = STAGE_VAL_NONE;

  if(piece_len <= 0) {  
    return -1; 
  }
  
  memset((*out_buf) + pos, rand_value , piece_len);

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  memcpy((*out_buf), in_buf, afl->queue_cur->len);

  LOG_TIME("END piece_overwrite_mutation(): %ld\n");
  return 0;
  
}

int clone_piece_insert_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN clone_piece_insert_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: cpin'\n");
  u32 clone_len = choose_block_len(afl, MAX_FILE - old_len);
  if(clone_len > old_len) {
    clone_len = choose_block_len(afl, old_len);
  }
  if(clone_len <= 0) {  
    return -1; 
  }
  u32 clone_from = rand_below(afl, old_len - clone_len + 1);
  LOG_FS_MESSAGE("clone_len: %d\n", clone_len);
  LOG_FS_MESSAGE("clone_from: %d\n", clone_from);

  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  
  afl->stage_name = "cpin";
  afl->stage_short = "cpin";

  u8* cloned_piece = malloc(clone_len);
  memcpy(cloned_piece, in_buf + clone_from, clone_len);

  LOG_SEED("rand value: ", cloned_piece, clone_len);
  afl->stage_val_type = STAGE_VAL_NONE;

  u8* ex_tmp = afl_realloc(AFL_BUF_PARAM(ex), old_len + clone_len);
  if (unlikely(!ex_tmp)) { PFATAL("alloc"); }
  (*out_buf) = ex_tmp;
  
  /* Copy head */ //todo: can probably be avoided
  memcpy(ex_tmp, in_buf, pos);

  /* Copy tail */
  memcpy(ex_tmp + pos + clone_len, in_buf + pos, old_len - pos);

  /* Insert cloned piece */
  memcpy(ex_tmp + pos, cloned_piece, clone_len);

  *new_len = old_len + clone_len;

  LOG_SEED("MUTATED_SEED: ", ex_tmp, *new_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, ex_tmp, *new_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  memcpy((*out_buf), in_buf, afl->queue_cur->len); //TODO: is this necessary / sufficient

  LOG_TIME("END clone_piece_insert_mutation(): %ld\n");
  return 0;
  
}

int clone_piece_overwrite_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN clone_piece_overwrite_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: cpov'\n");
  u32 clone_len = choose_block_len(afl, old_len - pos);
  if(clone_len <= 0) {  
    return -1; 
  }
  u32 clone_from = rand_below(afl, old_len - clone_len + 1);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  
  afl->stage_name = "cpov";
  afl->stage_short = "cpov";
  LOG_SEED("rand value: ", (in_buf + clone_from), clone_len);
  afl->stage_val_type = STAGE_VAL_NONE;  
  
  memcpy((*out_buf) + pos, in_buf + clone_from, clone_len);

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  memcpy((*out_buf), in_buf, afl->queue_cur->len);

  LOG_TIME("END clone_piece_overwrite_mutation(): %ld\n");
  return 0;
  
}

int sub_from_byte_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN sub_from_byte_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: sub8'\n");
  u8 orig = (*out_buf)[pos];
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  int val = rand_below(afl, ARITH_MAX);
  LOG_FS_MESSAGE("rand value: %d\n", val);

  afl->stage_name = "sub8";
  afl->stage_short = "sub8";
  afl->stage_cur_val = -val;
  afl->stage_val_type = STAGE_VAL_LE;

  (*out_buf)[pos] = orig - val;

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur; TODO
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  (*out_buf)[pos] = orig;
  LOG_TIME("END sub_from_byte_mutation(): %ld\n");
  return 0;
}

int add_to_dbyte_le_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN add_to_dbyte_le_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: add16le'\n");
  if(old_len - pos < 2) return -1;
  u16 orig16 = *(u16 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  int val = rand_below(afl, ARITH_MAX);
  LOG_FS_MESSAGE("rand value: %d\n", val);

  afl->stage_name = "add16le";
  afl->stage_short = "add16le";
  afl->stage_cur_val = val;
  afl->stage_val_type = STAGE_VAL_LE;

  *(u16 *)((*out_buf) + pos) = orig16 + val;

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur; TODO
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u16 *)((*out_buf) + pos) = orig16;
  LOG_TIME("END add_to_dbyte_le_mutation(): %ld\n");
  return 0;
}

int sub_from_dbyte_le_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN sub_from_dbyte_le_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: sub16le'\n");
  if(old_len - pos < 2) return -1;
  u16 orig16 = *(u16 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  int val = rand_below(afl, ARITH_MAX);
  LOG_FS_MESSAGE("rand value: %d\n", val);

  afl->stage_name = "sub16le";
  afl->stage_short = "sub16le";
  afl->stage_cur_val = -val;
  afl->stage_val_type = STAGE_VAL_LE;

  *(u16 *)((*out_buf) + pos) = orig16 - val;

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur; TODO
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u16 *)((*out_buf) + pos) = orig16;
  LOG_TIME("END sub_from_dbyte_le_mutation(): %ld\n");
  return 0;
}

int add_to_dbyte_be_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN add_to_dbyte_be_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: add16be'\n");
  if(old_len - pos < 2) return -1;
  u16 orig16 = *(u16 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  int val = rand_below(afl, ARITH_MAX);
  LOG_FS_MESSAGE("rand value: %d\n", val);

  afl->stage_name = "add16be";
  afl->stage_short = "add16be";
  afl->stage_cur_val = val;
  afl->stage_val_type = STAGE_VAL_BE;

  *(u16 *)((*out_buf) + pos) = SWAP16(SWAP16(orig16) + val);

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur; TODO
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u16 *)((*out_buf) + pos) = orig16;
  LOG_TIME("END add_to_dbyte_be_mutation(): %ld\n");
  return 0;
}

int sub_from_dbyte_be_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN sub_from_dbyte_be_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: sub16be'\n");
  if(old_len - pos < 2) return -1;
  u16 orig16 = *(u16 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  int val = rand_below(afl, ARITH_MAX);
  LOG_FS_MESSAGE("rand value: %d\n", val);

  afl->stage_name = "sub16be";
  afl->stage_short = "sub16be";
  afl->stage_cur_val = -val;
  afl->stage_val_type = STAGE_VAL_BE;

  *(u16 *)((*out_buf) + pos) = SWAP16(SWAP16(orig16) - val);

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur; TODO
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u16 *)((*out_buf) + pos) = orig16;
  LOG_TIME("END sub_from_dbyte_be_mutation(): %ld\n");
  return 0;
}

int add_to_qbyte_le_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN add_to_qbyte_le_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: add32le'\n");
  if(old_len - pos < 4) return -1;
  u32 orig32 = *(u32 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  int val = rand_below(afl, ARITH_MAX);
  LOG_FS_MESSAGE("rand value: %d\n", val);

  afl->stage_name = "add32le";
  afl->stage_short = "add32le";
  afl->stage_cur_val = val;
  afl->stage_val_type = STAGE_VAL_LE;

  *(u32 *)((*out_buf) + pos) = orig32 + val;

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur; TODO
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u32 *)((*out_buf) + pos) = orig32;
  LOG_TIME("END add_to_qbyte_le_mutation(): %ld\n");

  return 0;
}

int sub_from_qbyte_le_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN sub_from_qbyte_le_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: sub32le'\n");
  if(old_len - pos < 4) return -1;
  u32 orig32 = *(u32 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  int val = rand_below(afl, ARITH_MAX);
  LOG_FS_MESSAGE("rand value: %d\n", val);

  afl->stage_name = "sub32le";
  afl->stage_short = "sub32le";
  afl->stage_cur_val = -val;
  afl->stage_val_type = STAGE_VAL_LE;

  *(u32 *)((*out_buf) + pos) = orig32 - val;

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur; TODO
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u32 *)((*out_buf) + pos) = orig32;
  LOG_TIME("END sub_from_qbyte_le_mutation(): %ld\n");
  return 0;
}

int add_to_qbyte_be_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN add_to_qbyte_be_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: add32be'\n");
  if(old_len - pos < 4) return -1;
  u32 orig32 = *(u32 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  int val = rand_below(afl, ARITH_MAX);
  LOG_FS_MESSAGE("rand value: %d\n", val);

  afl->stage_name = "add32be";
  afl->stage_short = "add32be";
  afl->stage_cur_val = val;
  afl->stage_val_type = STAGE_VAL_BE;

  *(u32 *)((*out_buf) + pos) = SWAP32(SWAP32(orig32) + val);

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur; TODO
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u32 *)((*out_buf) + pos) = orig32;
  LOG_TIME("END add_to_qbyte_be_mutation(): %ld\n");
  return 0;
}

int sub_from_qbyte_be_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN sub_from_qbyte_be_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: sub32be'\n");
  if(old_len - pos < 4) return -1;
  u32 orig32 = *(u32 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  int val = rand_below(afl, ARITH_MAX);
  LOG_FS_MESSAGE("rand value: %d\n", val);

  afl->stage_name = "sub32be";
  afl->stage_short = "sub32be";
  afl->stage_cur_val = -val;
  afl->stage_val_type = STAGE_VAL_BE;

  *(u32 *)((*out_buf) + pos) = SWAP32(SWAP32(orig32) - val);

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur; TODO
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u32 *)((*out_buf) + pos) = orig32;

  LOG_TIME("END sub_from_qbyte_be_mutation(): %ld\n");
  return 0;
}

int interesting_byte_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN interesting_byte_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: int8'\n");
  u8 orig = (*out_buf)[pos];
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_name = "int8";
  afl->stage_short = "int8";
  int k = rand_below(afl, sizeof(interesting_8));
  s8 val = interesting_8[k];
  LOG_FS_MESSAGE("rand value: %d\n", val);
  afl->stage_cur_val = val;
  afl->stage_val_type = STAGE_VAL_LE;

  (*out_buf)[pos] = val;

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  (*out_buf)[pos] = orig;

  LOG_TIME("END interesting_byte_mutation(): %ld\n");
  return 0;
}

int interesting_dbyte_le_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN interesting_dbyte_le_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: int16le'\n");
  if(old_len - pos < 2) return -1;
  u16 orig16 = *(u16 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_name = "int16le";
  afl->stage_short = "int16le";
  int k = rand_below(afl, sizeof(interesting_16));
  s16 val = interesting_16[k];
  LOG_FS_MESSAGE("rand value: %d\n", val);
  afl->stage_cur_val = val;
  afl->stage_val_type = STAGE_VAL_LE;

  *(u16 *)((*out_buf) + pos) = val;

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u16 *)((*out_buf) + pos) = orig16;

  LOG_TIME("END interesting_dbyte_le_mutation(): %ld\n");
  return 0;
}

int interesting_dbyte_be_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN interesting_dbyte_be_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: int16be'\n");
  if(old_len - pos < 2) return -1;
  u16 orig16 = *(u16 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_name = "int16be";
  afl->stage_short = "int16be";
  u32 k = rand_below(afl, sizeof(interesting_16));
  s16 val = interesting_16[k];
  LOG_FS_MESSAGE("rand value: %d\n", val);
  afl->stage_cur_val = val;
  afl->stage_val_type = STAGE_VAL_BE;

  *(u16 *)((*out_buf) + pos) = SWAP16(val);

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u16 *)((*out_buf) + pos) = orig16;

  LOG_TIME("END interesting_dbyte_be_mutation(): %ld\n");
  return 0;
}

int interesting_qbyte_le_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN interesting_qbyte_le_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: int32le'\n");
  if(old_len - pos < 4) return -1;
  u32 orig32 = *(u32 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_name = "int32le";
  afl->stage_short = "int32le";
  int k = rand_below(afl, sizeof(interesting_32));
  s32 val = interesting_32[k];
  LOG_FS_MESSAGE("rand value: %d\n", val);
  afl->stage_cur_val = val;
  afl->stage_val_type = STAGE_VAL_LE;

  *(u32 *)((*out_buf) + pos) = val;

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u32 *)((*out_buf) + pos) = orig32;

  LOG_TIME("END interesting_qbyte_le_mutation(): %ld\n");
  return 0;
}

int interesting_qbyte_be_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN interesting_qbyte_be_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: int32be'\n");
  if(old_len - pos < 4) return -1;
  u32 orig32 = *(u32 *)((*out_buf) + pos);
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_name = "int32be";
  afl->stage_short = "int32be";
  int k = rand_below(afl, sizeof(interesting_32));
  s32 val = interesting_32[k];
  LOG_FS_MESSAGE("rand value: %d\n", val);
  afl->stage_cur_val = val;
  afl->stage_val_type = STAGE_VAL_BE;

  *(u32 *)((*out_buf) + pos) = SWAP32(val);

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  *(u32 *)((*out_buf) + pos) = orig32;

  LOG_TIME("END interesting_qbyte_be_mutation(): %ld\n");
  return 0;
}

int user_extra_overwrite_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN user_extra_overwrite_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: uextraov'\n");
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  
  afl->stage_name = "uextraov";
  afl->stage_short = "uextraov";
  if(afl->extras_cnt <= 0) return -1;
  int k = rand_below(afl, afl->extras_cnt);
  LOG_SEED("rand value: ", afl->extras[k].data,afl->extras[k].len);
  afl->stage_val_type = STAGE_VAL_NONE;

  if(afl->extras[k].len > old_len - pos) {  //TODO: consider skipping noop !memcmp(afl->extras[j].data, out_buf + i, afl->extras[j].len)
    return -1;
  }

  memcpy((*out_buf) + pos, afl->extras[k].data, afl->extras[k].len);

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  /* Restore all the clobbered memory. */
  memcpy((*out_buf) + pos, in_buf + pos, afl->extras[k].len);
  LOG_TIME("END user_extra_overwrite_mutation(): %ld\n");
  return 0;
}

int user_extra_insert_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN user_extra_insert_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: uextrain'\n");
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  
  afl->stage_name = "uextrain";
  afl->stage_short = "uextrain";
  if(afl->extras_cnt <= 0) return -1;
  int k = rand_below(afl, afl->extras_cnt);
  LOG_FS_MESSAGE("k=%d\n", k);
  LOG_FS_MESSAGE("extras_cnt=%d\n", afl->extras_cnt);
  LOG_SEED("rand value: ", afl->extras[k].data,afl->extras[k].len);
  afl->stage_val_type = STAGE_VAL_NONE;

  if(old_len + afl->extras[k].len > MAX_FILE) {  
    return -1; 
  }

  u8* ex_tmp = afl_realloc(AFL_BUF_PARAM(ex), old_len + afl->extras[k].len);
  if (unlikely(!ex_tmp)) { PFATAL("alloc"); }
  (*out_buf) = ex_tmp;
  
  /* Copy head */
  memcpy(ex_tmp, in_buf, pos); //todo: check correctness

  /* Copy tail */
  memcpy(ex_tmp + pos + afl->extras[k].len, in_buf + pos, old_len - pos);

  /* Insert token */
  memcpy(ex_tmp + pos, afl->extras[k].data, afl->extras[k].len);

  *new_len = old_len + afl->extras[k].len;
  LOG_SEED("MUTATED_SEED: ", ex_tmp, *new_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, ex_tmp, *new_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  memcpy((*out_buf), in_buf, afl->queue_cur->len); //TODO: is this necessary / sufficient

  LOG_TIME("END user_extra_insert_mutation(): %ld\n");
  return 0;
  
}

int auto_extra_overwrite_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN auto_extra_overwrite_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: aextraov'\n");
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  
  afl->stage_name = "aextraov";
  afl->stage_short = "aextraov";
  if(afl->extras_cnt <= 0) return -1;
  int k = rand_below(afl, afl->a_extras_cnt);
  LOG_FS_MESSAGE("a_extras_count=%d\n", afl->a_extras_cnt);
  LOG_FS_MESSAGE("k=%d\n", k);
  LOG_FS_MESSAGE("len=%d\n", afl->a_extras[k].len);
  LOG_SEED("rand value: ", afl->a_extras[k].data,afl->a_extras[k].len);
  afl->stage_val_type = STAGE_VAL_NONE;

  if(afl->a_extras[k].len > old_len - pos) {  //TODO: consider skipping noop !memcmp(afl->extras[j].data, out_buf + i, afl->extras[j].len)
    return -1; 
  }

  memcpy((*out_buf) + pos, afl->a_extras[k].data, afl->a_extras[k].len);

  LOG_SEED("MUTATED_SEED: ", (*out_buf), old_len);

  if(!ex) return 0;
  if (common_fuzz_stuff(afl, (*out_buf), old_len)) { return 1; }
  
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  /* Restore all the clobbered memory. */
  memcpy((*out_buf) + pos, in_buf + pos, afl->a_extras[k].len);
  LOG_TIME("END auto_extra_overwrite_mutation(): %ld\n");
  return 0;
}

int delete_block_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, u32 pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN delete_block_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: bdel'\n");
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  
  if(old_len < 10) {
    return -1;
  }

  afl->stage_name = "bdel";
  afl->stage_short = "bdel";
  u32 del_len = choose_block_len(afl, old_len - pos);
  del_len = del_len == old_len ? del_len - 1 : del_len;
  LOG_FS_MESSAGE("rand value: %d\n", del_len);
  afl->stage_val_type = STAGE_VAL_LE;

  memmove((*out_buf) + pos, (*out_buf) + pos + del_len, old_len - pos - del_len);
  *new_len = old_len - del_len;

  LOG_SEED("MUTATED_SEED: ", (*out_buf), *new_len);
  if(!ex) return 0;
  
  if (common_fuzz_stuff(afl, (*out_buf), *new_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  memcpy((*out_buf), in_buf, afl->queue_cur->len); //TODO: is this necessary / sufficient
  LOG_TIME("END delete_block_mutation(): %ld\n");
  return 0;
}

int auto_extra_insert_mutation(afl_state_t* afl, u8** out_buf, u8* in_buf, int pos, bool ex, u32 old_len, u32* new_len) {
  LOG_TIME("BEGIN auto_extra_insert_mutation(): %ld\n");
  LOG_MESSAGE("MUTATION: aextrain'\n");
  //u64 orig_hit_cnt = afl->queued_paths + afl->unique_crashes;
  if(afl->a_extras_cnt <= 0) return -1;
  afl->stage_name = "aextrain";
  afl->stage_short = "aextrain";
  int k = rand_below(afl, afl->a_extras_cnt);
  LOG_FS_MESSAGE("a_extras_count=%d\n", afl->a_extras_cnt);
  LOG_FS_MESSAGE("k=%d\n", k);
  LOG_FS_MESSAGE("old_len=%d\n", old_len);
  LOG_FS_MESSAGE("len=%d\n", afl->a_extras[k].len);
  LOG_SEED("rand value: ", afl->a_extras[k].data,afl->a_extras[k].len);
  
  afl->stage_val_type = STAGE_VAL_NONE;

  if(old_len + afl->a_extras[k].len > MAX_FILE) {  
    return -1; 
  }

  u8* ex_tmp = afl_realloc(AFL_BUF_PARAM(ex), old_len + afl->a_extras[k].len);
  if (unlikely(!ex_tmp)) { PFATAL("alloc"); }
  (*out_buf) = ex_tmp;
  
  /* Copy head */
  memcpy(ex_tmp, in_buf, pos); //todo: check correctness

  /* Insert token */
  memcpy(ex_tmp + pos, afl->a_extras[k].data, afl->a_extras[k].len);

  /* Copy tail */
  memcpy(ex_tmp + pos + afl->a_extras[k].len, in_buf + pos, old_len - pos);
  *new_len = old_len + afl->a_extras[k].len;

  LOG_SEED("MUTATED_SEED: ", ex_tmp, *new_len);
  if(!ex) return 0;
  if (common_fuzz_stuff(afl, ex_tmp, *new_len)) { return 1; }
  
  //u64 new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* ++afl->stage_cur;
  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
  */

  memcpy((*out_buf), in_buf, afl->queue_cur->len); //TODO: is this necessary / sufficient

  LOG_TIME("END auto_extra_insert_mutation(): %ld\n");
  return 0;
  
}
#ifndef RAIN_R4
  #ifndef RAIN_R1
    #ifndef RAIN_R2
      #ifndef RAIN_R3
        #define RAIN_R2
      #endif
    #endif
  #endif
#endif

/*
  Takes the original coverage map, and the coverage map produced by the mutated seed;
  returns a numerical value that represents the reward that we attribute to this mutation.
 ******
  For this implementation we decided to consider the reward as the sum of all the positive
  increments in the hit-counts of edges.
  New ideas can be valid and possibly better, more experiments are welcome.
*/
#ifdef RAIN_R1
u64 get_reward_single_mutation(u8* original_coverage_map, u8* new_coverage_map, u32 len) {
  LOG_TIME("BEGIN get_reward_single_mutation(): %ld\n");
  u64 tot = 0;
  for(u32 i = 0; i < len; i++) {
      if(new_coverage_map[i] > original_coverage_map[i]) {
          tot += new_coverage_map[i] - original_coverage_map[i];
      }
  }
  LOG_TIME("END get_reward_single_mutation(): %ld\n");
  return tot;
}
#endif

#ifdef RAIN_R4
u64 get_reward_single_mutation(u8* original_coverage_map, u8* new_coverage_map, u32 len) {
  LOG_TIME("BEGIN get_reward_single_mutation(): %ld\n");
  u64 res = 0;
  if (afl_global->last_exec_new_cov == 1) res = 1;
  LOG_TIME("END get_reward_single_mutation(): %ld\n");
  return res;
}
#endif

#ifdef RAIN_R2
u64 get_reward_single_mutation(u8* original_coverage_map, u8* new_coverage_map, u32 len) {
  LOG_TIME("BEGIN get_reward_single_mutation(): %ld\n");
  u64 tot = 0;
  for(u32 i = 0; i < len; i++) {
      if(new_coverage_map[i] > original_coverage_map[i]) {
          tot += 1;
      }
  }
  LOG_TIME("END get_reward_single_mutation(): %ld\n");
  return tot;
}
#endif

#ifdef RAIN_R3
u64 get_reward_single_mutation(u8* original_coverage_map, u8* new_coverage_map, u32 len) {
  LOG_TIME("BEGIN get_reward_single_mutation(): %ld\n");
  u64 tot = 0;
  for(u32 i = 0; i < len; i++) {
      if(new_coverage_map[i] && !original_coverage_map[i]) {
          tot += 1;
      }
  }
  LOG_TIME("END get_reward_single_mutation(): %ld\n");
  return tot;
}
#endif

/*
  if not already done, it runs the program once with the original seed, in order
  to retrieve the coverage map produced by the untouched seed.
*/ //TODO: check correctness

void get_initial_coverage(afl_state_t *afl, struct queue_entry* entry, u8* seed_buffer) {
  LOG_TIME("BEGIN get_initial_coverage(): %ld\n");
  if(!entry->original_coverage) {
    entry->original_coverage = (u8*) DFL_ck_alloc_nozero(afl->fsrv.map_size);
    common_fuzz_stuff(afl, seed_buffer, afl->queue_cur->len);
    memcpy(entry->original_coverage, afl->fsrv.trace_bits, afl->fsrv.map_size);
  }
  LOG_TIME("END get_initial_coverage(): %ld\n");

}
/*
  Updates the "global" reward associated to the mutations applied to a certain byte offset
*/
#ifndef RAIN_MAX_GLOBAL_REWARD
void update_global_reward(u64 new_reward, u64* count, u64* global_reward) {
  (*count)++;
  *global_reward = ((*count - 1)*(*global_reward) + new_reward)/(*count);
}
#endif

#ifdef RAIN_MAX_GLOBAL_REWARD
  void update_global_reward(u64 new_reward, u64* count, u64* global_reward) {
    (*count)++;
    if(new_reward >= 1) {
      *global_reward = 1;
    }
  }
#endif

void send_seed_and_size(char* seed, long length) {
    LOG_TIME("BEGIN send_seed_and_size(): %ld\n");
    LOG_FS_MESSAGE("%ld\n", out_buf_shmem);
    out_buf_shmem[0] = 0;
    ((long*) (out_buf_shmem + 1))[0] = length;
    memcpy(out_buf_shmem + 9, seed, length);
    sem_post(out_sem);
    LOG_FS_MESSAGE("SENT seed and size=%ld\n", length);
    sem_wait(in_sem);
    LOG_FS_MESSAGE("RECEIVED: %s\n", in_buf_shmem);    
    LOG_TIME("END send_seed_and_size(): %ld\n");
}

long get_next_action() {
    LOG_TIME("BEGIN get_next_action(): %ld\n");
    out_buf_shmem[0] = 1;
    sem_post(out_sem);
    LOG_MESSAGE("SENT get_next_action\n");
    sem_wait(in_sem);
    long next_pos = ((long*) in_buf_shmem)[0];
    LOG_FS_MESSAGE("RECEIVED next_action=%ld\n", next_pos); 
    LOG_TIME("END get_next_action(): %ld\n");
    return next_pos;  
}

void send_reward(long reward) {
    LOG_TIME("BEGIN send_reward(): %ld\n");
    out_buf_shmem[0] = 2;
    ((long*) (out_buf_shmem + 1))[0] = reward;
    sem_post(out_sem);
    LOG_FS_MESSAGE("SENT reward=%ld\n", reward);
    sem_wait(in_sem);
    LOG_FS_MESSAGE("RECEIVED: %s\n", in_buf_shmem);    
    LOG_TIME("END send_reward(): %ld\n");      
}

void send_new_entry_notice() {
    out_buf_shmem[0] = 3;
    sem_post(out_sem);
    LOG_MESSAGE("SENT new_entry_notice\n");
    sem_wait(in_sem);
    LOG_FS_MESSAGE("%s\n", in_buf_shmem);          
}

void send_finished_message() {
    out_buf_shmem[0] = 4;
    sem_post(out_sem);
    LOG_MESSAGE("SENT finished_message\n");
    sem_wait(in_sem);
    LOG_FS_MESSAGE("%s\n", in_buf_shmem);          
}

void close_semaphores() {
  // Only closing the semaphores, unlink is done by the python script
  sem_close(in_sem);
  sem_close(out_sem);
}

int (*mutations[25])() = {
    assign_random_byte_mutation, 
    add_to_byte_mutation,
    sub_from_byte_mutation,
    add_to_dbyte_le_mutation,
    sub_from_dbyte_le_mutation,
    add_to_dbyte_be_mutation,
    sub_from_dbyte_be_mutation,
    add_to_qbyte_le_mutation,
    sub_from_qbyte_le_mutation,
    add_to_qbyte_be_mutation,
    sub_from_qbyte_be_mutation,
    interesting_byte_mutation,
    interesting_dbyte_le_mutation,
    interesting_dbyte_be_mutation,
    interesting_qbyte_le_mutation,
    interesting_qbyte_be_mutation,
    user_extra_overwrite_mutation,
    user_extra_insert_mutation,
    auto_extra_overwrite_mutation,
    auto_extra_insert_mutation,
    clone_piece_insert_mutation,
    clone_piece_overwrite_mutation,
    piece_insert_mutation,
    piece_overwrite_mutation,
    delete_block_mutation
  };

/* returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */

u8 fuzz_one_original(afl_state_t *afl) {
  u32 len;
  u32 pos;
  u64 mutations_count = 0;
  u64 global_reward = 0; 
  u8 *in_buf, *out_buf; // *orig_in, *ex_tmp, *eff_map = 0;
  //u64 havoc_queued = 0, orig_hit_cnt, new_hit_cnt = 0;
  u32 /*splice_cycle = 0,*/ perf_score = 100, orig_perf;

  u8 ret_val = 1; // doing_det = 0;
  afl_global = afl;

  INIT_LOG_FILE()

  LOG_MESSAGE("BEGIN fuzz_one_original()\n");

  // init the semaphores and the shared memory buffers to handle communication with the python module
  if(!connected) {
    LOG_MESSAGE("initializing semaphores and shared memory.\n");

    out_sem = sem_open("/b", O_CREAT, 0666, 0);
    if ( out_sem == -1 ) {    
      perror("semaphore err."); 
    }

    in_sem = sem_open("/a", O_CREAT, 0666, 0);
    if ( in_sem == -1 ) {    
      perror("semaphore err."); 
    }

    int shm_out = shm_open("/bm", O_CREAT | O_RDWR, 0666);
    if ( shm_out == -1 ) {    
      perror("shared memory err."); 
    }

    int shm_in = shm_open("/am", O_CREAT | O_RDWR, 0666);
    if ( shm_in == -1 ) {    
      perror("shared memory err."); 
    }

    ftruncate(shm_out, MAX_FILE + 50);
    ftruncate(shm_in, MAX_FILE + 50);

    in_buf_shmem = (char*) mmap(NULL, MAX_FILE + 50, PROT_WRITE, MAP_SHARED, shm_in, 0);
    out_buf_shmem = (char*) mmap(NULL, MAX_FILE + 50, PROT_WRITE, MAP_SHARED, shm_out, 0);

    LOG_FS_MESSAGE("%ld\n", in_buf_shmem);
    LOG_FS_MESSAGE("%ld\n", out_buf_shmem);

    connected = true;
  }


#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (afl->queue_cur->depth > 1) return 1;

#else

  // if (likely(afl->pending_favored)) {
  //   /* If we have any favored, non-fuzzed new arrivals in the queue,
  //      possibly skip to them at the expense of already-fuzzed or non-favored
  //      cases. */

  //   if (((afl->queue_cur->was_fuzzed > 0 || afl->queue_cur->fuzz_level > 0) ||
  //        !afl->queue_cur->favored) &&
  //       likely(rand_below(afl, 100) < SKIP_TO_NEW_PROB)) {

  //     return 1;

  //   }

  // } else 
  // if (!afl->non_instrumented_mode && !afl->queue_cur->favored &&

  //            afl->queued_paths > 10) {

  //   /* Otherwise, still possibly skip non-favored cases, albeit less often.
  //      The odds of skipping stuff are higher for already-fuzzed inputs and
  //      lower for never-fuzzed entries. */

  //   if (afl->queue_cycle > 1 &&
  //       (afl->queue_cur->fuzz_level == 0 || afl->queue_cur->was_fuzzed)) {

  //     if (likely(rand_below(afl, 100) < SKIP_NFAV_NEW_PROB)) { return 1; }

  //   } else {

  //     if (likely(rand_below(afl, 100) < SKIP_NFAV_OLD_PROB)) { return 1; }

  //   }

  // }

#endif                                                     /* ^IGNORE_FINDS */

  if (unlikely(afl->not_on_tty)) {

    ACTF(
        "Fuzzing test case #%u (%u total, %llu uniq crashes found, "
        "perf_score=%0.0f, exec_us=%llu, hits=%u, map=%u)...",
        afl->current_entry, afl->queued_paths, afl->unique_crashes,
        afl->queue_cur->perf_score, afl->queue_cur->exec_us,
        likely(afl->n_fuzz) ? afl->n_fuzz[afl->queue_cur->n_fuzz_entry] : 0,
        afl->queue_cur->bitmap_size);
    fflush(stdout);

  }

  /*orig_in = */in_buf = queue_testcase_get(afl, afl->queue_cur);
  len = afl->queue_cur->len;

  out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
  if (unlikely(!out_buf)) { PFATAL("alloc"); }

  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/
  if (unlikely(afl->queue_cur->cal_failed)) {

    u8 res = FSRV_RUN_TMOUT;

    if (afl->queue_cur->cal_failed < CAL_CHANCES) {

      afl->queue_cur->exec_cksum = 0;

      res =
          calibrate_case(afl, afl->queue_cur, in_buf, afl->queue_cycle - 1, 0);

      if (unlikely(res == FSRV_RUN_ERROR)) {

        FATAL("Unable to execute target application");

      }

    }

    if (unlikely(afl->stop_soon) || res != afl->crash_mode) {

      ++afl->cur_skipped_paths;
      goto abandon_entry;

    }

  }

  /************
   * TRIMMING *
   ************/
  if (unlikely(!afl->non_instrumented_mode && !afl->queue_cur->trim_done &&
               !afl->disable_trim)) {

    u32 old_len = afl->queue_cur->len;

    u8 res = trim_case(afl, afl->queue_cur, in_buf);
    in_buf = queue_testcase_get(afl, afl->queue_cur);

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (unlikely(afl->stop_soon)) {

      ++afl->cur_skipped_paths;
      goto abandon_entry;

    }

    /* Don't retry trimming, even if it failed. */

    afl->queue_cur->trim_done = 1;

    len = afl->queue_cur->len;

    /* maybe current entry is not ready for splicing anymore */
    if (unlikely(len <= 4 && old_len > 4)) --afl->ready_for_splicing_count;

  }

  memcpy(out_buf, in_buf, len);
  /*********************
   * PERFORMANCE SCORE *
   *********************/

  if (likely(!afl->old_seed_selection))
    orig_perf = perf_score = afl->queue_cur->perf_score;
  else
    afl->queue_cur->perf_score = orig_perf = perf_score =
        calculate_score(afl, afl->queue_cur);

  if (unlikely(perf_score <= 0)) { goto abandon_entry; }

  if (unlikely(afl->shm.cmplog_mode &&
               afl->queue_cur->colorized < afl->cmplog_lvl &&
               (u32)len <= afl->cmplog_max_filesize)) {

    if (unlikely(len < 4)) {

      afl->queue_cur->colorized = CMPLOG_LVL_MAX;

    } else {

      if (afl->cmplog_lvl == 3 ||
          (afl->cmplog_lvl == 2 && afl->queue_cur->tc_ref) ||
          !(afl->fsrv.total_execs % afl->queued_paths) ||
          get_cur_time() - afl->last_path_time > 300000) {

        if (input_to_state_stage(afl, in_buf, out_buf, len)) {
          goto abandon_entry;

        }

      }

    }

  }

  /* Skip right away if -d is given, if it has not been chosen sufficiently
     often to warrant the expensive deterministic stage (fuzz_level), or
     if it has gone through deterministic testing in earlier, resumed runs
     (passed_det). */
  if (!(likely(afl->queue_cur->passed_det) || likely(afl->skip_deterministic) ||
      likely(perf_score <
             (afl->queue_cur->depth * 30 <= afl->havoc_max_mult * 100
                  ? afl->queue_cur->depth * 30
                  : afl->havoc_max_mult * 100))) && 
                  !(unlikely(afl->main_node_max &&
               (afl->queue_cur->exec_cksum % afl->main_node_max) !=
                   afl->main_node_id - 1)) && (afl->queue_cur->depth==1)) {

    //doing_det = 1;
    if(walking_bitflip_stage(afl, out_buf)) { goto abandon_entry; };
    /* we're properly done with deterministic steps and can mark it as such
      in the .state/ directory. In our case the deterministic stage coincides
      with the walking bitflip mutation.*/

    if (!afl->queue_cur->passed_det) { mark_as_det_done(afl, afl->queue_cur); }

  }


  /***************************
   * REINFORCEMENT MUTATIONS *
   * ************************/

  /*
    This is where the new stuff takes place.
  */

  send_seed_and_size(out_buf, len); //TODO: inviare solo una volta, salvare pythonside
  LOG_SEED("ORIGINAL_SEED: ", out_buf, len);

  get_initial_coverage(afl, afl->queue_cur, out_buf);
  bool is_rand = false;
  pos = get_next_action();
  afl->stage_cur_byte = pos;
  int res;
  int useless = 0;

  for(int i = 0; i < 25; i++) {
    res = mutations[i](afl, &out_buf, in_buf, pos, true, afl->queue_cur->len, &useless);
    if(!res) 
    {
      u64 new_reward = get_reward_single_mutation(afl->queue_cur->original_coverage, afl->fsrv.trace_bits, afl->fsrv.map_size);
      update_global_reward(new_reward, &mutations_count, &global_reward);
      
    } else { 
      if(res == 1) {
        goto abandon_entry;
      }
    }
  }

#ifdef RAIN_DO_HAVOC
  #ifdef RAIN_HAVOC_TEST
  if(true) {
  #endif
  #ifndef RAIN_HAVOC_TEST 
  if(afl->queue_cur->fuzz_level > afl->queue_cur->len) {
  #endif
    bool mutation_performed = false;
    u32 use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));
    LOG_FS_MESSAGE("Havoc for %d\n", use_stacking);
    int i = 0;
    int working_len = len;
    while(i < use_stacking) {
      int r;
      if(mutation_performed) {
        send_seed_and_size(out_buf, working_len);
        LOG_SEED("ORIGINAL_SEED: ", out_buf, working_len);
        pos = get_next_action();
      }
      mutation_performed = false;
      r = rand_below(afl, 25);
      if(r == 0) {
        assign_random_byte_mutation(afl, out_buf, pos, false, working_len);
      } else if(r == 1) {
        add_to_byte_mutation(afl, out_buf, pos, false, working_len);
      } else if(r == 2) {
        sub_from_byte_mutation(afl, out_buf, pos, false, working_len);
      } else if(r == 3) {
        interesting_byte_mutation(afl, out_buf, pos, false, working_len);
      } else if (r <= 9) {
        if (len - pos < 2) continue;
        if(r == 4) {
          add_to_dbyte_le_mutation(afl, out_buf, pos, false, working_len);
        } else if (r == 5) {
          sub_from_dbyte_le_mutation(afl, out_buf, pos, false, working_len);
        } else if (r == 6) {
          add_to_dbyte_be_mutation(afl, out_buf, pos, false, working_len);
        } else if (r == 7) {
          sub_from_dbyte_be_mutation(afl, out_buf, pos, false, working_len);
        } else if (r == 8) {
          interesting_dbyte_le_mutation(afl, out_buf, pos, false, working_len);
        } else if (r == 9) {
          interesting_dbyte_be_mutation(afl, out_buf, pos, false, working_len);
        }
      } else if(r <= 15) {
        if (len - pos < 4) continue;
        if(r == 10) {
          add_to_qbyte_le_mutation(afl, out_buf, pos, false, working_len);
        } else if (r == 11) {
          sub_from_qbyte_le_mutation(afl, out_buf, pos, false, working_len);
        } else if (r == 12) {
          add_to_qbyte_be_mutation(afl, out_buf, pos, false, working_len);
        } else if (r == 13) {
          sub_from_qbyte_be_mutation(afl, out_buf, pos, false, working_len);
        } else if (r == 14) {
          interesting_qbyte_le_mutation(afl, out_buf, pos, false, working_len);
        } else if (r == 15) {
          interesting_qbyte_be_mutation(afl, out_buf, pos, false, working_len);
        } 
      } else if (r <= 17) {
        if(!afl->extras_cnt) continue;
        if(r == 16) {
          if(user_extra_overwrite_mutation(afl, out_buf, in_buf, pos, false, working_len) == -1) continue;
        } else if(r == 17) {
          // if(user_extra_insert_mutation(afl, &out_buf, out_buf, pos, false, working_len, &working_len) == -1) continue;
        }
      } else if (r <= 19) {
        if(!afl->a_extras_cnt) continue;
        if(r == 18) {
          if(auto_extra_overwrite_mutation(afl, out_buf, in_buf, pos, false, working_len) == -1) continue;
        } else if(r == 19) {
          // if(auto_extra_insert_mutation(afl, &out_buf, out_buf, pos, false, working_len, &working_len) == -1) continue;
        }
      } else if (r == 20) {
        // if(clone_piece_insert_mutation(afl, &out_buf, out_buf, pos, false, working_len, &working_len) == -1) continue;
      } else if (r == 21) {
        if(clone_piece_overwrite_mutation(afl, out_buf, in_buf, pos, false, working_len) == -1) continue;
      } else if (r == 22) {
        // if(piece_insert_mutation(afl, &out_buf, out_buf, pos, false, working_len, &working_len) == -1) continue;
      } else if (r == 23) {
        if(piece_overwrite_mutation(afl, out_buf, in_buf, pos, false, working_len) == -1) continue;
      } else if (r == 24) {
        // if(delete_block_mutation(afl, out_buf, in_buf, pos, false, working_len, &working_len) == -1) continue;
      }
      mutation_performed = true;
      i++;
    }
    while(true){
      int r = rand_below(afl, 10);
      if (r == 0) {
        if(!user_extra_insert_mutation(afl, &out_buf, out_buf, pos, false, working_len, &working_len)) break;
      } else if(r == 1) {
        if(!auto_extra_insert_mutation(afl, &out_buf, out_buf, pos, false, working_len, &working_len)) break;
      } else if(r == 2) {
        if(!clone_piece_insert_mutation(afl, &out_buf, out_buf, pos, false, working_len, &working_len)) break;
      } else if(r == 3) {
        if(!piece_insert_mutation(afl, &out_buf, out_buf, pos, false, working_len, &working_len)) break;
      } else if(r == 4) {
        delete_block_mutation(afl, out_buf, in_buf, pos, false, working_len, &working_len);
        break;
      }
    }

    LOG_SEED("HAVOC_MUTATED_SEED: ", out_buf, working_len);
    res = common_fuzz_stuff(afl, out_buf, working_len);
    
    if(res) goto abandon_entry;
    
  }

#endif

// #endif                                                     /* !IGNORE_FINDS */

  ret_val = 0;

/* we are through with this queue entry - for this iteration */
abandon_entry:

  /* Update afl->pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!afl->stop_soon && !afl->queue_cur->cal_failed &&
      (afl->queue_cur->was_fuzzed == 0 || afl->queue_cur->fuzz_level == 0) &&
      !afl->queue_cur->disabled) {

    if (!afl->queue_cur->was_fuzzed) {

      --afl->pending_not_fuzzed;
      afl->queue_cur->was_fuzzed = 1;
      if (afl->queue_cur->favored) { --afl->pending_favored; }

    }

  }

  ++afl->queue_cur->fuzz_level;
  //orig_in = NULL;

  if(mutations_count > 0) send_reward(global_reward);
  LOG_MESSAGE("END: fuzz_one_original().\n");
  
  // Terminating RainFuzz if ran once
  #ifdef RAIN_RUN_ONCE
    afl->stop_soon = 1;
  #endif

  afl->fuzz_one_original_count++;
  
  // Terminating RainFuzz if reached max runs
  #ifdef RAIN_MAX_RUNS
    if(afl->fuzz_one_original_count > RAIN_MAX_RUNS) {
      afl->stop_soon = 1;
    }
  #endif

  return ret_val;

#undef FLIP_BIT

}

/* MOpt mode */
static u8 mopt_common_fuzzing(afl_state_t *afl, MOpt_globals_t MOpt_globals) {

  if (!MOpt_globals.is_pilot_mode) {

    if (swarm_num == 1) {

      afl->key_module = 2;
      return 0;

    }

  }

  u32 len, temp_len;
  u32 i;
  u32 j;
  u8 *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued = 0, orig_hit_cnt, new_hit_cnt = 0, cur_ms_lv, prev_cksum;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, eff_cnt = 1;

  u8 ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (afl->queue_cur->depth > 1) return 1;

#else

  if (likely(afl->pending_favored)) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if (((afl->queue_cur->was_fuzzed > 0 || afl->queue_cur->fuzz_level > 0) ||
         !afl->queue_cur->favored) &&
        rand_below(afl, 100) < SKIP_TO_NEW_PROB) {

      return 1;

    }

  } else if (!afl->non_instrumented_mode && !afl->queue_cur->favored &&

             afl->queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (afl->queue_cycle > 1 &&
        (afl->queue_cur->fuzz_level == 0 || afl->queue_cur->was_fuzzed)) {

      if (likely(rand_below(afl, 100) < SKIP_NFAV_NEW_PROB)) { return 1; }

    } else {

      if (likely(rand_below(afl, 100) < SKIP_NFAV_OLD_PROB)) { return 1; }

    }

  }

#endif                                                     /* ^IGNORE_FINDS */

  if (afl->not_on_tty) {

    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         afl->current_entry, afl->queued_paths, afl->unique_crashes);
    fflush(stdout);

  }

  /* Map the test case into memory. */
  orig_in = in_buf = queue_testcase_get(afl, afl->queue_cur);
  len = afl->queue_cur->len;

  out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
  if (unlikely(!out_buf)) { PFATAL("alloc"); }

  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (unlikely(afl->queue_cur->cal_failed)) {

    u8 res = FSRV_RUN_TMOUT;

    if (afl->queue_cur->cal_failed < CAL_CHANCES) {

      afl->queue_cur->exec_cksum = 0;

      res =
          calibrate_case(afl, afl->queue_cur, in_buf, afl->queue_cycle - 1, 0);

      if (res == FSRV_RUN_ERROR) {

        FATAL("Unable to execute target application");

      }

    }

    if (afl->stop_soon || res != afl->crash_mode) {

      ++afl->cur_skipped_paths;
      goto abandon_entry;

    }

  }

  /************
   * TRIMMING *
   ************/

  if (unlikely(!afl->non_instrumented_mode && !afl->queue_cur->trim_done &&
               !afl->disable_trim)) {

    u32 old_len = afl->queue_cur->len;

    u8 res = trim_case(afl, afl->queue_cur, in_buf);
    orig_in = in_buf = queue_testcase_get(afl, afl->queue_cur);

    if (res == FSRV_RUN_ERROR) {

      FATAL("Unable to execute target application");

    }

    if (afl->stop_soon) {

      ++afl->cur_skipped_paths;
      goto abandon_entry;

    }

    /* Don't retry trimming, even if it failed. */

    afl->queue_cur->trim_done = 1;

    len = afl->queue_cur->len;

    /* maybe current entry is not ready for splicing anymore */
    if (unlikely(len <= 4 && old_len > 4)) --afl->ready_for_splicing_count;

  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  if (likely(!afl->old_seed_selection))
    orig_perf = perf_score = afl->queue_cur->perf_score;
  else
    orig_perf = perf_score = calculate_score(afl, afl->queue_cur);

  if (unlikely(perf_score <= 0)) { goto abandon_entry; }

  if (unlikely(afl->shm.cmplog_mode &&
               afl->queue_cur->colorized < afl->cmplog_lvl &&
               (u32)len <= afl->cmplog_max_filesize)) {

    if (unlikely(len < 4)) {

      afl->queue_cur->colorized = CMPLOG_LVL_MAX;

    } else {

      if (afl->cmplog_lvl == 3 ||
          (afl->cmplog_lvl == 2 && afl->queue_cur->tc_ref) ||
          !(afl->fsrv.total_execs % afl->queued_paths) ||
          get_cur_time() - afl->last_path_time > 300000) {

        if (input_to_state_stage(afl, in_buf, out_buf, len)) {

          goto abandon_entry;

        }

      }

    }

  }

  /* Go to pacemker fuzzing if MOpt is doing well */

  cur_ms_lv = get_cur_time();
  if (!(afl->key_puppet == 0 &&
        ((cur_ms_lv - afl->last_path_time < (u32)afl->limit_time_puppet) ||
         (afl->last_crash_time != 0 &&
          cur_ms_lv - afl->last_crash_time < (u32)afl->limit_time_puppet) ||
         afl->last_path_time == 0))) {

    afl->key_puppet = 1;
    goto pacemaker_fuzzing;

  }

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (likely(afl->skip_deterministic || afl->queue_cur->was_fuzzed ||
             afl->queue_cur->passed_det)) {

    goto havoc_stage;

  }

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this main instance. */

  if (unlikely(afl->main_node_max &&
               (afl->queue_cur->exec_cksum % afl->main_node_max) !=
                   afl->main_node_id - 1)) {

    goto havoc_stage;

  }

  doing_det = 1;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

  /* Single walking bit. */

  afl->stage_short = "flip1";
  afl->stage_max = len << 3;
  afl->stage_name = "bitflip 1/1";

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  prev_cksum = afl->queue_cur->exec_cksum;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT1-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).

       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

      */

    if (!afl->non_instrumented_mode && (afl->stage_cur & 7) == 7) {

      u64 cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      if (afl->stage_cur == afl->stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) {

          a_collect[a_len] = out_buf[afl->stage_cur >> 3];

        }

        ++a_len;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA) {

          maybe_add_auto(afl, a_collect, a_len);

        }

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA) {

          maybe_add_auto(afl, a_collect, a_len);

        }

        a_len = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != afl->queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA) {

          a_collect[a_len] = out_buf[afl->stage_cur >> 3];

        }

        ++a_len;

      }

    }                                       /* if (afl->stage_cur & 7) == 7 */

  }                                                   /* for afl->stage_cur */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP1] += afl->stage_max;

  /* Two walking bits. */

  afl->stage_name = "bitflip 2/1";
  afl->stage_short = "flip2";
  afl->stage_max = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT2-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

  }                                                   /* for afl->stage_cur */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP2] += afl->stage_max;

  /* Four walking bits. */

  afl->stage_name = "bitflip 4/1";
  afl->stage_short = "flip4";
  afl->stage_max = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT4-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

  }                                                   /* for afl->stage_cur */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP4] += afl->stage_max;

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
         flag first and last byte as doing something. */

  eff_map = afl_realloc(AFL_BUF_PARAM(eff), EFF_ALEN(len));
  if (unlikely(!eff_map)) { PFATAL("alloc"); }
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {

    eff_map[EFF_APOS(len - 1)] = 1;
    ++eff_cnt;

  }

  /* Walking byte. */

  afl->stage_name = "bitflip 8/8";
  afl->stage_short = "flip8";
  afl->stage_max = len;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur;

    out_buf[afl->stage_cur] ^= 0xFF;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT8-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(afl->stage_cur)]) {

      u64 cksum;

      /* If in non-instrumented mode or if the file is very short, just flag
         everything without wasting time on checksums. */

      if (!afl->non_instrumented_mode && len >= EFF_MIN_LEN) {

        cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      } else {

        cksum = ~afl->queue_cur->exec_cksum;

      }

      if (cksum != afl->queue_cur->exec_cksum) {

        eff_map[EFF_APOS(afl->stage_cur)] = 1;
        ++eff_cnt;

      }

    }

    out_buf[afl->stage_cur] ^= 0xFF;

  }                                                   /* for afl->stage_cur */

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != (u32)EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

    memset(eff_map, 1, EFF_ALEN(len));

    afl->blocks_eff_select += EFF_ALEN(len);

  } else {

    afl->blocks_eff_select += eff_cnt;

  }

  afl->blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP8] += afl->stage_max;

  /* Two walking bytes. */

  if (len < 2) { goto skip_bitflip; }

  afl->stage_name = "bitflip 16/8";
  afl->stage_short = "flip16";
  afl->stage_cur = 0;
  afl->stage_max = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      --afl->stage_max;
      continue;

    }

    afl->stage_cur_byte = i;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT16-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
    ++afl->stage_cur;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP16] += afl->stage_max;

  if (len < 4) { goto skip_bitflip; }

  /* Four walking bytes. */

  afl->stage_name = "bitflip 32/8";
  afl->stage_short = "flip32";
  afl->stage_cur = 0;
  afl->stage_max = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      --afl->stage_max;
      continue;

    }

    afl->stage_cur_byte = i;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_FLIP_BIT32-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif
    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
    ++afl->stage_cur;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

  }                                               /* for i = 0; i < len - 3 */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP32] += afl->stage_max;

skip_bitflip:

  if (afl->no_arith) { goto skip_arith; }

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */

  afl->stage_name = "arith 8/8";
  afl->stage_short = "arith8";
  afl->stage_cur = 0;
  afl->stage_max = 2 * len * ARITH_MAX;

  afl->stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      afl->stage_max -= 2 * ARITH_MAX;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = j;
        out_buf[i] = orig + j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH8+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      r = orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = -j;
        out_buf[i] = orig - j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH8_-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      out_buf[i] = orig;

    }

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2) { goto skip_arith; }

  afl->stage_name = "arith 16/8";
  afl->stage_short = "arith16";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      afl->stage_max -= 4 * ARITH_MAX;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u16 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      afl->stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

        afl->stage_cur_val = j;
        *(u16 *)(out_buf + i) = orig + j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH16+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        *(u16 *)(out_buf + i) = orig - j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH16_-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      /* Big endian comes next. Same deal. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) + j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_ARITH16+BE-%u-%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) - j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_ARITH16_BE+%u+%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      *(u16 *)(out_buf + i) = orig;

    }

  }                                               /* for i = 0; i < len - 1 */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH16] += afl->stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4) { goto skip_arith; }

  afl->stage_name = "arith 32/8";
  afl->stage_short = "arith32";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      afl->stage_max -= 4 * ARITH_MAX;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u32 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      afl->stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

        afl->stage_cur_val = j;
        *(u32 *)(out_buf + i) = orig + j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH32+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        *(u32 *)(out_buf + i) = orig - j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_ARITH32_-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      /* Big endian next. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) + j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_ARITH32+BE-%u-%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) - j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_ARITH32_BE-%u-%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      *(u32 *)(out_buf + i) = orig;

    }

  }                                               /* for i = 0; i < len - 3 */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH32] += afl->stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  afl->stage_name = "interest 8/8";
  afl->stage_short = "int8";
  afl->stage_cur = 0;
  afl->stage_max = len * sizeof(interesting_8);

  afl->stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < (u32)len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      afl->stage_max -= sizeof(interesting_8);
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); ++j) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {

        --afl->stage_max;
        continue;

      }

      afl->stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s MOPT_INTERESTING8-%u-%u", afl->queue_cur->fname, i, j);
#endif
      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      out_buf[i] = orig;
      ++afl->stage_cur;

    }

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST8] += afl->stage_max;

  /* Setting 16-bit integers, both endians. */

  if (afl->no_arith || len < 2) { goto skip_interest; }

  afl->stage_name = "interest 16/8";
  afl->stage_short = "int16";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      afl->stage_max -= sizeof(interesting_16);
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      afl->stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        *(u16 *)(out_buf + i) = interesting_16[j];

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_INTERESTING16-%u-%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_INTERESTING16BE-%u-%u", afl->queue_cur->fname, i, j);
#endif
        *(u16 *)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

    }

    *(u16 *)(out_buf + i) = orig;

  }                                               /* for i = 0; i < len - 1 */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST16] += afl->stage_max;

  if (len < 4) { goto skip_interest; }

  /* Setting 32-bit integers, both endians. */

  afl->stage_name = "interest 32/8";
  afl->stage_short = "int32";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      afl->stage_max -= sizeof(interesting_32) >> 1;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

      afl->stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        *(u32 *)(out_buf + i) = interesting_32[j];

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_INTERESTING32-%u-%u", afl->queue_cur->fname, i, j);
#endif
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s MOPT_INTERESTING32BE-%u-%u", afl->queue_cur->fname, i, j);
#endif
        *(u32 *)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

    }

    *(u32 *)(out_buf + i) = orig;

  }                                               /* for i = 0; i < len - 3 */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST32] += afl->stage_max;

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!afl->extras_cnt) { goto skip_user_extras; }

  /* Overwrite with user-supplied extras. */

  afl->stage_name = "user extras (over)";
  afl->stage_short = "ext_UO";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u32 last_len = 0;

    afl->stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < afl->extras_cnt; ++j) {

      /* Skip extras probabilistically if afl->extras_cnt > AFL_MAX_DET_EXTRAS.
         Also skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((afl->extras_cnt > afl->max_det_extras &&
           rand_below(afl, afl->extras_cnt) >= afl->max_det_extras) ||
          afl->extras[j].len > len - i ||
          !memcmp(afl->extras[j].data, out_buf + i, afl->extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, afl->extras[j].len))) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->extras[j].len;
      memcpy(out_buf + i, afl->extras[j].data, last_len);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s MOPT_EXTRAS_overwrite-%u-%u", afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_UO] += afl->stage_max;

  /* Insertion of user-supplied extras. */

  afl->stage_name = "user extras (insert)";
  afl->stage_short = "ext_UI";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * (len + 1);

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = afl_realloc(AFL_BUF_PARAM(ex), len + MAX_DICT_FILE);
  if (unlikely(!ex_tmp)) { PFATAL("alloc"); }

  for (i = 0; i <= (u32)len; ++i) {

    afl->stage_cur_byte = i;

    for (j = 0; j < afl->extras_cnt; ++j) {

      if (len + afl->extras[j].len > MAX_FILE) {

        --afl->stage_max;
        continue;

      }

      /* Insert token */
      memcpy(ex_tmp + i, afl->extras[j].data, afl->extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + afl->extras[j].len, out_buf + i, len - i);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s MOPT_EXTRAS_insert-%u-%u", afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, ex_tmp, len + afl->extras[j].len)) {

        goto abandon_entry;

      }

      ++afl->stage_cur;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }                                                  /* for i = 0; i <= len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_UI] += afl->stage_max;

skip_user_extras:

  if (!afl->a_extras_cnt) { goto skip_extras; }

  afl->stage_name = "auto extras (over)";
  afl->stage_short = "ext_AO";
  afl->stage_cur = 0;
  afl->stage_max = MIN(afl->a_extras_cnt, (u32)USE_AUTO_EXTRAS) * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u32 last_len = 0;

    afl->stage_cur_byte = i;

    u32 min_extra_len = MIN(afl->a_extras_cnt, (u32)USE_AUTO_EXTRAS);
    for (j = 0; j < min_extra_len; ++j) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if ((afl->a_extras[j].len) > (len - i) ||
          !memcmp(afl->a_extras[j].data, out_buf + i, afl->a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, afl->a_extras[j].len))) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->a_extras[j].len;
      memcpy(out_buf + i, afl->a_extras[j].data, last_len);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s MOPT_AUTO_EXTRAS_overwrite-%u-%u", afl->queue_cur->fname, i,
               j);
#endif

      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_AO] += afl->stage_max;

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!afl->queue_cur->passed_det) { mark_as_det_done(afl, afl->queue_cur); }

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:
pacemaker_fuzzing:

  afl->stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    afl->stage_name = MOpt_globals.havoc_stagename;
    afl->stage_short = MOpt_globals.havoc_stagenameshort;
    afl->stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                     perf_score / afl->havoc_div / 100;

  } else {

    perf_score = orig_perf;

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE,
             MOpt_globals.splice_stageformat, splice_cycle);
    afl->stage_name = afl->stage_name_buf;
    afl->stage_short = MOpt_globals.splice_stagenameshort;
    afl->stage_max = SPLICE_HAVOC * perf_score / afl->havoc_div / 100;

  }

  s32 temp_len_puppet;

  // for (; afl->swarm_now < swarm_num; ++afl->swarm_now)
  {

    if (afl->key_puppet == 1) {

      if (unlikely(afl->orig_hit_cnt_puppet == 0)) {

        afl->orig_hit_cnt_puppet = afl->queued_paths + afl->unique_crashes;
        afl->last_limit_time_start = get_cur_time();
        afl->SPLICE_CYCLES_puppet =
            (rand_below(
                 afl, SPLICE_CYCLES_puppet_up - SPLICE_CYCLES_puppet_low + 1) +
             SPLICE_CYCLES_puppet_low);

      }

    }                                            /* if afl->key_puppet == 1 */

    {

#ifndef IGNORE_FINDS
    havoc_stage_puppet:
#endif

      afl->stage_cur_byte = -1;

      /* The havoc stage mutation code is also invoked when splicing files; if
         the splice_cycle variable is set, generate different descriptions and
         such. */

      if (!splice_cycle) {

        afl->stage_name = MOpt_globals.havoc_stagename;
        afl->stage_short = MOpt_globals.havoc_stagenameshort;
        afl->stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                         perf_score / afl->havoc_div / 100;

      } else {

        perf_score = orig_perf;
        snprintf(afl->stage_name_buf, STAGE_BUF_SIZE,
                 MOpt_globals.splice_stageformat, splice_cycle);
        afl->stage_name = afl->stage_name_buf;
        afl->stage_short = MOpt_globals.splice_stagenameshort;
        afl->stage_max = SPLICE_HAVOC * perf_score / afl->havoc_div / 100;

      }

      if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

      temp_len = len;

      orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

      havoc_queued = afl->queued_paths;

      u32 r_max;

      r_max = 15 + ((afl->extras_cnt + afl->a_extras_cnt) ? 2 : 0);

      if (unlikely(afl->expand_havoc && afl->ready_for_splicing_count > 1)) {

        /* add expensive havoc cases here, they are activated after a full
           cycle without finds happened */

        ++r_max;

      }

      for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max;
           ++afl->stage_cur) {

        u32 use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));

        afl->stage_cur_val = use_stacking;

        for (i = 0; i < operator_num; ++i) {

          MOpt_globals.cycles_v3[i] = MOpt_globals.cycles_v2[i];

        }

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s MOPT_HAVOC-%u",
                 afl->queue_cur->fname, use_stacking);
#endif

        for (i = 0; i < use_stacking; ++i) {

          switch (select_algorithm(afl, r_max)) {

            case 0:
              /* Flip a single bit somewhere. Spooky! */
              FLIP_BIT(out_buf, rand_below(afl, temp_len << 3));
              MOpt_globals.cycles_v2[STAGE_FLIP1]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT1");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 1:
              if (temp_len < 2) { break; }
              temp_len_puppet = rand_below(afl, (temp_len << 3) - 1);
              FLIP_BIT(out_buf, temp_len_puppet);
              FLIP_BIT(out_buf, temp_len_puppet + 1);
              MOpt_globals.cycles_v2[STAGE_FLIP2]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT2");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 2:
              if (temp_len < 2) { break; }
              temp_len_puppet = rand_below(afl, (temp_len << 3) - 3);
              FLIP_BIT(out_buf, temp_len_puppet);
              FLIP_BIT(out_buf, temp_len_puppet + 1);
              FLIP_BIT(out_buf, temp_len_puppet + 2);
              FLIP_BIT(out_buf, temp_len_puppet + 3);
              MOpt_globals.cycles_v2[STAGE_FLIP4]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT4");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 3:
              if (temp_len < 4) { break; }
              out_buf[rand_below(afl, temp_len)] ^= 0xFF;
              MOpt_globals.cycles_v2[STAGE_FLIP8]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT8");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 4:
              if (temp_len < 8) { break; }
              *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) ^= 0xFFFF;
              MOpt_globals.cycles_v2[STAGE_FLIP16]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT16");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 5:
              if (temp_len < 8) { break; }
              *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) ^= 0xFFFFFFFF;
              MOpt_globals.cycles_v2[STAGE_FLIP32]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP_BIT32");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 6:
              out_buf[rand_below(afl, temp_len)] -=
                  1 + rand_below(afl, ARITH_MAX);
              out_buf[rand_below(afl, temp_len)] +=
                  1 + rand_below(afl, ARITH_MAX);
              MOpt_globals.cycles_v2[STAGE_ARITH8]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 7:
              /* Randomly subtract from word, random endian. */
              if (temp_len < 8) { break; }
              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 1);
                *(u16 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16-%u", pos);
                strcat(afl->mutation, afl->m_tmp);
#endif

              } else {

                u32 pos = rand_below(afl, temp_len - 1);
                u16 num = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16BE-%u-%u",
                         pos, num);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u16 *)(out_buf + pos) =
                    SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

              }

              /* Randomly add to word, random endian. */
              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 1);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16+-%u", pos);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u16 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 1);
                u16 num = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16BE+-%u-%u",
                         pos, num);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u16 *)(out_buf + pos) =
                    SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

              }

              MOpt_globals.cycles_v2[STAGE_ARITH16]++;
              break;

            case 8:
              /* Randomly subtract from dword, random endian. */
              if (temp_len < 8) { break; }
              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 3);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32_-%u", pos);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 3);
                u32 num = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32BE_-%u-%u",
                         pos, num);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + pos) =
                    SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

              }

              /* Randomly add to dword, random endian. */
              // if (temp_len < 4) break;
              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 3);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32+-%u", pos);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 3);
                u32 num = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32BE+-%u-%u",
                         pos, num);
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + pos) =
                    SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

              }

              MOpt_globals.cycles_v2[STAGE_ARITH32]++;
              break;

            case 9:
              /* Set byte to interesting value. */
              if (temp_len < 4) { break; }
              out_buf[rand_below(afl, temp_len)] =
                  interesting_8[rand_below(afl, sizeof(interesting_8))];
              MOpt_globals.cycles_v2[STAGE_INTEREST8]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING8");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 10:
              /* Set word to interesting value, randomly choosing endian. */
              if (temp_len < 8) { break; }
              if (rand_below(afl, 2)) {

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16");
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
                    interesting_16[rand_below(afl,
                                              sizeof(interesting_16) >> 1)];

              } else {

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16BE");
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
                    SWAP16(interesting_16[rand_below(
                        afl, sizeof(interesting_16) >> 1)]);

              }

              MOpt_globals.cycles_v2[STAGE_INTEREST16]++;
              break;

            case 11:
              /* Set dword to interesting value, randomly choosing endian. */

              if (temp_len < 8) { break; }

              if (rand_below(afl, 2)) {

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32");
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
                    interesting_32[rand_below(afl,
                                              sizeof(interesting_32) >> 2)];

              } else {

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32BE");
                strcat(afl->mutation, afl->m_tmp);
#endif
                *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
                    SWAP32(interesting_32[rand_below(
                        afl, sizeof(interesting_32) >> 2)]);

              }

              MOpt_globals.cycles_v2[STAGE_INTEREST32]++;
              break;

            case 12:

              /* Just set a random byte to a random value. Because,
                 why not. We use XOR with 1-255 to eliminate the
                 possibility of a no-op. */

              out_buf[rand_below(afl, temp_len)] ^= 1 + rand_below(afl, 255);
              MOpt_globals.cycles_v2[STAGE_RANDOMBYTE]++;
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " RAND8");
              strcat(afl->mutation, afl->m_tmp);
#endif
              break;

            case 13: {

              /* Delete bytes. We're making this a bit more likely
                 than insertion (the next option) in hopes of keeping
                 files reasonably small. */

              u32 del_from, del_len;

              if (temp_len < 2) { break; }

              /* Don't delete too much. */

              del_len = choose_block_len(afl, temp_len - 1);

              del_from = rand_below(afl, temp_len - del_len + 1);

#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " DEL-%u%u", del_from,
                       del_len);
              strcat(afl->mutation, afl->m_tmp);
#endif
              memmove(out_buf + del_from, out_buf + del_from + del_len,
                      temp_len - del_from - del_len);

              temp_len -= del_len;
              MOpt_globals.cycles_v2[STAGE_DELETEBYTE]++;
              break;

            }

            case 14:

              if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

                /* Clone bytes (75%) or insert a block of constant bytes (25%).
                 */

                u8  actually_clone = rand_below(afl, 4);
                u32 clone_from, clone_to, clone_len;
                u8 *new_buf;

                if (likely(actually_clone)) {

                  clone_len = choose_block_len(afl, temp_len);
                  clone_from = rand_below(afl, temp_len - clone_len + 1);

                } else {

                  clone_len = choose_block_len(afl, HAVOC_BLK_XL);
                  clone_from = 0;

                }

                clone_to = rand_below(afl, temp_len);

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE_%s-%u-%u-%u",
                         actually_clone ? "clone" : "insert", clone_from,
                         clone_to, clone_len);
                strcat(afl->mutation, afl->m_tmp);
#endif
                new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch),
                                      temp_len + clone_len);
                if (unlikely(!new_buf)) { PFATAL("alloc"); }

                /* Head */

                memcpy(new_buf, out_buf, clone_to);

                /* Inserted part */

                if (actually_clone) {

                  memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);

                } else {

                  memset(new_buf + clone_to,
                         rand_below(afl, 2)
                             ? rand_below(afl, 256)
                             : out_buf[rand_below(afl, temp_len)],
                         clone_len);

                }

                /* Tail */
                memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                       temp_len - clone_to);

                out_buf = new_buf;
                afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
                temp_len += clone_len;
                MOpt_globals.cycles_v2[STAGE_Clone75]++;

              }

              break;

            case 15: {

              /* Overwrite bytes with a randomly selected chunk (75%) or fixed
                 bytes (25%). */

              u32 copy_from, copy_to, copy_len;

              if (temp_len < 2) { break; }

              copy_len = choose_block_len(afl, temp_len - 1);

              copy_from = rand_below(afl, temp_len - copy_len + 1);
              copy_to = rand_below(afl, temp_len - copy_len + 1);

              if (likely(rand_below(afl, 4))) {

                if (likely(copy_from != copy_to)) {

#ifdef INTROSPECTION
                  snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                           " OVERWRITE_COPY-%u-%u-%u", copy_from, copy_to,
                           copy_len);
                  strcat(afl->mutation, afl->m_tmp);
#endif
                  memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

                }

              } else {

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                         " OVERWRITE_FIXED-%u-%u-%u", copy_from, copy_to,
                         copy_len);
                strcat(afl->mutation, afl->m_tmp);
#endif
                memset(out_buf + copy_to,
                       rand_below(afl, 2) ? rand_below(afl, 256)
                                          : out_buf[rand_below(afl, temp_len)],
                       copy_len);

              }

              MOpt_globals.cycles_v2[STAGE_OverWrite75]++;
              break;

            }                                                    /* case 15 */

              /* Values 16 and 17 can be selected only if there are any extras
                 present in the dictionaries. */

            case 16: {

              /* Overwrite bytes with an extra. */

              if (!afl->extras_cnt ||
                  (afl->a_extras_cnt && rand_below(afl, 2))) {

                /* No user-specified extras or odds in our favor. Let's use an
                  auto-detected one. */

                u32 use_extra = rand_below(afl, afl->a_extras_cnt);
                u32 extra_len = afl->a_extras[use_extra].len;

                if (extra_len > (u32)temp_len) break;

                u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                         " AUTO_EXTRA_OVERWRITE-%u-%u", insert_at, extra_len);
                strcat(afl->mutation, afl->m_tmp);
#endif
                memcpy(out_buf + insert_at, afl->a_extras[use_extra].data,
                       extra_len);

              } else {

                /* No auto extras or odds in our favor. Use the dictionary. */

                u32 use_extra = rand_below(afl, afl->extras_cnt);
                u32 extra_len = afl->extras[use_extra].len;

                if (extra_len > (u32)temp_len) break;

                u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                         " EXTRA_OVERWRITE-%u-%u", insert_at, extra_len);
                strcat(afl->mutation, afl->m_tmp);
#endif
                memcpy(out_buf + insert_at, afl->extras[use_extra].data,
                       extra_len);

              }

              MOpt_globals.cycles_v2[STAGE_OverWriteExtra]++;

              break;

            }

              /* Insert an extra. */

            case 17: {

              u32 use_extra, extra_len,
                  insert_at = rand_below(afl, temp_len + 1);
              u8 *ptr;

              /* Insert an extra. Do the same dice-rolling stuff as for the
                previous case. */

              if (!afl->extras_cnt ||
                  (afl->a_extras_cnt && rand_below(afl, 2))) {

                use_extra = rand_below(afl, afl->a_extras_cnt);
                extra_len = afl->a_extras[use_extra].len;
                ptr = afl->a_extras[use_extra].data;
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                         " AUTO_EXTRA_INSERT-%u-%u", insert_at, extra_len);
                strcat(afl->mutation, afl->m_tmp);
#endif

              } else {

                use_extra = rand_below(afl, afl->extras_cnt);
                extra_len = afl->extras[use_extra].len;
                ptr = afl->extras[use_extra].data;
#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp), " EXTRA_INSERT-%u-%u",
                         insert_at, extra_len);
                strcat(afl->mutation, afl->m_tmp);
#endif

              }

              if (temp_len + extra_len >= MAX_FILE) break;

              out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len + extra_len);
              if (unlikely(!out_buf)) { PFATAL("alloc"); }

              /* Tail */
              memmove(out_buf + insert_at + extra_len, out_buf + insert_at,
                      temp_len - insert_at);

              /* Inserted part */
              memcpy(out_buf + insert_at, ptr, extra_len);

              temp_len += extra_len;
              MOpt_globals.cycles_v2[STAGE_InsertExtra]++;
              break;

            }

            default: {

              if (unlikely(afl->ready_for_splicing_count < 2)) break;

              u32 tid;
              do {

                tid = rand_below(afl, afl->queued_paths);

              } while (tid == afl->current_entry ||

                       afl->queue_buf[tid]->len < 4);

              /* Get the testcase for splicing. */
              struct queue_entry *target = afl->queue_buf[tid];
              u32                 new_len = target->len;
              u8 *                new_buf = queue_testcase_get(afl, target);

              if ((temp_len >= 2 && rand_below(afl, 2)) ||
                  temp_len + HAVOC_BLK_XL >= MAX_FILE) {

                /* overwrite mode */

                u32 copy_from, copy_to, copy_len;

                copy_len = choose_block_len(afl, new_len - 1);
                if (copy_len > temp_len) copy_len = temp_len;

                copy_from = rand_below(afl, new_len - copy_len + 1);
                copy_to = rand_below(afl, temp_len - copy_len + 1);

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                         " SPLICE_OVERWRITE-%u-%u-%u-%s", copy_from, copy_to,
                         copy_len, target->fname);
                strcat(afl->mutation, afl->m_tmp);
#endif
                memmove(out_buf + copy_to, new_buf + copy_from, copy_len);

              } else {

                /* insert mode */

                u32 clone_from, clone_to, clone_len;

                clone_len = choose_block_len(afl, new_len);
                clone_from = rand_below(afl, new_len - clone_len + 1);
                clone_to = rand_below(afl, temp_len + 1);

                u8 *temp_buf = afl_realloc(AFL_BUF_PARAM(out_scratch),
                                           temp_len + clone_len + 1);
                if (unlikely(!temp_buf)) { PFATAL("alloc"); }

#ifdef INTROSPECTION
                snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                         " SPLICE_INSERT-%u-%u-%u-%s", clone_from, clone_to,
                         clone_len, target->fname);
                strcat(afl->mutation, afl->m_tmp);
#endif
                /* Head */

                memcpy(temp_buf, out_buf, clone_to);

                /* Inserted part */

                memcpy(temp_buf + clone_to, new_buf + clone_from, clone_len);

                /* Tail */
                memcpy(temp_buf + clone_to + clone_len, out_buf + clone_to,
                       temp_len - clone_to);

                out_buf = temp_buf;
                afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
                temp_len += clone_len;

              }

              MOpt_globals.cycles_v2[STAGE_Splice]++;
              break;

            }  // end of default:

          }                                    /* switch select_algorithm() */

        }                                      /* for i=0; i < use_stacking */

        ++*MOpt_globals.pTime;

        u64 temp_total_found = afl->queued_paths + afl->unique_crashes;

        if (common_fuzz_stuff(afl, out_buf, temp_len)) {

          goto abandon_entry_puppet;

        }

        /* out_buf might have been mangled a bit, so let's restore it to its
           original size and shape. */

        out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
        if (unlikely(!out_buf)) { PFATAL("alloc"); }
        temp_len = len;
        memcpy(out_buf, in_buf, len);

        /* If we're finding new stuff, let's run for a bit longer, limits
           permitting. */

        if (afl->queued_paths != havoc_queued) {

          if (perf_score <= afl->havoc_max_mult * 100) {

            afl->stage_max *= 2;
            perf_score *= 2;

          }

          havoc_queued = afl->queued_paths;

        }

        if (unlikely(afl->queued_paths + afl->unique_crashes >
                     temp_total_found)) {

          u64 temp_temp_puppet =
              afl->queued_paths + afl->unique_crashes - temp_total_found;
          afl->total_puppet_find = afl->total_puppet_find + temp_temp_puppet;

          if (MOpt_globals.is_pilot_mode) {

            for (i = 0; i < operator_num; ++i) {

              if (MOpt_globals.cycles_v2[i] > MOpt_globals.cycles_v3[i]) {

                MOpt_globals.finds_v2[i] += temp_temp_puppet;

              }

            }

          } else {

            for (i = 0; i < operator_num; i++) {

              if (afl->core_operator_cycles_puppet_v2[i] >
                  afl->core_operator_cycles_puppet_v3[i])

                afl->core_operator_finds_puppet_v2[i] += temp_temp_puppet;

            }

          }

        }                                                             /* if */

      } /* for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max;

           ++afl->stage_cur) { */

      new_hit_cnt = afl->queued_paths + afl->unique_crashes;

      if (MOpt_globals.is_pilot_mode) {

        if (!splice_cycle) {

          afl->stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
          afl->stage_cycles[STAGE_HAVOC] += afl->stage_max;

        } else {

          afl->stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
          afl->stage_cycles[STAGE_SPLICE] += afl->stage_max;

        }

      }

#ifndef IGNORE_FINDS

      /************
       * SPLICING *
       ************/

    retry_splicing_puppet:

      if (afl->use_splicing &&
          splice_cycle++ < (u32)afl->SPLICE_CYCLES_puppet &&
          afl->ready_for_splicing_count > 1 && afl->queue_cur->len >= 4) {

        struct queue_entry *target;
        u32                 tid, split_at;
        u8 *                new_buf;
        s32                 f_diff, l_diff;

        /* First of all, if we've modified in_buf for havoc, let's clean that
           up... */

        if (in_buf != orig_in) {

          in_buf = orig_in;
          len = afl->queue_cur->len;

        }

        /* Pick a random queue entry and seek to it. Don't splice with yourself.
         */

        do {

          tid = rand_below(afl, afl->queued_paths);

        } while (tid == afl->current_entry || afl->queue_buf[tid]->len < 4);

        afl->splicing_with = tid;
        target = afl->queue_buf[tid];

        /* Read the testcase into a new buffer. */
        new_buf = queue_testcase_get(afl, target);

        /* Find a suitable splicin g location, somewhere between the first and
           the last differing byte. Bail out if the difference is just a single
           byte or so. */

        locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

        if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {

          goto retry_splicing_puppet;

        }

        /* Split somewhere between the first and last differing byte. */

        split_at = f_diff + rand_below(afl, l_diff - f_diff);

        /* Do the thing. */

        len = target->len;
        afl->in_scratch_buf = afl_realloc(AFL_BUF_PARAM(in_scratch), len);
        memcpy(afl->in_scratch_buf, in_buf, split_at);
        memcpy(afl->in_scratch_buf + split_at, new_buf, len - split_at);
        in_buf = afl->in_scratch_buf;
        afl_swap_bufs(AFL_BUF_PARAM(in), AFL_BUF_PARAM(in_scratch));

        out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
        if (unlikely(!out_buf)) { PFATAL("alloc"); }
        memcpy(out_buf, in_buf, len);

        goto havoc_stage_puppet;

      }                                                  /* if splice_cycle */

#endif                                                     /* !IGNORE_FINDS */

      ret_val = 0;

    abandon_entry:
    abandon_entry_puppet:

      if ((s64)splice_cycle >= afl->SPLICE_CYCLES_puppet) {

        afl->SPLICE_CYCLES_puppet =
            (rand_below(
                 afl, SPLICE_CYCLES_puppet_up - SPLICE_CYCLES_puppet_low + 1) +
             SPLICE_CYCLES_puppet_low);

      }

      afl->splicing_with = -1;

      /* Update afl->pending_not_fuzzed count if we made it through the
         calibration cycle and have not seen this entry before. */
      /*
        // TODO FIXME: I think we need this plus need an -L -1 check
        if (!afl->stop_soon && !afl->queue_cur->cal_failed &&
            (afl->queue_cur->was_fuzzed == 0 || afl->queue_cur->fuzz_level == 0)
        && !afl->queue_cur->disabled) {

          if (!afl->queue_cur->was_fuzzed) {

            --afl->pending_not_fuzzed;
            afl->queue_cur->was_fuzzed = 1;
            if (afl->queue_cur->favored) { --afl->pending_favored; }

          }

        }

      */

      orig_in = NULL;

      if (afl->key_puppet == 1) {

        if (unlikely(
                afl->queued_paths + afl->unique_crashes >
                ((afl->queued_paths + afl->unique_crashes) * limit_time_bound +
                 afl->orig_hit_cnt_puppet))) {

          afl->key_puppet = 0;
          afl->orig_hit_cnt_puppet = 0;
          afl->last_limit_time_start = 0;

        }

      }

      if (unlikely(*MOpt_globals.pTime > MOpt_globals.period)) {

        afl->total_pacemaker_time += *MOpt_globals.pTime;
        *MOpt_globals.pTime = 0;
        new_hit_cnt = afl->queued_paths + afl->unique_crashes;

        if (MOpt_globals.is_pilot_mode) {

          afl->swarm_fitness[afl->swarm_now] =
              (double)(afl->total_puppet_find - afl->temp_puppet_find) /
              ((double)(afl->tmp_pilot_time) / afl->period_pilot_tmp);

        }

        afl->temp_puppet_find = afl->total_puppet_find;
        u64 temp_stage_finds_puppet = 0;
        for (i = 0; i < operator_num; ++i) {

          if (MOpt_globals.is_pilot_mode) {

            double temp_eff = 0.0;

            if (MOpt_globals.cycles_v2[i] > MOpt_globals.cycles[i]) {

              temp_eff =
                  (double)(MOpt_globals.finds_v2[i] - MOpt_globals.finds[i]) /
                  (double)(MOpt_globals.cycles_v2[i] - MOpt_globals.cycles[i]);

            }

            if (afl->eff_best[afl->swarm_now][i] < temp_eff) {

              afl->eff_best[afl->swarm_now][i] = temp_eff;
              afl->L_best[afl->swarm_now][i] = afl->x_now[afl->swarm_now][i];

            }

          }

          MOpt_globals.finds[i] = MOpt_globals.finds_v2[i];
          MOpt_globals.cycles[i] = MOpt_globals.cycles_v2[i];
          temp_stage_finds_puppet += MOpt_globals.finds[i];

        }                                    /* for i = 0; i < operator_num */

        if (MOpt_globals.is_pilot_mode) {

          afl->swarm_now = afl->swarm_now + 1;
          if (afl->swarm_now == swarm_num) {

            afl->key_module = 1;
            for (i = 0; i < operator_num; ++i) {

              afl->core_operator_cycles_puppet_v2[i] =
                  afl->core_operator_cycles_puppet[i];
              afl->core_operator_cycles_puppet_v3[i] =
                  afl->core_operator_cycles_puppet[i];
              afl->core_operator_finds_puppet_v2[i] =
                  afl->core_operator_finds_puppet[i];

            }

            double swarm_eff = 0.0;
            afl->swarm_now = 0;
            for (i = 0; i < swarm_num; ++i) {

              if (afl->swarm_fitness[i] > swarm_eff) {

                swarm_eff = afl->swarm_fitness[i];
                afl->swarm_now = i;

              }

            }

            if (afl->swarm_now < 0 || afl->swarm_now > swarm_num - 1) {

              PFATAL("swarm_now error number  %d", afl->swarm_now);

            }

          }                               /* if afl->swarm_now == swarm_num */

          /* adjust pointers dependent on 'afl->swarm_now' */
          afl->mopt_globals_pilot.finds =
              afl->stage_finds_puppet[afl->swarm_now];
          afl->mopt_globals_pilot.finds_v2 =
              afl->stage_finds_puppet_v2[afl->swarm_now];
          afl->mopt_globals_pilot.cycles =
              afl->stage_cycles_puppet[afl->swarm_now];
          afl->mopt_globals_pilot.cycles_v2 =
              afl->stage_cycles_puppet_v2[afl->swarm_now];
          afl->mopt_globals_pilot.cycles_v3 =
              afl->stage_cycles_puppet_v3[afl->swarm_now];

        } else {

          for (i = 0; i < operator_num; i++) {

            afl->core_operator_finds_puppet[i] =
                afl->core_operator_finds_puppet_v2[i];
            afl->core_operator_cycles_puppet[i] =
                afl->core_operator_cycles_puppet_v2[i];
            temp_stage_finds_puppet += afl->core_operator_finds_puppet[i];

          }

          afl->key_module = 2;

          afl->old_hit_count = new_hit_cnt;

        }                                                  /* if pilot_mode */

      }         /* if (unlikely(*MOpt_globals.pTime > MOpt_globals.period)) */

    }                                                              /* block */

  }                                                                /* block */

  return ret_val;

}

#undef FLIP_BIT

u8 core_fuzzing(afl_state_t *afl) {

  return mopt_common_fuzzing(afl, afl->mopt_globals_core);

}

u8 pilot_fuzzing(afl_state_t *afl) {

  return mopt_common_fuzzing(afl, afl->mopt_globals_pilot);

}

void pso_updating(afl_state_t *afl) {

  afl->g_now++;
  if (afl->g_now > afl->g_max) { afl->g_now = 0; }
  afl->w_now =
      (afl->w_init - afl->w_end) * (afl->g_max - afl->g_now) / (afl->g_max) +
      afl->w_end;
  int tmp_swarm, i, j;
  u64 temp_operator_finds_puppet = 0;
  for (i = 0; i < operator_num; ++i) {

    afl->operator_finds_puppet[i] = afl->core_operator_finds_puppet[i];

    for (j = 0; j < swarm_num; ++j) {

      afl->operator_finds_puppet[i] =
          afl->operator_finds_puppet[i] + afl->stage_finds_puppet[j][i];

    }

    temp_operator_finds_puppet =
        temp_operator_finds_puppet + afl->operator_finds_puppet[i];

  }

  for (i = 0; i < operator_num; ++i) {

    if (afl->operator_finds_puppet[i]) {

      afl->G_best[i] = (double)((double)(afl->operator_finds_puppet[i]) /
                                (double)(temp_operator_finds_puppet));

    }

  }

  for (tmp_swarm = 0; tmp_swarm < swarm_num; ++tmp_swarm) {

    double x_temp = 0.0;
    for (i = 0; i < operator_num; ++i) {

      afl->probability_now[tmp_swarm][i] = 0.0;
      afl->v_now[tmp_swarm][i] =
          afl->w_now * afl->v_now[tmp_swarm][i] +
          RAND_C * (afl->L_best[tmp_swarm][i] - afl->x_now[tmp_swarm][i]) +
          RAND_C * (afl->G_best[i] - afl->x_now[tmp_swarm][i]);
      afl->x_now[tmp_swarm][i] += afl->v_now[tmp_swarm][i];
      if (afl->x_now[tmp_swarm][i] > v_max) {

        afl->x_now[tmp_swarm][i] = v_max;

      } else if (afl->x_now[tmp_swarm][i] < v_min) {

        afl->x_now[tmp_swarm][i] = v_min;

      }

      x_temp += afl->x_now[tmp_swarm][i];

    }

    for (i = 0; i < operator_num; ++i) {

      afl->x_now[tmp_swarm][i] = afl->x_now[tmp_swarm][i] / x_temp;
      if (likely(i != 0)) {

        afl->probability_now[tmp_swarm][i] =
            afl->probability_now[tmp_swarm][i - 1] + afl->x_now[tmp_swarm][i];

      } else {

        afl->probability_now[tmp_swarm][i] = afl->x_now[tmp_swarm][i];

      }

    }

    if (afl->probability_now[tmp_swarm][operator_num - 1] < 0.99 ||
        afl->probability_now[tmp_swarm][operator_num - 1] > 1.01) {

      FATAL("ERROR probability");

    }

  }

  afl->swarm_now = 0;
  afl->key_module = 0;

}

/* larger change for MOpt implementation: the original fuzz_one was renamed
   to fuzz_one_original. All documentation references to fuzz_one therefore
   mean fuzz_one_original */

u8 fuzz_one(afl_state_t *afl) {

  int key_val_lv_1 = 0, key_val_lv_2 = 0;

#ifdef _AFL_DOCUMENT_MUTATIONS

  u8 path_buf[PATH_MAX];
  if (afl->do_document == 0) {

    snprintf(path_buf, PATH_MAX, "%s/mutations", afl->out_dir);
    afl->do_document = mkdir(path_buf, 0700);  // if it exists we do not care
    afl->do_document = 1;

  } else {

    afl->do_document = 2;
    afl->stop_soon = 2;

  }

#endif

  // if limit_time_sig == -1 then both are run after each other

  if (afl->limit_time_sig <= 0) { key_val_lv_1 = fuzz_one_original(afl); }

  if (afl->limit_time_sig != 0) {

    if (afl->key_module == 0) {

      key_val_lv_2 = pilot_fuzzing(afl);

    } else if (afl->key_module == 1) {

      key_val_lv_2 = core_fuzzing(afl);

    } else if (afl->key_module == 2) {

      pso_updating(afl);

    }

  }

  return (key_val_lv_1 | key_val_lv_2);

}

