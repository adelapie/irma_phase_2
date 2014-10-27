/**
 * gcd.h
 *
 * This file is part of IRMAcard.
 *
 * IRMAcard is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * IRMAcard is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IRMAcard. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) September 2011 - 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#ifndef __gcd_H
#define __gcd_H

#define DIGIT_BITS 30
#define DIGIT_BITS_LONG 30*2

#define GCD_MAX_SIZE_2_BITS		32
#define GCD_MAX_SIZE_2_BITS_LONG	65

#define N_BITS_0 GCD_MAX_SIZE_2_BITS - 4 - DIGIT_BITS
#define N_BITS_1 GCD_MAX_SIZE_2_BITS - 3 - DIGIT_BITS
#define N_BITS_2 GCD_MAX_SIZE_2_BITS - 2 - DIGIT_BITS
#define N_BITS_3 GCD_MAX_SIZE_2_BITS - 2 - DIGIT_BITS
#define N_BITS_4 GCD_MAX_SIZE_2_BITS - 1 - DIGIT_BITS
#define N_BITS_5 GCD_MAX_SIZE_2_BITS - 1 - DIGIT_BITS
#define N_BITS_6 GCD_MAX_SIZE_2_BITS - 1 - DIGIT_BITS
#define N_BITS_7 GCD_MAX_SIZE_2_BITS - 1 - DIGIT_BITS
#define N_BITS_8 GCD_MAX_SIZE_2_BITS - 0 - DIGIT_BITS
#define N_BITS_9 GCD_MAX_SIZE_2_BITS - 0 - DIGIT_BITS
#define N_BITS_A GCD_MAX_SIZE_2_BITS - 0 - DIGIT_BITS
#define N_BITS_B GCD_MAX_SIZE_2_BITS - 0 - DIGIT_BITS
#define N_BITS_C GCD_MAX_SIZE_2_BITS - 0 - DIGIT_BITS
#define N_BITS_D GCD_MAX_SIZE_2_BITS - 0 - DIGIT_BITS
#define N_BITS_E GCD_MAX_SIZE_2_BITS - 0 - DIGIT_BITS
#define N_BITS_F GCD_MAX_SIZE_2_BITS - 0 - DIGIT_BITS

#define N_BITS_0_LONG GCD_MAX_SIZE_2_BITS_LONG - 4 - DIGIT_BITS_LONG
#define N_BITS_1_LONG GCD_MAX_SIZE_2_BITS_LONG - 3 - DIGIT_BITS_LONG
#define N_BITS_2_LONG GCD_MAX_SIZE_2_BITS_LONG - 2 - DIGIT_BITS_LONG
#define N_BITS_3_LONG GCD_MAX_SIZE_2_BITS_LONG - 2 - DIGIT_BITS_LONG
#define N_BITS_4_LONG GCD_MAX_SIZE_2_BITS_LONG - 1 - DIGIT_BITS_LONG
#define N_BITS_5_LONG GCD_MAX_SIZE_2_BITS_LONG - 1 - DIGIT_BITS_LONG
#define N_BITS_6_LONG GCD_MAX_SIZE_2_BITS_LONG - 1 - DIGIT_BITS_LONG
#define N_BITS_7_LONG GCD_MAX_SIZE_2_BITS_LONG - 1 - DIGIT_BITS_LONG
#define N_BITS_8_LONG GCD_MAX_SIZE_2_BITS_LONG - 0 - DIGIT_BITS_LONG
#define N_BITS_9_LONG GCD_MAX_SIZE_2_BITS_LONG - 0 - DIGIT_BITS_LONG
#define N_BITS_A_LONG GCD_MAX_SIZE_2_BITS_LONG - 0 - DIGIT_BITS_LONG
#define N_BITS_B_LONG GCD_MAX_SIZE_2_BITS_LONG - 0 - DIGIT_BITS_LONG
#define N_BITS_C_LONG GCD_MAX_SIZE_2_BITS_LONG - 0 - DIGIT_BITS_LONG
#define N_BITS_D_LONG GCD_MAX_SIZE_2_BITS_LONG - 0 - DIGIT_BITS_LONG
#define N_BITS_E_LONG GCD_MAX_SIZE_2_BITS_LONG - 0 - DIGIT_BITS_LONG
#define N_BITS_F_LONG GCD_MAX_SIZE_2_BITS_LONG - 0 - DIGIT_BITS_LONG

#define GCD_MAX_SIZE 9
#define GCD_MAX_SIZE_2 4

#define BASE_LEHMER 0x8000

#define EQUAL	0x01
#define LE	0x08
#define BE	0x00


#include "types.h"

void gcd_euclid(unsigned char *a, unsigned char *b, unsigned char *t);

extern unsigned char flag_1; // C
extern unsigned char flag_2; // Z

#define IfSmaller(action) \
do { \
  __code(PRIM, PRIM_LOAD_CCR); \
  __code(PRIM, PRIM_BIT_MANIPULATE_BYTE, (1<<7 | 3), (1<<3)); \
  __code(PRIM, PRIM_SHIFT_RIGHT, 1, 3); \
  __code(STORE, &flag_1, 1); \
  __code(PRIM, PRIM_LOAD_CCR); \
  __code(PRIM, PRIM_BIT_MANIPULATE_BYTE, (1<<7 | 3), (1<<0)); \
  __code(STORE, &flag_2, 1); \
  if (flag_1 = 0x01 && flag_2 == 0x00) { action; } \
} while (0)
                      
#endif // __gcd_H
