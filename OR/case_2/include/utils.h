/**
 * utils.h
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

#ifndef __utils_H
#define __utils_H

#include "types.h"

/**
 * Compute a cryptographic hash of the given input values
 * 
 * @param list of values to be included in the hash
 * @param length of the values list
 * @param result of the hashing operation
 * @param buffer which can be used for temporary storage
 * @param size of the buffer
 */
void ComputeHash(ValueArray list, unsigned int length, ByteArray result,
                         ByteArray buffer, unsigned int size);

/**
 * Compute the helper value S' = S^(2_l) where l = SIZE_S_EXPONENT*8
 * 
 * This value is required for exponentiations with base S and an 
 * exponent which is larger than SIZE_N bytes.
 */
void ComputeS_(Credential *credential, unsigned char *buffer);

/**
 * Compute the modular exponentiation: result = S^exponent mod n
 * 
 * This function will use the helper value S' to compute exponentiations 
 * with exponents larger than SIZE_N bytes.
 * 
 * @param size of the exponent
 * @param exponent the power to which the base S should be raised
 * @param result of the computation
 */
void ModExpSpecial(Credential *credential, int size, ByteArray exponent, ByteArray result, ByteArray buffer);

/**
 * Clear size bytes from a bytearray
 *
 * @param size the amount of bytes to clear
 * @param buffer to be cleared
 */
void ClearBytes(int size, void *buffer);

/**
 * Clear the current credential.
 */
void ClearCredential(Credential *credential);

/**
 * Clear the current session.
 */
//void ClearSession(void);

#define multosBlockMultiply(blockLength, block1, block2, result) \
do \
{ \
  __push (BLOCKCAST(blockLength)(__typechk(unsigned char *, block1))); \
  __push (BLOCKCAST(blockLength)(__typechk(unsigned char *, block2))); \
  __code (PRIM, PRIM_MULTIPLY, blockLength); \
  __code (STORE, __typechk(unsigned char *, result), blockLength); \
} while (0)

#define multosBlockMultiplyExtended(blockLength, block1, block2, result) \
do \
{ \
  __push (BLOCKCAST(blockLength)(__typechk(unsigned char *, block1))); \
  __push (BLOCKCAST(blockLength)(__typechk(unsigned char *, block2))); \
  __code (PRIM, PRIM_MULTIPLY, blockLength); \
  __code (STORE, __typechk(unsigned char *, result), blockLength*2); \
} while (0)

#define r_prima_op_1(block1, block2, result) \
do \
{ \
  __push (BLOCKCAST(1)(__typechk(unsigned char *, block1))); \
  __push (BLOCKCAST(SIZE_M)(__typechk(unsigned char *, block2))); \
  __code (PRIM, PRIM_MULTIPLY, SIZE_M); \
  __code (STORE, __typechk(unsigned char *, result), SIZE_M); \
} while (0)

#define r_minus(block1, block2, result) \
do \
{ \
  __push (BLOCKCAST(1)(__typechk(unsigned char *, block1))); \
  __push (BLOCKCAST(1)(__typechk(unsigned char *, block2))); \
  __code (PRIM, PRIM_MULTIPLY, 1); \
  __code (STORE, __typechk(unsigned char *, result), 1 + 1); \
} while (0)

#define __BINARY_OPN(N, OP, RES, OP1, OP2) \
do \
{  \
  __push (BLOCKCAST(N)(__typechk(unsigned char *, OP1))); \
  __push (BLOCKCAST(N)(__typechk(unsigned char *, OP2))); \
  __code (OP, N);  \
  __code (POPN, N);  \
  __code (STORE, __typechk(unsigned char *, RES), N); \
} while (0)


#define multosBlockAdd(blockLength, block1, block2, result) \
    __BINARY_OPN (blockLength, ADDN, result, block1, block2)                      

#endif // __utils_H
