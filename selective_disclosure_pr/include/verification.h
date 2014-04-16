/**
 * verification.h
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
 * Copyright (C) July 2011 - 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#ifndef __verification_H
#define __verification_H

#include "MULTOS.h"
#include "types.h"

void generate_r_tilde(void);
void generate_m_tilde(void);
void generate_mh_tilde(void);
void generate_ms_tilde(void);

void init_PRNG(void);
void reset_PRNG(void);

/**
 * Generate the corresponding mHat[i] value.
 */
void ComputeHat(void);

/**
 * Select the attributes to be disclosed.
 */
int verifySelection(Credential *credential, unsigned int selection);

#define VERIFICATION_ERROR_MASTER_SECRET -1
#define VERIFICATION_ERROR_EXPIRY -2
#define VERIFICATION_ERROR_NOT_FOUND -3
#define VERIFICATION_SELECTION_VALID 1

/**
 * Construct a proof.
 */
void constructProof(Credential *credential, unsigned char *masterSecret);

/**
 * Compute the value v' = v - e*r_A.
 */
#define crypto_compute_vPrime() \
do { \
  /* Clear the buffer, to prevent garbage messing up the computation */\
  __code(CLEARN, public.prove.buffer.data, SIZE_V - 2*SIZE_E); \
  /* Multiply e with least significant half of r_A */\
  __code(PUSHZ, SIZE_E - SIZE_R_A/2); \
  __push(BLOCKCAST(SIZE_R_A/2)(public.prove.rA + SIZE_R_A/2)); \
  __push(BLOCKCAST(SIZE_E)(credential->signature.e)); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_E); \
  __code(STORE, public.prove.buffer.data + SIZE_V - 2*SIZE_E, 2*SIZE_E); \
  /* Multiply e with most significant half of r_A */\
  __code(PUSHZ, SIZE_E - SIZE_R_A/2); \
  __push(BLOCKCAST(SIZE_R_A/2)(public.prove.rA)); \
  __push(BLOCKCAST(SIZE_E)(credential->signature.e)); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_E); \
  /* Combine the two multiplications into a single result */\
  __code(ADDN, public.prove.buffer.data, SIZE_V - SIZE_R_A/2); \
  __code(POPN, 2*SIZE_E); \
  /* Subtract from v and store the result in v' */\
  __push(BLOCKCAST(SIZE_V/2 + 1)(credential->signature.v + SIZE_V/2)); \
  __push(BLOCKCAST(SIZE_V/2 + 1)(public.prove.buffer.data + SIZE_V/2)); \
  __code(SUBN, SIZE_V/2 + 1); \
  IfCarry( \
    debugMessage("Subtraction with borrow, adding 1"); \
    __code(INCN, public.prove.buffer.data, SIZE_V/2); \
  ); \
  __code(POPN, SIZE_V/2 + 1); \
  __code(STORE, public.prove.buffer.data + SIZE_V/2, SIZE_V/2 + 1); \
  __push(BLOCKCAST(SIZE_V/2)(credential->signature.v)); \
  __push(BLOCKCAST(SIZE_V/2)(public.prove.buffer.data)); \
  __code(SUBN, SIZE_V/2); \
  __code(POPN, SIZE_V/2); \
  __code(STORE, public.prove.buffer.data, SIZE_V/2); \
} while (0)
/* Simple subtraction does not fit on the stack.
  __push(BLOCKCAST(SIZE_V)(credential->signature.v)); \
  __push(BLOCKCAST(SIZE_V)(public.prove.buffer.data)); \
  __code(SUBN, SIZE_V); \
  __code(POPN, SIZE_V); \
  __code(STORE, public.prove.buffer.data, SIZE_V); \
} while (0) */

/**
 * Compute the response value vHat = vTilde + c*v'.
 *
 * Requires vTilde to be stored in vHat.
 */
#define crypto_compute_vHat() \
do { \
  /* Multiply c with least significant part of v */\
  __code(PUSHZ, SIZE_V/2 - SIZE_H); \
  __push(BLOCKCAST(SIZE_H)(session.prove.challenge)); \
  __push(BLOCKCAST(SIZE_V/2)(public.prove.buffer.data + SIZE_V/2 + 1)); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_V/2); \
  __code(STORE, public.prove.buffer.data + SIZE_V/2 + 1, 2*(SIZE_V/2)); \
  /* Multiply c with most significant part of v */\
  __code(PUSHZ, SIZE_V/2 + 1 - SIZE_H); \
  __push(BLOCKCAST(SIZE_H)(session.prove.challenge)); \
  __push(BLOCKCAST(SIZE_V/2 + 1)(public.prove.buffer.data)); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_V/2 + 1); \
  /* Clear the buffer, to prevent garbage messing up the computation, do NOT do this earlier since it will destroy vPrime */\
  __code(CLEARN, public.prove.buffer.data, SIZE_V/2 + 1); \
  /* Combine the two multiplications into a single result */\
  __code(ADDN, public.prove.buffer.data, SIZE_V); \
  __code(POPN, SIZE_V + 1); \
  /* Add vTilde and store the result in vHat */\
  __push(BLOCKCAST(SIZE_V_)(public.prove.buffer.data + SIZE_V + SIZE_V/2 - SIZE_V_)); \
  __code(ADDN, public.prove.vHat, SIZE_V_); \
  __code(POPN, SIZE_V_); \
} while (0)

/**
 * Compute the value e' = e - 2^(l_e' - 1).
 *
 * In this case, it is just ignoring the first bytes, so nothing to do here.
 */
#define crypto_compute_ePrime()

/**
 * Compute the response value eHat = eTilde + c*e'.
 *
 * Requires eTilde to be stored in eHat.
 */
#define crypto_compute_eHat() \
do { \
  /* Multiply c with ePrime (SIZE_H since SIZE_H > SIZE_EPRIME) */\
  __code(PUSHZ, SIZE_H - SIZE_EPRIME); \
  __push(BLOCKCAST(SIZE_EPRIME)(credential->signature.e + SIZE_E - SIZE_EPRIME)); /* ePrime */\
  __push(BLOCKCAST(SIZE_H)(session.prove.challenge)); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_H); \
  /* Add eTilde and store the result in eHat */\
  __code(ADDN, public.prove.eHat, SIZE_E_); \
  /* Cleanup the stack */\
  __code(POPN, 2*SIZE_H); \
} while (0)

/**
 * Compute the response value mHat[i] = mTilde[i] + c*m[i].
 *
 * Requires mTilde[i] to be stored in mHat[i].
 *
 * @param i index of the message to be hidden.
 */
#define crypto_compute_mHat(i) \
do { \
  /* Multiply c with m */\
  __code(PUSHZ, SIZE_M_ + 2 - 2*SIZE_M); \
  __push(BLOCKCAST(SIZE_H)(session.prove.challenge)); \
  __push(BLOCKCAST(SIZE_M)(i == 0 ? masterSecret : credential->attribute[i - 1])); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_M); \
  /* Put the result address in front of the operand (for STOREI) */\
  __push(session.prove.mHatTemp); \
  __code(PUSHZ, SIZE_M_); \
  __code(ORN, SIZE_M_ + 2); \
  __code(POPN, SIZE_M_ + 2); \
  /* Add mTilde to the result of the multiplication and store in mHatTemp*/\
  __push(BLOCKCAST(SIZE_M_)(session.prove.mHatTemp)); \
  __code(ADDN, SIZE_M_); \
  __code(POPN, SIZE_M_); \
  __code(STOREI, SIZE_M_); \
} while (0)

/**
 * Determine whether an attribute is to be disclosed or not.
 *
 * @param index of the attribute.
 * @return 1 if disclosed, 0 if not.
 */
#define disclosed(index) ((session.prove.disclose >> (index)) & 0x0001)

#define multosSecureHashIV(msgLen, hashLen, hashOut, msgIn, intermediateHash, numPrevHashedBytes, numMsgRemainder, msgRemainder) \
do { \
 __push (__typechk(unsigned short, msgLen)); \
 __push (__typechk(unsigned short, hashLen)); \
 __push (__typechk(unsigned char *, hashOut)); \
 __push (__typechk(unsigned char *, msgIn)); \
 __push (__typechk(unsigned char *, intermediateHash)); \
 __push (__typechk(unsigned long *, numPrevHashedBytes)); \
 __push (__typechk(unsigned short, *numMsgRemainder)); \
 __push (__typechk(unsigned short, *msgRemainder)); \
 __code (PRIM, PRIM_SECURE_HASH_IV); \
 __code(STORE, msgRemainder, 2); \
 __code(STORE, numMsgRemainder, 2); \
} while (0)

#define crypto_compute_r(i) \
do { \
  /* Multiply c with m */\
  __code(PUSHZ, SIZE_M_ + 2 - 2*SIZE_M); \
  __push(BLOCKCAST(SIZE_H)(session.prove.challenge)); \
  __push(BLOCKCAST(SIZE_M)(r)); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_M); \
  /* Put the result address in front of the operand (for STOREI) */\
  __push(session.prove.mHatTemp); \
  __code(PUSHZ, SIZE_M_); \
  __code(ORN, SIZE_M_ + 2); \
  __code(POPN, SIZE_M_ + 2); \
  /* Add mTilde to the result of the multiplication and store in mHatTemp*/\
  __push(BLOCKCAST(SIZE_M_)(session.prove.mHatTemp)); \
  __code(ADDN, SIZE_M_); \
  __code(POPN, SIZE_M_); \
  __code(STOREI, SIZE_M_); \
} while (0)

#define crypto_compute_h(i) \
do { \
  /* Multiply c with m */\
  __code(PUSHZ, SIZE_M_ + 2 - 2*SIZE_M); \
  __push(BLOCKCAST(SIZE_H)(session.prove.challenge)); \
  __push(BLOCKCAST(SIZE_M)(h)); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_M); \
  /* Put the result address in front of the operand (for STOREI) */\
  __push(session.prove.mHatTemp); \
  __code(PUSHZ, SIZE_M_); \
  __code(ORN, SIZE_M_ + 2); \
  __code(POPN, SIZE_M_ + 2); \
  /* Add mTilde to the result of the multiplication and store in mHatTemp*/\
  __push(BLOCKCAST(SIZE_M_)(session.prove.mHatTemp)); \
  __code(ADDN, SIZE_M_); \
  __code(POPN, SIZE_M_); \
  __code(STOREI, SIZE_M_); \
} while (0)



#endif // __verification_H
