/**
 * verification.c
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
 * Copyright (C) July 2011 - 2014.
 *   Antonio de la Piedra <a.delapiedra@cs.ru.nl>, Radboud University Nijmegen.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#include "verification.h"

#include "debug.h"
#include "math.h"
#include "memory.h"
#include "random.h"
#include "sizes.h"
#include "types.h"
#include "utils.h"

#include "AES.h"

extern PublicData public;
extern SessionData session;
extern unsigned char r[SIZE_M];
extern Number rev_attr_1;

/********************************************************************/
/* Proving functions                                                */
/********************************************************************/

void init_PRNG(void) {
  unsigned char PRNG_output[SIZE_H + 4]; // 49 52 4D 41 (IRMA)
  RandomBits(PRNG_output, LENGTH_H);
  
  PRNG_output[SIZE_H] 		= 0x49;
  PRNG_output[SIZE_H + 1]	= 0x52;
  PRNG_output[SIZE_H + 2]	= 0x4D;
  PRNG_output[SIZE_H + 3]	= 41;
  
  SHA(SHA_256, session.prove.aesKey, SIZE_H + 4, PRNG_output);
  
  session.prove.ctrBlock = 0x00; 
}
 
void reset_PRNG(void) {
  session.prove.ctrBlock = 0x00; 
}

void ComputeHat(void) {

  AESblock ct, ctr;
  unsigned char key_size = 0x10; // AES-256
  
  Clear(SIZE_AES_BLOCK_128, ctr);
  ctr[0] = session.prove.ctrBlock;

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(SIZE_M_ - 16 - 16 - 16 - 16, session.prove.mHatTemp + 16 + 16 + 16 + 16, ct);

  session.prove.ctrBlock = ctr[0];
        
}

unsigned int realSize(unsigned char *buffer, unsigned int size) {
  while (*buffer == 0) {
    buffer++;
    size--;
  }

  return size;
}

/**
 * Construct a proof.
 */
void constructProof(Credential *credential, unsigned char *masterSecret) {
  unsigned char i, j;
  unsigned int rA_size;
  unsigned int rA_offset;

  unsigned long dwPrevHashedBytes;
  unsigned short wLenMsgRem;
  unsigned short pRemainder;
      
  rA_size = realSize(credential->signature.v, SIZE_V) - 1 - realSize(credential->signature.e, SIZE_E);
  if (rA_size > SIZE_R_A) { rA_size = SIZE_R_A; }
  rA_offset = SIZE_R_A - rA_size;

  init_PRNG();

  // HASH - init
  
  memset(session.prove.bufferHash, 0, 64);  

  pRemainder = 0;
  dwPrevHashedBytes = 0;
  wLenMsgRem = 0;

  //multosSecureHashIV(SIZE_STATZK, SHA_256, session.prove.challenge, public.prove.apdu.nonce, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  /* C = Z^m * S^r \mod n */

  ModExp(SIZE_M, SIZE_N, credential->attribute[0], credential->issuerKey.n, credential->issuerKey.Z, public.prove.buffer.number[0]);          
  ModExp(SIZE_M, SIZE_N, r, credential->issuerKey.n, credential->issuerKey.S, public.prove.buffer.number[1]);          

  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential->issuerKey.n);  
  Copy(SIZE_N, session.prove.C, public.prove.buffer.number[0]);
    
  multosSecureHashIV(SIZE_N, SHA_256, session.prove.challenge, session.prove.C, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  /* C_tilde = (Z^(m_r))^ \tilde{m_h} * S ^ \tilde{r}/ */

  ComputeHat();  
  ModExp(SIZE_M_, SIZE_N, session.prove.mHatTemp, credential->issuerKey.n, rev_attr_1, public.prove.buffer.number[0]);          

  ComputeHat();  
  ModExp(SIZE_M_, SIZE_N, session.prove.mHatTemp, credential->issuerKey.n, credential->issuerKey.S, public.prove.buffer.number[1]);          
  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential->issuerKey.n);  
  
  Copy(SIZE_N, session.prove.Ctilde, public.prove.buffer.number[0]);
  
  multosSecureHashIV(SIZE_N, SHA_256, session.prove.challenge, session.prove.Ctilde, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  /* \tilde{Co} = Z^{\tilde{m}} * S^{\tilde{r}} \mod n */
  
  ModExp(SIZE_M_, SIZE_N, session.prove.mHatTemp, credential->issuerKey.n, credential->issuerKey.S, public.prove.buffer.number[1]);          

  ComputeHat();  
  ModExp(SIZE_M_, SIZE_N, session.prove.mHatTemp, credential->issuerKey.n, credential->issuerKey.Z, public.prove.buffer.number[0]);          

  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential->issuerKey.n);
  multosSecureHashIV(SIZE_N, SHA_256, session.prove.challenge, public.prove.buffer.number[0], session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  //reset_PRNG(); // XXXX: Move after \tilde{Z} ?

  // IMPORTANT: Correction to the length of eTilde to prevent overflows
  RandomBits(public.prove.eHat, LENGTH_E_ - 1);
  debugValue("eTilde", public.prove.eHat, SIZE_E_);
  // IMPORTANT: Correction to the length of vTilde to prevent overflows
  RandomBits(public.prove.vHat, LENGTH_V_ - 1);
  debugValue("vTilde", public.prove.vHat, SIZE_V_);
  // IMPORTANT: Correction to the length of rA to prevent negative values
  RandomBits(public.prove.rA + rA_offset, rA_size * 8 - 1);
  for (i = 0; i < rA_offset; i++) {
    public.prove.rA[i] = 0x00; // Set first byte(s) of rA, since it's not set by RandomBits command
  }
  debugValue("rA", public.prove.rA, SIZE_R_A);

  // Compute A' = A * S^r_A
  ModExpSpecial(credential, SIZE_R_A, public.prove.rA, public.prove.APrime, public.prove.buffer.number[0]);
  debugValue("A' = S^r_A mod n", public.prove.APrime, SIZE_N);
  ModMul(SIZE_N, public.prove.APrime, credential->signature.A, credential->issuerKey.n);
  debugValue("A' = A' * A mod n", public.prove.APrime, SIZE_N);

  // Compute ZTilde = A'^eTilde * S^vTilde * (R[i]^mTilde[i] foreach i not in D)
  ModExpSpecial(credential, SIZE_V_, public.prove.vHat, public.prove.buffer.number[0], public.prove.buffer.number[1]);
  debugValue("ZTilde = S^vTilde", public.prove.buffer.number[0], SIZE_N);
  ModExp(SIZE_E_, SIZE_N, public.prove.eHat, credential->issuerKey.n, public.prove.APrime, public.prove.buffer.number[1]);
  debugValue("buffer = A'^eTilde", public.prove.buffer.number[1], SIZE_N);
  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential->issuerKey.n);
  debugValue("ZTilde = ZTilde * buffer", public.prove.buffer.number[0], SIZE_N);
 
  // m

  ModExp(SIZE_M_, SIZE_N, session.prove.mHatTemp, credential->issuerKey.n, credential->issuerKey.R[1], public.prove.buffer.number[1]);
  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential->issuerKey.n);

  // ms

  ComputeHat();  

  ModExp(SIZE_M_, SIZE_N, session.prove.mHatTemp, credential->issuerKey.n, credential->issuerKey.R[0], public.prove.buffer.number[1]);
  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential->issuerKey.n);


  multosSecureHashIV(SIZE_H, SHA_256, session.prove.challenge, public.prove.context, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);
  multosSecureHashIV(SIZE_N, SHA_256, session.prove.challenge, public.prove.APrime, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);
  multosSecureHashIV(SIZE_N, SHA_256, session.prove.challenge, public.prove.buffer.number[0], session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  crypto_compute_ePrime(); // Compute e' = e - 2^(l_e' - 1)
  debugValue("e' = e - 2^(l_e' - 1)", credential->signature.e + SIZE_E - SIZE_EPRIME, SIZE_EPRIME);

  crypto_compute_eHat(); // Compute e^ = e~ + c e'
  debugValue("e^ = e~ + c*e'", public.prove.eHat, SIZE_E_);

  crypto_compute_vPrime(); // Compute v' = v - e r_A
  debugValue("v' = v - e*r_A", public.prove.buffer.data, SIZE_V);

  crypto_compute_vHat(); // Compute v^ = v~ + c v'
  debugValue("vHat", public.prove.vHat, SIZE_V_);

  Copy(SIZE_H, public.prove.apdu.challenge, session.prove.challenge);

  // return eHat, vHat, c, A'
}
