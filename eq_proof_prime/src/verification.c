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


#include "AES.h"
#include "types.h"
#include "types.debug.h"
#include "APDU.h"
#include "CHV.h"
#include "debug.h"
#include "issuance.h"
#include "math.h"
#include "memory.h"
#include "logging.h"
#include "random.h"
#include "RSA.h"
#include "sizes.h"
#include "utils.h"
#include "verification.h"

extern unsigned char mod[RSA_MOD_BYTES];
extern unsigned char pu_exp[RSA_EXP_BYTES];
extern unsigned char pr_exp[RSA_EXP_BYTES];

extern PublicData public;
extern SessionData session;
extern Credential credentials[MAX_CRED];

#define E_HAT_C_1 0x15
#define E_HAT_C_2 0x16

#define V_HAT_C_1 0x17
#define V_HAT_C_2 0x18

#define RA_C_1 0x01
#define RA_C_2 0x02

#define CNT_A_1 0x09 
#define CNT_A_2 0x58

/**
 * Generate the corresponding mHat[i] value (AES-CTR).
 */
void ComputeMS(void) {

  /* In the equality proof ms(1) = ms(2), that
  means that in order to proof the equality of the
  exponent we must choose the same random value
  for \tilde{ms}. In this case, we initialize
  the counter to a safe value beyond the total number
  of calls to the PRNG i.e. 0x80 */

  AESblock ct, ctr;
  unsigned char key_size = 0x10; // AES-256
  
  Clear(SIZE_AES_BLOCK_128, ctr);
  ctr[0] = 0x80;

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
}

void ComputeM1(void) {

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

void ComputeM2(void) {

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

/********************************************************************/
/* PRNG functions                                                   */
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

/**
 * Generate the corresponding mHat[i] value (AES-CTR).
 */
void ComputeM(void) {

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

/********************************************************************/
/* Proving functions                                                */
/********************************************************************/

unsigned int realSize(unsigned char *buffer, unsigned int size) {
  while (*buffer == 0) {
    buffer++;
    size--;
  }

  return size;
}

void gen_attr_1(Credential * credential, unsigned char P1, CLMessage masterSecret)
{

        if (disclosed(P1)) {

          Copy(SIZE_M, public.apdu.data, credential->attribute[P1 - 1]);
          APDU_returnLa(SIZE_M);
        } else {
          if (P1 == 0x00)
            ComputeMS();
          else
            ComputeM1();
          crypto_compute_mHat(P1);
          Copy(SIZE_M_, public.apdu.data, session.prove.mHatTemp);

          debugValue("Returned response", public.apdu.data, SIZE_M_);
          APDU_returnLa(SIZE_M_);
        }
}

void gen_attr_2(Credential * credential, unsigned char P1, CLMessage masterSecret)
{

        if (disclosed(P1)) {

          Copy(SIZE_M, public.apdu.data, credential->attribute[P1 - 1]);
          APDU_returnLa(SIZE_M);
        } else {
          if (P1 == 0x00)
            ComputeMS();
          else
            ComputeM2();
          crypto_compute_mHat(P1);
          Copy(SIZE_M_, public.apdu.data, session.prove.mHatTemp);

          debugValue("Returned response", public.apdu.data, SIZE_M_);
          APDU_returnLa(SIZE_M_);
        }
}


int ComputeAPrime1(void) {

    Credential * credential = &credentials[0];
  
    unsigned int rA_size;
    unsigned int rA_offset;
    unsigned int i;             

    AESblock ct, ctr;
    unsigned char key_size = 0x10; // AES-256
             
    rA_size = realSize(credential->signature.v, SIZE_V) - 1 - realSize(credential->signature.e, SIZE_E);
                     
    if (rA_size > SIZE_R_A) 
      rA_size = SIZE_R_A; 
                            
    rA_offset = SIZE_R_A - rA_size;
                              
// 138 bytes
  
  Clear(SIZE_AES_BLOCK_128, ctr);
  ctr[0] = CNT_A_1;

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(SIZE_R_A - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16, public.prove.rA + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);
  
                                          
    for (i = 0; i < rA_offset; i++) {
      public.prove.rA[i] = 0x00; // Set first byte(s) of rA1, since it's not set by RandomBits command
    }

    Copy(SIZE_R_A, public.prove.rA1, public.prove.rA);
                                                    
    ModExpSpecial(credential, SIZE_R_A, public.prove.rA1, public.prove.APrime1, public.prove.buffer.number[0]);
    ModMul(SIZE_N, public.prove.APrime1, credential->signature.A, credential->issuerKey.n);
}

int ComputeAPrime2(void)
{

    Credential * credential = &credentials[1];
  
    unsigned int rA_size;
    unsigned int rA_offset;
    unsigned int i;             

    AESblock ct, ctr;
    unsigned char key_size = 0x10; // AES-256

                 
    rA_size = realSize(credential->signature.v, SIZE_V) - 1 - realSize(credential->signature.e, SIZE_E);
                     
    if (rA_size > SIZE_R_A) 
      rA_size = SIZE_R_A; 
                            
    rA_offset = SIZE_R_A - rA_size;
                              
  Clear(SIZE_AES_BLOCK_128, ctr);
  ctr[0] = CNT_A_2;

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, public.prove.rA + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(SIZE_R_A - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16, public.prove.rA + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

                                          
    for (i = 0; i < rA_offset; i++) {
      public.prove.rA[i] = 0x00; // Set first byte(s) of rA, since it's not set by RandomBits command
    }

    Copy(SIZE_R_A, public.prove.rA2, public.prove.rA);
                                                      
    ModExpSpecial(credential, SIZE_R_A, public.prove.rA2, public.prove.APrime2, public.prove.buffer.number[1]); //cred_2_buffer);
    ModMul(SIZE_N, public.prove.APrime2, credential->signature.A, credential->issuerKey.n);

}

void ComputeEPrime1(Credential * credential_1) {

  crypto_compute_ePrime1();
  ComputeE1();
  crypto_compute_eHat1();

}

void ComputeEPrime2(Credential * credential_2) {

  crypto_compute_ePrime2();
  ComputeE2();
  crypto_compute_eHat2();

}

void ComputeVPrime1(Credential * credential_1) {

  crypto_compute_vPrime1(); // Compute v' = v - e r_A
  ComputeV1();
  crypto_compute_vHat1(); // Compute v^ = v~ + c v'

}

void ComputeVPrime2(Credential * credential_2) {

  crypto_compute_vPrime2(); // Compute v' = v - e r_A
  ComputeV2();
  crypto_compute_vHat2(); // Compute v^ = v~ + c v'

}

//9, 16 llamadas

void ComputeV1(void) {
  AESblock ct, ctr;
  unsigned char key_size = 0x10; // AES-256
    
  // 255 bytes

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
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(SIZE_V_ - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  session.prove.ctrBlock = ctr[0];        
}

void ComputeV2(void) {
  AESblock ct, ctr;
  unsigned char key_size = 0x10; // AES-256
    
  // 255 bytes

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
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  ctr[0]++;  
  AES(session.prove.aesKey, key_size, ct, ctr);
  Copy(SIZE_V_ - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16 - 16, session.prove.mHatTemp + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16 + 16, ct);

  session.prove.ctrBlock = ctr[0];        
}

void ComputeE1(void) {

// 57 bytes

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
  Copy(SIZE_E_ - 16 - 16 - 16, session.prove.mHatTemp + 16 + 16 + 16, ct);

  session.prove.ctrBlock = ctr[0];        

}

void ComputeE2(void) {

// 57 bytes

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
  Copy(SIZE_E_ - 16 - 16 - 16, session.prove.mHatTemp + 16 + 16 + 16, ct);

  session.prove.ctrBlock = ctr[0];        
}


/**
 * Select the attributes to be disclosed.
 *
 * @param selection bitmask of attributes to be disclosed.
 */
int verifySelection(Credential *credential, unsigned int selection) {

  // Never disclose the master secret.
  if ((selection & 0x0001) != 0) {
    debugError("selectAttributes(): master secret cannot be disclosed");
    return VERIFICATION_ERROR_MASTER_SECRET;
  }

  // Always disclose the expiry attribute.
  if ((selection & 0x0002) == 0) {
    debugError("selectAttributes(): expiry attribute must be disclosed");
    return VERIFICATION_ERROR_EXPIRY;
  }

  // Do not allow non-existant attributes.
  if ((selection & (0xFFFF << credential->size + 1)) != 0) {
    debugError("selectAttributes(): selection contains non-existant attributes");
    return VERIFICATION_ERROR_NOT_FOUND;
  }

  debugInteger("Attribute disclosure selection", selection);
  return VERIFICATION_SELECTION_VALID;
}


/**
 * Construct a proof.
 */
void constructProof(unsigned char *masterSecret) {

  unsigned char i, j;

  unsigned long dwPrevHashedBytes;
  unsigned short wLenMsgRem;
  unsigned short pRemainder;

  Credential * credential_1;
  Credential * credential_2;       

  //RSA_key * public_key, private_key;
            
  init_PRNG();

  credential_1 = &credentials[0];
  credential_2 = &credentials[1];

  // challenge - initialization

  memset(session.prove.bufferHash, 0, 64);  

  pRemainder = 0;
  dwPrevHashedBytes = 0;
  wLenMsgRem = 0;
  
  Clear(SIZE_H, session.prove.challenge);

  // context

  multosSecureHashIV(SIZE_H, SHA_256, session.prove.challenge, public.prove.context, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  // cred 1

  ComputeAPrime1();
  multosSecureHashIV(SIZE_N, SHA_256, session.prove.challenge, public.prove.APrime1, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);
      
  ComputeV1();
  ModExpSpecial(credential_1, SIZE_V_, session.prove.mHatTemp, public.prove.buffer.number[0], public.prove.buffer.number[1]);

  ComputeE1();
  ModExp(SIZE_E_, SIZE_N, session.prove.mHatTemp, credential_1->issuerKey.n, public.prove.APrime1, public.prove.buffer.number[1]);

  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential_1->issuerKey.n);
 
  ComputeMS();
  ModExp(SIZE_M_, SIZE_N, session.prove.mHatTemp, credential_1->issuerKey.n, credential_1->issuerKey.R[0], public.prove.buffer.number[1]);
  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential_1->issuerKey.n);

  ComputeM1();
  ModExp(SIZE_M_, SIZE_N, session.prove.mHatTemp, credential_1->issuerKey.n, credential_1->issuerKey.R[1], public.prove.buffer.number[1]);
  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential_1->issuerKey.n);

  multosSecureHashIV(SIZE_N, SHA_256, session.prove.challenge, public.prove.buffer.number[0], session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  // cred 2 

  ComputeAPrime2();
  multosSecureHashIV(SIZE_N, SHA_256, session.prove.challenge, public.prove.APrime2, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  ComputeV2();
  ModExpSpecial(credential_2, SIZE_V_, session.prove.mHatTemp, public.prove.buffer.number[0], public.prove.buffer.number[1]);

  ComputeE2();
  ModExp(SIZE_E_, SIZE_N, session.prove.mHatTemp, credential_2->issuerKey.n, public.prove.APrime2, public.prove.buffer.number[1]);

  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential_2->issuerKey.n);

  ComputeMS();
  ModExp(SIZE_M_, SIZE_N, session.prove.mHatTemp, credential_2->issuerKey.n, credential_2->issuerKey.R[0], public.prove.buffer.number[1]);
  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential_2->issuerKey.n);

  ComputeM1();
  ModExp(SIZE_M_, SIZE_N, session.prove.mHatTemp, credential_2->issuerKey.n, credential_2->issuerKey.R[1], public.prove.buffer.number[1]);
  ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential_2->issuerKey.n);

  multosSecureHashIV(SIZE_N, SHA_256, session.prove.challenge, public.prove.buffer.number[0], session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  multosSecureHashIV(SIZE_STATZK, SHA_256, session.prove.challenge, public.prove.apdu.nonce, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

}
