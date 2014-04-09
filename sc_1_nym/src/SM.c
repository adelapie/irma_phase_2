/**
 * SM.c
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
 * Copyright (C) May 2012 - 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#include "SM.h"

#include "APDU.h"
#include "math.h"
#include "memory.h"
#include "verification.h"
#include "DES.h"
#include "utils.h"
#include "MULTOS.h"

// Secure messaging: Initialisation Vector
unsigned char SM_IV[SM_IV_BYTES];
extern PublicData public;
extern SessionData session;


/********************************************************************/
/* Secure Messaging functions                                       */
/********************************************************************/

unsigned char checkMAC(void) {
  unsigned char result;
  unsigned char iv[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

  DES_CBC_sign(__La, public.apdu.data, session.prove.mHatTemp, 0x10, session.prove.macKey, iv);
  multosBlockCompare(8, public.apdu.data, iv, &result);

  return result;
}

/**
 * Wrap a response APDU for secure messaging
 */
void SM_APDU_wrap(unsigned char *apdu, unsigned char *buffer) {
  unsigned int offset = 0;
  int i;
  
  unsigned char blockLen = 16;
  unsigned short test;
  unsigned char iv[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  unsigned char key_size = 0x10; // 128 bits

    __La = SM_ISO7816_4_pad(apdu, __La);

    multosBlockEncipherCBC(0x04, __La, public.apdu.data, public.apdu.session, 8, iv, key_size, session.prove.secKey);

    apdu[0] = 0x87;
    apdu[1] = __La + 1;
    apdu[2] = 0x01;
      
    CopyBytes(__La, apdu + 3, buffer);

    __La += 3;

    apdu[__La++] = 0x99;
    apdu[__La++] = 0x02;
    apdu[__La++] = __SW >> 8;
    apdu[__La++] = __SW;

  __La = SM_ISO7816_4_pad(apdu, __La);

  apdu[__La++] = 0x8e;
  apdu[__La++] = 0x08;
  DES_CBC_sign(__La, apdu, apdu + __La, 0x10, session.prove.macKey, iv);

  __La += 8;

}

/**
 * Add padding to the input data according to ISO7816-4
 *
 * @param data that needs to be padded
 * @param length of the data that needs to be padded
 * @return the new size of the data including padding
 */
unsigned int SM_ISO7816_4_pad(unsigned char *data, unsigned int length) {
  data[length++] = 0x80;
  while (length % 16 != 0) {
    data[length++] = 0x00;
  }
  return length;
}

/**
 * Remove padding from the input data according to ISO7816-4
 *
 * @param data that contains padding
 * @param length of the data including padding
 * @return the new size of the data excluding padding
 */
int SM_ISO7816_4_unpad(unsigned char *data, unsigned int *length) {
  while (*length > 0 && data[--(*length)] == 0x00);

  if (data[*length] != 0x80) {
    return SM_ISO7816_4_ERROR_PADDING_INVALID;
  } else {
    return *length;
  }
}

/**
 * Derive session key from a given key seed and mode
 *
 * @param key to be stored
 * @param mode for which a key needs to be derived
 */
void SM_session_key(unsigned int seed_bytes, unsigned char *seed, unsigned char *key, unsigned char mode) {
  int i, j, bits;

  // Derive the session key for mode
  seed[seed_bytes + 0] = 0x00;
  seed[seed_bytes + 1] = 0x00;
  seed[seed_bytes + 2] = 0x00;
  seed[seed_bytes + 3] = mode;
  SHA(SM_SHA_BYTES, key, seed_bytes + 4, seed);

#ifdef SM_DES
  // Compute the parity bits
  for (i = 0; i < SM_KEY_BYTES; i++) {
    for (j = 0, bits = 0; j < 8; j++) {
      bits += (key[i] >> j) & 0x01;
    }
    if (bits % 2 == 0) {
      key[i] ^= 0x01;
    }
  }
#endif // SM_DES
}

/**
 * Derive session keys from a given key seed
 */
void SM_setup(unsigned int seed_bytes, unsigned char *seed, SM_parameters *params) {
  unsigned char key_tmp[SM_SHA_BYTES];

  // Derive the session key for encryption
  SM_session_key(seed_bytes, seed, key_tmp, 0x01);
  Copy(SM_KEY_BYTES, params->key_enc, key_tmp);
  Copy(4, params->ssc, key_tmp + SM_KEY_BYTES);

  // Derive the session key for authentication
  SM_session_key(seed_bytes, seed, key_tmp, 0x02);
  Copy(SM_KEY_BYTES, params->key_mac, key_tmp);
  Copy(4, params->ssc + 4, key_tmp + SM_KEY_BYTES);
}
