/**
 * AES.c
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
 * Copyright (C) May 2013 - 2013.
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

void AES_CBC_sign(unsigned int message_bytes, const unsigned char *message, unsigned char *signature, unsigned int key_bytes, const unsigned char *key, const unsigned char *iv) {
  unsigned char i;
    
  AES_CBC_encrypt(AES_BLOCK_BYTES, message, signature, key_bytes, key, iv);
  for (i = 1; i < message_bytes / AES_BLOCK_BYTES; i++) {
    AES_CBC_encrypt(AES_BLOCK_BYTES, message + i*AES_BLOCK_BYTES, signature, key_bytes, key, signature);
  }
}

void AES_CMAC_sign(unsigned int message_bytes, const unsigned char *message, unsigned char *signature, unsigned int key_bytes, const unsigned char *key, const unsigned char *iv) {
  unsigned char i;

  AES_CBC_encrypt(AES_BLOCK_BYTES, message, signature, key_bytes, key, iv);
  for (i = 1; i < message_bytes / AES_BLOCK_BYTES; i++) {
    AES_CBC_encrypt(AES_BLOCK_BYTES, message + i*AES_BLOCK_BYTES, signature, key_bytes, key, signature);
  }
}

void aes_128_cbc_encrypt(unsigned char *key, unsigned char *iv, unsigned char *data, unsigned char * data_out, unsigned int data_len) {

  AESblock cbc, aux;
  unsigned char *pos = data;
  int i, j, blocks;

  Copy(SIZE_AES_BLOCK_128, cbc, iv);

  blocks = data_len / SIZE_AES_BLOCK_128;
  
  for (i = 0; i < blocks; i++) {
    for (j = 0; j < SIZE_AES_BLOCK_128; j++)
      cbc[j] ^= pos[j];
  
    AES(key, 0x10, aux, cbc);
    Copy(SIZE_AES_BLOCK_128, data_out, aux);
  
    //data_out += SIZE_AES_BLOCK_128;

    //pos += SIZE_AES_BLOCK_128;
  }
}
