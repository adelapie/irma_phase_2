/**
 * random.c
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
 * Copyright (C) April 2013 - 2013.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

#include "random.h"

#include "MULTOS.h"

/**
 * Generate a random number in the buffer of the given number of bytes
 *
 * @param buffer to store the generated random number
 * @param bytes number of random bytes to generate
 */
void RandomBytes(unsigned char *buffer, unsigned int bytes) {
  unsigned char number[8];
  buffer += bytes;

  // Generate the random number in blocks of eight bytes (64 bits)
  while (bytes >= 8) {
    buffer -= 8;
    __push(buffer);
    __code(PRIM, PRIM_RANDOM_NUMBER);
    __code(STOREI, 8);
    bytes -= 8;
  }

  // Generate the remaining few bytes
  if (bytes > 0) {
    buffer -= (bytes + 7) / 8;
    __code(PRIM, PRIM_RANDOM_NUMBER);
    __code(STORE, number, 8);
    __push((bytes + 7) / 8);
    __push(buffer);
    __push(number);
    __code(PRIM, PRIM_COPY_NON_ATOMIC);
  }
}

/**
 * Generate a random number in the buffer of length bits
 *
 * @param buffer to store the generated random number
 * @param length in bits of the random number to generate
 */
void RandomBits(unsigned char *buffer, unsigned int bits) {
  RandomBytes(buffer, (bits + 7) / 8);

  if (bits % 8 != 0) {
    buffer[0] &= 0xFF >> (8 - (bits % 8));
  }
}

#ifdef FAKE_RANDOM

/**
 * Generate a random number in the buffer of the given number of bytes
 *
 * @param buffer to store the generated random number
 * @param bytes number of random bytes to generate
 */
void FakeRandomBytes(unsigned char *buffer, unsigned int bytes) {
  buffer += bytes;

  // Generate the fake random number
  while (bytes > 0) {
    *(--buffer) = bytes--;
  }
}

/**
 * Generate a fake random number in the buffer of length bits
 *
 * @param buffer to store the generated fake random number
 * @param length in bits of the fake random number to generate
 */
void FakeRandomBits(unsigned char *buffer, unsigned int bits) {
  FakeRandomBytes(buffer, (bits + 7) / 8);

  if (bits % 8 != 0) {
    buffer[0] &= 0xFF >> (8 - (bits % 8));
  }
}

#endif // FAKE_RANDOM
