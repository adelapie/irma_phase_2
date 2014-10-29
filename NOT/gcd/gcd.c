/**
 * gcd.c
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
 * Copyright (C) 
 *   Antonio de la Piedra <a.delapiedra@cs.ru.nl>, Radboud University Nijmegen.
 */

#include "gcd.h"

#include "utils.h"
#include "ASN1.h"
#include "debug.h"
#include "math.h"
#include "memory.h"
#include "SHA.h"
#include "types.h"
#include "types.h"
#include "types.debug.h"
#include "APDU.h"
#include "auth.h"
#include "CHV.h"
#include "debug.h"
#include "issuance.h"
#include "math.h"
#include "memory.h"
#include "logging.h"
#include "random.h"
#include "RSA.h"
#include "SM.h"
#include "sizes.h"
#include "utils.h"
#include "verification.h"
#include "gcd.h"

extern PublicData public;
extern SessionData session;

void prepare_array(unsigned char *a, int size)
{
  int i = 0;
  
  for(i = 0; i < GCD_MAX_SIZE_2 - 1; i++) 
    a[i] &= 0x00;
            
  a[GCD_MAX_SIZE_2 - 1] &= 0x01;
}

/********************************************************************/
/* GCD and methods for solving diophantine linear quations          */
/********************************************************************/

/* Euclidean algorithm for parameters of GCD_MAX_SIZE = 9 bytes */

void gcd_euclid(unsigned char *a, unsigned char *b, unsigned char *t)
{
  unsigned char q[GCD_MAX_SIZE]; /* quotient of Euclidean division */
  unsigned char r[GCD_MAX_SIZE]; /* remainder of Euclidean division */
  unsigned char y[GCD_MAX_SIZE]; /* result */
  unsigned char z[GCD_MAX_SIZE]; /* buffer of zeroes for comparing */

  unsigned char finish = 0x00;

  Clear(GCD_MAX_SIZE, z);

  while (1) {
    multosBlockCompare(GCD_MAX_SIZE, b, z, &finish);

    if (finish == 0x01)
      break;
              
    CopyBytes(GCD_MAX_SIZE, y, b);

    multosBlockDivide(GCD_MAX_SIZE, a, b, q, r);
    CopyBytes(GCD_MAX_SIZE, b, r);
    Copy(GCD_MAX_SIZE, a, y);
  }

    Copy(GCD_MAX_SIZE, t, a);
} 

/* Stein's algorithm for parameters of GCD_MAX_SIZE = 9 bytes */

// max-size
void gcd_stein5(unsigned char *n1, unsigned char *n2)
{
  unsigned char a[GCD_MAX_SIZE]; 
  unsigned char b[GCD_MAX_SIZE]; 

  unsigned char pof2[GCD_MAX_SIZE];
  unsigned char tmp_1[GCD_MAX_SIZE];
  unsigned char tmp[GCD_MAX_SIZE];
  unsigned char zeroes[GCD_MAX_SIZE];

  unsigned char finish_1 = 0x00;
  unsigned char finish = 0x00;

  unsigned short inc = 0x00;
  int i = 0;

  Clear(GCD_MAX_SIZE, pof2);
  Clear(GCD_MAX_SIZE, tmp_1);
  Clear(GCD_MAX_SIZE, tmp);
  Clear(GCD_MAX_SIZE, zeroes);
  Clear(GCD_MAX_SIZE, a);
  Clear(GCD_MAX_SIZE, b);

  Copy(GCD_MAX_SIZE, a, n1);
  Copy(GCD_MAX_SIZE, b, n2);

          // First part 

          while(1) {
            Copy(GCD_MAX_SIZE, tmp_1, a);
            Copy(GCD_MAX_SIZE, tmp, b);
            
            prepare_array(tmp_1, GCD_MAX_SIZE);
            prepare_array(tmp, GCD_MAX_SIZE);
          
            multosBlockCompare(GCD_MAX_SIZE, tmp_1, zeroes, &finish_1);
            multosBlockCompare(GCD_MAX_SIZE, tmp, zeroes, &finish);

            if (finish_1 == 0x00 && finish != 0x00)
              break;

            if (finish == 0x00 && finish_1 != 0x00)
              break;

            multosBlockShiftRight(GCD_MAX_SIZE, 1, a, a);
            multosBlockShiftRight(GCD_MAX_SIZE, 1, b, b);

            multosBlockIncrement(GCD_MAX_SIZE, pof2);
          }

         // Second part

          while(1) {

            multosBlockCompare(GCD_MAX_SIZE, a, b, &finish_1);
            if (finish_1 == 0x01)
              break;

            multosBlockCompare(GCD_MAX_SIZE, a, zeroes, &finish_1);
            if (finish_1 == 0x01)
              break;
             
            while(1) {
              Copy(GCD_MAX_SIZE, tmp_1, a);
              prepare_array(tmp_1, GCD_MAX_SIZE);

              multosBlockCompare(GCD_MAX_SIZE, tmp_1, zeroes, &finish_1);

              if (finish_1 == 0x00)
                break;

                multosBlockShiftRight(GCD_MAX_SIZE, 1, a, a);
            }  

            while(1) {
              Copy(GCD_MAX_SIZE, tmp, b);
              prepare_array(tmp, GCD_MAX_SIZE);

              multosBlockCompare(GCD_MAX_SIZE, tmp, zeroes, &finish);

              if (finish == 0x00)
                break;

                multosBlockShiftRight(GCD_MAX_SIZE, 1, b, b);
            }
            
            multosBlockCompare(GCD_MAX_SIZE, a, b, &finish_1);

            //num1 >= num2
            if (finish_1 == 0x01 || finish_1 == 0x30) {
               multosBlockSubtract(GCD_MAX_SIZE, a, b, a);               
               multosBlockShiftRight(GCD_MAX_SIZE, 1, a, a);
            } else {
              Copy(GCD_MAX_SIZE, tmp_1, a);
              multosBlockSubtract(GCD_MAX_SIZE, b, a, a);               
               multosBlockShiftRight(GCD_MAX_SIZE, 1, a, a);
              Copy(GCD_MAX_SIZE, b, tmp_1);
            }
          }
                              
          b[0] <<= (pof2[0] << 8) | pof2[1];
                    
          Copy(GCD_MAX_SIZE, public.apdu.data, b); 
} 

// case #1
void gcd_stein4(unsigned char *n1, unsigned char *n2)
{
  unsigned char a[GCD_MAX_SIZE_2]; 
  unsigned char b[GCD_MAX_SIZE_2]; 

  unsigned char pof2[GCD_MAX_SIZE_2];
  unsigned char tmp_1[GCD_MAX_SIZE_2];
  unsigned char tmp_2[GCD_MAX_SIZE_2];
  unsigned char zeroes[GCD_MAX_SIZE_2];

  unsigned char finish_1 = 0x00;
  unsigned char finish_2 = 0x00;

  unsigned short inc = 0x00;
  int i = 0;

  Clear(GCD_MAX_SIZE_2, pof2);
  Clear(GCD_MAX_SIZE_2, tmp_1);
  Clear(GCD_MAX_SIZE_2, tmp_2);
  Clear(GCD_MAX_SIZE_2, zeroes);

  Copy(GCD_MAX_SIZE_2, a, n1);
  Copy(GCD_MAX_SIZE_2, b, n2);

          // First part 

          while(1) {
            Copy(GCD_MAX_SIZE_2, tmp_1, a);
            Copy(GCD_MAX_SIZE_2, tmp_2, b);
            
            prepare_array(tmp_1, GCD_MAX_SIZE_2);
            prepare_array(tmp_2, GCD_MAX_SIZE_2);
          
            multosBlockCompare(GCD_MAX_SIZE_2, tmp_1, zeroes, &finish_1);
            multosBlockCompare(GCD_MAX_SIZE_2, tmp_2, zeroes, &finish_2);

            if (finish_1 == 0x00 && finish_2 != 0x00)
              break;

            if (finish_2 == 0x00 && finish_1 != 0x00)
              break;

            multosBlockShiftRight(GCD_MAX_SIZE_2, 1, a, a);
            multosBlockShiftRight(GCD_MAX_SIZE_2, 1, b, b);

            multosBlockIncrement(GCD_MAX_SIZE_2, pof2);
          }

         // Second part

          while(1) {

            multosBlockCompare(GCD_MAX_SIZE_2, a, b, &finish_1);
            if (finish_1 == 0x01)
              break;

            multosBlockCompare(GCD_MAX_SIZE_2, a, zeroes, &finish_1);
            if (finish_1 == 0x01)
              break;
             
            while(1) {
              Copy(GCD_MAX_SIZE_2, tmp_1, a);
              prepare_array(tmp_1, GCD_MAX_SIZE_2);

              multosBlockCompare(GCD_MAX_SIZE_2, tmp_1, zeroes, &finish_1);

              if (finish_1 == 0x00)
                break;

                multosBlockShiftRight(GCD_MAX_SIZE_2, 1, a, a);
            }  

            while(1) {
              Copy(GCD_MAX_SIZE_2, tmp_2, b);
              prepare_array(tmp_2, GCD_MAX_SIZE_2);

              multosBlockCompare(GCD_MAX_SIZE_2, tmp_2, zeroes, &finish_2);

              if (finish_2 == 0x00)
                break;

                multosBlockShiftRight(GCD_MAX_SIZE_2, 1, b, b);
            }
            
            multosBlockCompare(GCD_MAX_SIZE_2, a, b, &finish_1);

            //num1 >= num2
            if (finish_1 == 0x01 || finish_1 == 0x30) {
               multosBlockSubtract(GCD_MAX_SIZE_2, a, b, a);               
               multosBlockShiftRight(GCD_MAX_SIZE_2, 1, a, a);
            } else {
              Copy(GCD_MAX_SIZE_2, tmp_1, a);
              multosBlockSubtract(GCD_MAX_SIZE_2, b, a, a);               
               multosBlockShiftRight(GCD_MAX_SIZE_2, 1, a, a);
              Copy(GCD_MAX_SIZE_2, b, tmp_1);
            }
          }
                              
          b[0] <<= (pof2[0] << 8) | pof2[1];
          
          Copy(GCD_MAX_SIZE_2, public.apdu.data, b);
} 

// case #2
void gcd_stein_c_2(unsigned char *n1, unsigned char *n2)
{
  unsigned char a[GCD_MAX_SIZE_2]; 
  unsigned char b[GCD_MAX_SIZE_2]; 

  unsigned char pof2[GCD_MAX_SIZE_2];
  unsigned char tmp_1[GCD_MAX_SIZE_2];
  unsigned char tmp_2[GCD_MAX_SIZE_2];
  unsigned char zeroes[GCD_MAX_SIZE_2];

  unsigned char finish_1 = 0x00;
  unsigned char finish_2 = 0x00;

  unsigned short inc = 0x00;
  int i = 0;

  Clear(GCD_MAX_SIZE_2, pof2);
  Clear(GCD_MAX_SIZE_2, tmp_1);
  Clear(GCD_MAX_SIZE_2, tmp_2);
  Clear(GCD_MAX_SIZE_2, zeroes);

  Copy(GCD_MAX_SIZE_2, a, n1);
  Copy(GCD_MAX_SIZE_2, b, n2);

          // First part 

          while(1) {
            Copy(GCD_MAX_SIZE_2, tmp_1, a);
            Copy(GCD_MAX_SIZE_2, tmp_2, b);
            
            prepare_array(tmp_1, GCD_MAX_SIZE_2);
            prepare_array(tmp_2, GCD_MAX_SIZE_2);
          
            multosBlockCompare(GCD_MAX_SIZE_2, tmp_1, zeroes, &finish_1);
            multosBlockCompare(GCD_MAX_SIZE_2, tmp_2, zeroes, &finish_2);

            if (finish_1 == 0x00 && finish_2 != 0x00)
              break;

            if (finish_2 == 0x00 && finish_1 != 0x00)
              break;

            multosBlockShiftRight(GCD_MAX_SIZE_2, 1, a, a);
            multosBlockShiftRight(GCD_MAX_SIZE_2, 1, b, b);

            multosBlockIncrement(GCD_MAX_SIZE_2, pof2);
          }

         // Second part

          while(1) {

            multosBlockCompare(GCD_MAX_SIZE_2, a, b, &finish_1);
            if (finish_1 == 0x01)
              break;

            multosBlockCompare(GCD_MAX_SIZE_2, a, zeroes, &finish_1);
            if (finish_1 == 0x01)
              break;
             
            while(1) {
              Copy(GCD_MAX_SIZE_2, tmp_1, a);
              prepare_array(tmp_1, GCD_MAX_SIZE_2);

              multosBlockCompare(GCD_MAX_SIZE_2, tmp_1, zeroes, &finish_1);

              if (finish_1 == 0x00)
                break;

                multosBlockShiftRight(GCD_MAX_SIZE_2, 1, a, a);
            }  

            while(1) {
              Copy(GCD_MAX_SIZE_2, tmp_2, b);
              prepare_array(tmp_2, GCD_MAX_SIZE_2);

              multosBlockCompare(GCD_MAX_SIZE_2, tmp_2, zeroes, &finish_2);

              if (finish_2 == 0x00)
                break;

                multosBlockShiftRight(GCD_MAX_SIZE_2, 1, b, b);
            }
            
            multosBlockCompare(GCD_MAX_SIZE_2, a, b, &finish_1);

            //num1 >= num2
            if (finish_1 == 0x01 || finish_1 == 0x30) {
               multosBlockSubtract(GCD_MAX_SIZE_2, a, b, a);               
               multosBlockShiftRight(GCD_MAX_SIZE_2, 1, a, a);
            } else {
              Copy(GCD_MAX_SIZE_2, tmp_1, a);
              multosBlockSubtract(GCD_MAX_SIZE_2, b, a, a);               
               multosBlockShiftRight(GCD_MAX_SIZE_2, 1, a, a);
              Copy(GCD_MAX_SIZE_2, b, tmp_1);
            }
          }
                              
          b[0] <<= (pof2[0] << 8) | pof2[1];
          
          Copy(GCD_MAX_SIZE_2, public.apdu.data, b);
} 
