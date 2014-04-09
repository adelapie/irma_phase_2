/**
 * IRMAcard.c
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
 *   Antonio de la Piedra <a.delapiedra@cs.ru.nl>, Radboud University Nijmegen.
 *   Pim Vullers <pim@cs.ru.nl>, Radboud University Nijmegen.
 */

/**
 * Application Identifier (AID)
 *
 * 0xF8: 0xFX to indicate a Proprietary AID
 * 0x49524D4163617264: ASCII encoded string "IRMAcard"
 */
#pragma attribute("aid", "F8 49 52 4D 41 63 61 72 64")

/**
 * DIR Record
 *
 * The DIR Record for a file contains information about the name of the
 * application when loaded on the card. At application load time the content of
 * the DIR record is entered into the smart card DIR File by MULTOS.
 * DIR: DIRectory entry for the application list of the card
 *
 * 0x60 YZ: Application template (length: 0xYZ bytes)
 *   0x4F YZ: Application identifier, AID (length: 0xYZ bytes)
 *   0x50 YZ: Application label, human-readable identifier (length: 0xYZ bytes)
 */
#pragma attribute("dir", "61 15 4F 09 F8 49 52 4D 41 63 61 72 64 50 08 49 52 4D 41 63 61 72 64")

/**
 * FCI Record
 *
 * The File Control Information (FCI) Record contains the information that is
 * returned when a MEL application is selected. MULTOS stores the FCI Record and
 * returns the information if required during a Select File command.
 *
 * 0x6F YZ: FCI template (length: 0xYZ bytes)
 *   0xA5 YZ: Proprietary information encoded in BER-TLV (length: 0xYZ bytes)
 *     0x10 YZ: Sequence, version information (length: 0xYZ bytes)
 *       0x02 01: Integer, major (length: 0x01 byte)
 *       0x02 01: Integer, minor (length: 0x01 byte)
 *       0x02 01: Integer, maintenance (optional, length: 0x01 byte)
 *       0x02 01: Integer, build (optional, length: 0x01 byte)
 *       0x10 YZ: Sequence, extra information (optional, length: 0xYZ bytes)
 *         0x0C YZ: UTF-8 string, identifier (length: 0xYZ bytes)
 *         0x02 01: Integer, counter (optional, length: 0x01 byte)
 *         0x04 YZ: Octet string, data (optional, length: 0xYZ bytes)
 */
#pragma attribute("fci", "6F 16 A5 14 10 12 02 01 00 02 01 08 10 0A 0C 05 61 6C 70 68 61 02 01 00")

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
#include "DES.h"
#include "SM.h"
#include "sizes.h"
#include "utils.h"
#include "verification.h"

/********************************************************************/
/* Public segment (APDU buffer) variable declaration                */
/********************************************************************/
#pragma melpublic

// Idemix: protocol public variables
PublicData public;


/********************************************************************/
/* Session segment (application RAM memory) variable declaration    */
/********************************************************************/
#pragma melsession

// Idemix: protocol session variables
SessionData session;
Credential *credential;

// Secure messaging: session parameters
SM_parameters tunnel;
Terminal terminal;

// State administration
unsigned int state;

#define STATE_ISSUE_CREDENTIAL 0x00FF
#define STATE_ISSUE_SETUP      0x0001
#define STATE_ISSUE_PUBLIC_KEY 0x0002
#define STATE_ISSUE_ATTRIBUTES 0x0004
#define STATE_ISSUE_COMMITTED  0x0008
#define STATE_ISSUE_CHALLENGED 0x0010
#define STATE_ISSUE_SIGNATURE  0x0020
#define STATE_ISSUE_VERIFY     0x0040
#define STATE_ISSUE_FINISHED   0x0080

#define STATE_PROVE_CREDENTIAL 0x0F00
#define STATE_PROVE_SETUP      0x0100
#define STATE_PROVE_COMMITTED  0x0200
#define STATE_PROVE_SIGNATURE  0x0400
#define STATE_PROVE_ATTRIBUTES 0x0800

#define matchState(x) \
  ((state & (x)) != 0)

#define checkState(x) \
  if (!matchState(x)) { APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED); }

#define nextState() \
  state <<= 1


/********************************************************************/
/* Static segment (application EEPROM memory) variable declarations */
/********************************************************************/
#pragma melstatic

unsigned char ECDSA_SIG[] = {0x0B,0x28,0x6D,0x6F,0xFC,0xC7,0x8C,0x28,0x6A,0x5D,0xB9,0x15,0xA2,0x7E,0x73,0x30,0xD8,0xF2,0x1D,0xB4,0xBE,0xE1,0x6F,0x01,0x56,0xA9,0x3E,0xF7,0x20,0x0B,0x0F,0x71,0x01,0x96,0x3C,0x71,0x5C,0xDA,0x4B,0x7F,0x7F,0x9D,0x79,0x88,0xDD,0xD7,0xCF,0xA4,0xC1,0xFB,0x33,0xC7,0xB1,0x35,0x1B,0x07,0x0A,0x7D,0xFD,0x33,0x90,0x3D,0xCD,0x56};
unsigned char ECDSA_HASH[] = {0xdb,0xbf,0x44,0x8a,0x24,0x29,0xe3,0x21,0x96,0x44,0x78,0x99,0xec,0x91,0x11,0x03,0xaf,0xc0,0x42,0x9e,0x4c,0xa3,0xcc,0x3d,0x9c,0x24,0xa8,0x3f,0x0c,0xb0,0xdd,0xf0};

/* Curve25591 CA PK */

unsigned char PK_CA[64] = {0x02,0x5D,0x18,0x27,0xDF,0x0D,0x71,0x92,
             0x67,0xB6,0x01,0x50,0x8C,0x9B,0x38,0x1D,
             0xA0,0xA5,0xE8,0x4D,0xAF,0x9A,0x73,0xFB,
             0x2A,0xCF,0x24,0x3B,0x06,0x95,0xDC,0xAB,
             0x20,0x77,0x0E,0x03,0xE1,0x38,0x59,0xBF,
             0x2A,0x15,0xFB,0xDE,0x32,0xBC,0x6C,0x57,
             0x87,0x5F,0x49,0xA7,0xB2,0x51,0x17,0xC4,
             0xAA,0x0E,0x57,0x21,0xFB,0xF5,0xB8,0xE6};

// Curve25519 parameters (Weierstrass)

unsigned char domainParams[] = {
  0x00, // format	
  0x20, // prime length
  0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xed,// P
  0x2A,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x98,0x49,0x14,0xA1,0x44,// A
  0x7B,0x42,0x5E,0xD0,0x97,0xB4,0x25,0xED,0x09,0x7B,0x42,0x5E,0xD0,0x97,0xB4,0x25,0xED,0x09,0x7B,0x42,0x5E,0xD0,0x97,0xB4,0x26,0x0B,0x5E,0x9C,0x77,0x10,0xC8,0x64,// B
  0x72,0x66,0xF8,0x64,0xF7,0x99,0xE0,0xD8,0x19,0x4D,0xFA,0x07,0x1F,0x95,0xAA,0x4D,0x1F,0x29,0xD1,0xDF,0x42,0xD5,0x53,0xB4,0x95,0x0B,0x0F,0xDD,0x9C,0x5D,0x57,0x11,// Gx
  0x72,0xFB,0x43,0xCD,0x55,0x68,0xB3,0xB6,0x91,0x20,0x4C,0xA8,0xE6,0xA2,0x93,0x06,0x33,0x71,0x6B,0x80,0xFE,0x7D,0xAD,0xAF,0x91,0xE0,0x72,0x34,0x49,0x91,0xE1,0xF1,// Gy
  0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0xDE,0xF9,0xDE,0xA2,0xF7,0x9C,0xD6,0x58,0x12,0x63,0x1A,0x5C,0xF5,0xD3,0xED,// r
  0x08 // H
};


// Idemix: credentials and master secret
Credential credentials[MAX_CRED];
CLMessage masterSecret;

// Card holder verification: PIN
CHV_PIN cardPIN = {
  { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00 },
  SIZE_CARD_PIN,
  CHV_PIN_COUNT,
  0x80
};
CHV_PIN credPIN = {
  { 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00 },
  SIZE_CRED_PIN,
  CHV_PIN_COUNT,
  0x40
};

RSA_public_key caKey;

// Logging
Log log;
IRMALogEntry *logEntry;

// NYMs

Number Rr    = {0x12,0xED,0x9D,0x5D,0x9C,0x99,0x60,0xBA,0xCE,0x45,0xB7,0x47,0x1E,0xD9,0x35,0x72,0xEA,0x0B,0x82,0xC6,0x11,0x12,0x01,0x27,0x70,0x1E,0x4E,0xF2,0x2A,0x59,0x1C,0xDC,0x17,0x31,0x36,0xA4,0x68,0x92,0x61,0x03,0x73,0x6A,0x56,0x71,0x3F,0xEF,0x31,0x11,0xFD,0xE1,0x9E,0x67,0xCE,0x63,0x2A,0xB1,0x40,0xA6,0xFF,0x6E,0x09,0x24,0x5A,0xC3,0xD6,0xE0,0x22,0xCD,0x44,0xA7,0xCC,0x36,0xBC,0xBE,0x6B,0x21,0x89,0x96,0x0D,0x3D,0x47,0x51,0x3A,0xB2,0x61,0x0F,0x27,0xD2,0x72,0x92,0x4A,0x84,0x15,0x46,0x46,0x02,0x7B,0x73,0x89,0x3D,0x3E,0xE8,0x55,0x47,0x67,0x31,0x89,0x42,0xA8,0x40,0x3F,0x0C,0xD2,0xA4,0x12,0x64,0x81,0x43,0x88,0xBE,0x4D,0xF3,0x45,0xE4,0x79,0xEF,0x52,0xA8};
Number Rdom  = {0x5C,0xAE,0x46,0xA4,0x32,0xBE,0x9D,0xB7,0x2F,0x3B,0x10,0x6E,0x21,0x04,0xB6,0x8F,0x36,0x1A,0x9B,0x3E,0x7B,0x06,0xBB,0xE3,0xE5,0x2E,0x60,0xE6,0x98,0x32,0x61,0x8B,0x94,0x1C,0x95,0x2A,0xA2,0xC6,0xEE,0xFF,0xC2,0x22,0x31,0x1E,0xBB,0xAB,0x92,0x2F,0x70,0x20,0xD6,0x09,0xD1,0x43,0x5A,0x8F,0x3F,0x94,0x1F,0x43,0x73,0xE4,0x08,0xBE,0x5F,0xEB,0xAF,0x47,0x1D,0x05,0xC1,0xB9,0x10,0x30,0x78,0x9F,0x7F,0xEA,0x45,0x0F,0x61,0xD6,0xCB,0x9A,0x4D,0xD8,0x64,0x22,0x53,0x32,0x7E,0x7E,0xBF,0x49,0xC1,0x60,0x0C,0x2A,0x07,0x5E,0xC9,0xB9,0xDE,0xC1,0x96,0xDD,0xBD,0xC3,0x73,0xC2,0x9D,0x1A,0xF5,0xCE,0xAD,0x34,0xFA,0x69,0x93,0xB8,0xCD,0xD7,0x39,0xD0,0x4E,0xA0,0xD2,0x53};
Number gamma = {0x88,0xCC,0x7B,0xD5,0xEA,0xA3,0x90,0x06,0xA6,0x3D,0x1D,0xBA,0x18,0xBD,0xAF,0x00,0x13,0x07,0x25,0x59,0x7A,0x0A,0x46,0xF0,0xBA,0xCC,0xEF,0x16,0x39,0x52,0x83,0x3B,0xCB,0xDD,0x40,0x70,0x28,0x1C,0xC0,0x42,0xB4,0x25,0x54,0x88,0xD0,0xE2,0x60,0xB4,0xD4,0x8A,0x31,0xD9,0x4B,0xCA,0x67,0xC8,0x54,0x73,0x7D,0x37,0x89,0x0C,0x7B,0x21,0x18,0x4A,0x05,0x3C,0xD5,0x79,0x17,0x66,0x81,0x09,0x3A,0xB0,0xEF,0x0B,0x8D,0xB9,0x4A,0xFD,0x18,0x12,0xA7,0x8E,0x1E,0x62,0xAE,0x94,0x26,0x51,0xBB,0x90,0x9E,0x6F,0x5E,0x5A,0x2C,0xEF,0x60,0x04,0x94,0x6C,0xCA,0x3F,0x66,0xEC,0x21,0xCB,0x9A,0xC0,0x1F,0xF9,0xD3,0xE8,0x8F,0x19,0xAC,0x27,0xFC,0x77,0xB1,0x90,0x3F,0x14,0x10,0x49};

unsigned char r1[SIZE_M] = {0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x2a,0xbc,0xdd,0xc3,0x1A,0xcd,0x01,0x06,0x43};


/********************************************************************/
/* APDU handling                                                    */
/********************************************************************/

void processPINVerify(void);
void processPINChange(void);
void processInitialisation(void);
void processIssuance(void);
void processVerification(void);
void processAdministration(void);

void main(void) {
  unsigned char genOK;

  switch (CLA & (0xFF ^ (CLA_SECURE_MESSAGING | CLA_COMMAND_CHAINING))) {

    //////////////////////////////////////////////////////////////////
    // Generic functionality                                        //
    //////////////////////////////////////////////////////////////////

    case CLA_ISO7816:
      // Process the instruction
      switch (INS) {

        //////////////////////////////////////////////////////////////
        // Authentication                                           //
        //////////////////////////////////////////////////////////////

        case INS_PERFORM_SECURITY_OPERATION:
          if (!CheckCase(3)) {
            APDU_returnSW(SW_WRONG_LENGTH);
          }
          if (P1P2 != 0x00BE) {
            APDU_returnSW(SW_WRONG_P1P2);
          }
          if (public.vfyCert.offset + Lc > 768) {
            APDU_returnSW(SW_COMMAND_NOT_ALLOWED);
          }

          // Add the incoming data to the buffer.
          CopyBytes(Lc, public.vfyCert.cert + public.vfyCert.offset, public.apdu.data);
          public.vfyCert.offset += Lc;

          // Verify the certificate.
          if (!APDU_chained) {
            public.vfyCert.offset = 0;
            if (authentication_verifyCertificate(&caKey, public.vfyCert.cert, session.auth.certBody) < 0) {
              APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
            }
            authentication_parseCertificate(session.auth.certBody);
          }
          APDU_return();

        case INS_GET_CHALLENGE:

          if (!CheckCase(3)) {
            APDU_returnSW(SW_WRONG_LENGTH);
          }
                    
          SHA(SHA_256, session.prove.challenge, 128 + 3, public.apdu.data + SIZE_STATZK);
          APDU_checkLength(SIZE_STATZK + 128 + 3 + 64); // mod RSA + exp RSA + ECDSA_sig (256-bit)
          
          multosEccVerifySignature((unsigned char *)&domainParams,
                                   session.prove.challenge, 
                                   (unsigned char *)(public.apdu.data + SIZE_STATZK + 128 + 3), 
                                   (unsigned char *)&PK_CA, 
                                   0x00, 
                                   &genOK);
          
          if(!genOK) {
            APDU_returnSW(0x90FF);
          } else {      
            Copy(SIZE_STATZK, session.prove.nonceV, public.prove.apdu.nonce);          
            Copy(SIZE_STATZK, session.prove.nonceV, public.apdu.data);
            authentication_generateChallenge(NULL, public.apdu.data); 

            APDU_returnLa(RSA_MOD_BYTES);
          }

        case INS_INTERNAL_AUTHENTICATE:
          // Perform card authentication & secure messaging setup
          break;

        //////////////////////////////////////////////////////////////
        // Card holder verification                                 //
        //////////////////////////////////////////////////////////////

        case INS_VERIFY:
	        debugMessage("Processing PIN verification...");
          processPINVerify();
          __code(SYSTEM, 4);

        case INS_CHANGE_REFERENCE_DATA:
          debugMessage("Processing PIN change...");
          processPINChange();
          return;

        //////////////////////////////////////////////////////////////
        // Unknown instruction byte (INS)                           //
        //////////////////////////////////////////////////////////////

        default:
          debugWarning("Unknown instruction");
          APDU_returnSW(SW_INS_NOT_SUPPORTED);
      }

    //////////////////////////////////////////////////////////////////
    // Idemix functionality                                         //
    //////////////////////////////////////////////////////////////////

    case CLA_IRMACARD:
      switch (INS & 0xF0) {
        case 0x00:
          debugMessage("Processing initialisation instruction...");
          processInitialisation();
          __code(SYSTEM, 4);

        case 0x10:
          debugMessage("Processing issuance instruction...");
          processIssuance();
          __code(SYSTEM, 4);

        case 0x20:
          debugMessage("Processing verification instruction...");
          processVerification();
//          SM_return();
          SM_APDU_wrap(public.apdu.data, public.apdu.session);
          __code(SYSTEM, 4);


        case 0x30:
          debugMessage("Processing administration instruction...");
          processAdministration();
          return;

        default:
          debugWarning("Unknown instruction");
          debugInteger("INS", INS);
          APDU_returnSW(SW_INS_NOT_SUPPORTED);
      }

    //////////////////////////////////////////////////////////////////
    // Unknown class byte (CLA)                                     //
    //////////////////////////////////////////////////////////////////

    default:
      debugWarning("Unknown class");
      debugInteger("CLA", CLA);
      APDU_returnSW(SW_CLA_NOT_SUPPORTED);
  }
}

void processPINVerify(void) {
  int result;

  debugMessage("INS_VERIFY");

  APDU_checkP1(0x00);
  switch (P2) {
    case P2_CARD_PIN:
      debugMessage("Verifying card administration PIN...");
      result = CHV_PIN_verify(&cardPIN, Lc, public.apdu.data);
      break;

    case P2_CRED_PIN:
      debugMessage("Verifying credential protection PIN...");
      result = CHV_PIN_verify(&credPIN, Lc, public.apdu.data);
      break;

    default:
      debugWarning("Unknown parameter");
      APDU_returnSW(SW_WRONG_P1P2);
  }

  // Translate the result to the corresponding Status Word.
  if (result == CHV_VALID) {
    APDU_returnSW(SW_NO_ERROR);
  } else if (result == CHV_WRONG_LENGTH) {
    APDU_returnSW(SW_WRONG_LENGTH);
  } else {
    APDU_returnSW(SW_COUNTER(CHV_TRIES_LEFT * result));
  }
}

void processPINChange(void) {
  int result;

  debugMessage("INS_CHANGE_REFERENCE_DATA");

  APDU_checkP1(0x00);

  switch (P2) {
    case P2_CARD_PIN:
      APDU_checkLength(2*SIZE_PIN_MAX);
      debugMessage("Changing card administration PIN...");
      result = CHV_PIN_update(&cardPIN, Lc, public.apdu.data);
      break;

    case P2_CRED_PIN:
      if (!CHV_verified(cardPIN)) {
        APDU_returnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
      }
      debugMessage("Changing credential protection PIN...");
      result = CHV_PIN_update(&credPIN, Lc, public.apdu.data);
      break;

    default:
      debugWarning("Unknown parameter");
      APDU_returnSW(SW_WRONG_P1P2);
  }

  // Translate the result to the corresponding Status Word.
  if (result == CHV_VALID) {
    APDU_returnSW(SW_NO_ERROR);
  } else if (result == CHV_WRONG_LENGTH) {
    APDU_returnSW(SW_WRONG_LENGTH);
  } else {
    APDU_returnSW(SW_COUNTER(CHV_TRIES_LEFT * result));
  }
}

void processInitialisation(void) {
  unsigned char flag;

  switch (INS) {
    case INS_GENERATE_SECRET:
      debugMessage("INS_GENERATE_SECRET");
#ifndef TEST
      if (!(APDU_wrapped || CheckCase(1))) {
        APDU_returnSW(SW_WRONG_LENGTH);
      }

      // Prevent reinitialisation of the master secret
      TestZero(SIZE_M, masterSecret, flag);
      if (flag == 0) {
        debugWarning("Master secret is already generated");
        APDU_returnSW(SW_COMMAND_NOT_ALLOWED_AGAIN);
      }

      // Generate a random value for the master secret
      RandomBits(masterSecret, LENGTH_M);
#else // TEST
      if (!((APDU_wrapped || CheckCase(3)) && Lc == SIZE_M)) {
        APDU_returnSW(SW_WRONG_LENGTH);
      }

      // Use the test value for the master secret
      Copy(SIZE_M, masterSecret, public.apdu.data);
#endif // TEST
      debugValue("Initialised master secret", masterSecret, SIZE_M);
      APDU_returnSW(SW_NO_ERROR);

    case INS_AUTHENTICATION_SECRET:
      debugMessage("INS_AUTHENTICATION_SECRET");
      if (P2 != 0x00) {
          APDU_returnSW(SW_WRONG_P1P2);
      }
      switch (P1) {
        case P1_AUTH_EXPONENT + 2:
          debugMessage("P1_AUTHENTICATION_EXPONENT");
          if (!((APDU_wrapped || CheckCase(3)) && Lc == RSA_EXP_BYTES)) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }

          Copy(RSA_EXP_BYTES, caKey.exponent, public.apdu.data);
          debugValue("Initialised rsaExponent", caKey.exponent, RSA_EXP_BYTES);
          break;

        case P1_AUTH_MODULUS + 2:
          debugMessage("P1_AUTHENTICATION_MODULUS");
          if (!((APDU_wrapped || CheckCase(3)) && Lc == RSA_MOD_BYTES)) {
            APDU_ReturnSW(SW_WRONG_LENGTH);
          }

          Copy(RSA_MOD_BYTES, caKey.modulus, public.apdu.data);
          debugValue("Initialised rsaModulus", caKey.modulus, RSA_MOD_BYTES);
          break;

        default:
          debugWarning("Unknown parameter");
          APDU_ReturnSW(SW_WRONG_P1P2);
      }
      APDU_ReturnSW(SW_NO_ERROR);

    default:
      debugWarning("Unknown instruction");
      debugInteger("INS", INS);
      APDU_returnSW(SW_INS_NOT_SUPPORTED);
  }
}


void startIssuance(void) {
  unsigned char i;

  APDU_checkP1P2(0x0000);

  // Ensure that the master secret is initiaised
  IfZeroBytes(SIZE_M, masterSecret, RandomBits(masterSecret, LENGTH_M));

  // Start a new issuance session
  credential = NULL;

  // Check policy
  if (!auth_checkIssuance(&terminal, public.issuanceSetup.id)) {
    APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
  }

  // Locate a credential slot
  for (i = 0; i < MAX_CRED; i++) {
    // Reuse the existing credential slot.
    if (credentials[i].id == public.issuanceSetup.id) {
      debugMessage("Credential already exists");
      if (!auth_checkOverwrite(&terminal, public.issuanceSetup.id)) {
        debugWarning("Overwrite not allowed");
        APDU_returnSW(SW_COMMAND_NOT_ALLOWED_AGAIN);
      } else {
        credential = &credentials[i];
        break;
      }

    // Use a new credential slot
    } else if (credentials[i].id == 0 && credential == NULL) {
      debugMessage("Found empty slot");
      credential = &credentials[i];
    }
  }

  // No credential slot selected, out of space
  if (credential == NULL) {
    debugWarning("Cannot issue another credential");
    APDU_returnSW(SW_COMMAND_NOT_ALLOWED);
  }

  // Initialise the credential
  credential->id = public.issuanceSetup.id;
  credential->size = public.issuanceSetup.size;
  credential->issuerFlags = public.issuanceSetup.flags;
  Copy(SIZE_H, credential->proof.context, public.issuanceSetup.context);
  debugHash("Initialised context", credential->proof.context);

  // Create new log entry
  logEntry = (IRMALogEntry*) log_new_entry(&log);
  Copy(SIZE_TIMESTAMP, logEntry->timestamp, public.issuanceSetup.timestamp);
  Copy(AUTH_TERMINAL_ID_BYTES, logEntry->terminal, terminal.id);
  logEntry->action = ACTION_ISSUE;
  logEntry->credential = credential->id;

  // Initialise the issuance state
  state = STATE_ISSUE_SETUP;
}

void processIssuance(void) {

  // Issuance requires the terminal to be authenticated.
  /* Implicit due to the fact that we've got a secure tunnel. */

  // Issuance requires the credential PIN to be verified.
  if (!CHV_verified(credPIN)) {
    APDU_returnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
  }

  // Special case: start issuance
  if (INS == INS_ISSUE_CREDENTIAL) {
    debugMessage("INS_ISSUE_CREDENTIAL");
    APDU_checkLength(sizeof(IssuanceSetup));

    startIssuance();

  // All other issuance commands
  } else {

    // A credential should be selected for issuance
    if (credential == NULL || !matchState(STATE_ISSUE_CREDENTIAL)) {
      APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
    }

    switch (INS) {
      case INS_ISSUE_PUBLIC_KEY:
        debugMessage("INS_ISSUE_PUBLIC_KEY");
        if (matchState(STATE_ISSUE_SETUP)) {
          nextState();
        }
        checkState(STATE_ISSUE_PUBLIC_KEY);
        APDU_checkLength(SIZE_N);

        switch (P1) {
          case P1_PUBLIC_KEY_N:
            debugMessage("P1_PUBLIC_KEY_N");
            Copy(SIZE_N, credential->issuerKey.n, public.apdu.data);
            debugNumber("Initialised isserKey.n", credential->issuerKey.n);
            break;

          case P1_PUBLIC_KEY_Z:
            debugMessage("P1_PUBLIC_KEY_Z");
            Copy(SIZE_N, credential->issuerKey.Z, public.apdu.data);
            debugNumber("Initialised isserKey.Z", credential->issuerKey.Z);
            break;

          case P1_PUBLIC_KEY_S:
            debugMessage("P1_PUBLIC_KEY_S");
            Copy(SIZE_N, credential->issuerKey.S, public.apdu.data);
            debugNumber("Initialised isserKey.S", credential->issuerKey.S);
            ComputeS_(credential, public.issue.buffer.data);
            debugNumber("Initialised isserKey.S_", credential->issuerKey.S_);
            break;

          case P1_PUBLIC_KEY_R:
            debugMessage("P1_PUBLIC_KEY_R");
            APDU_checkP2upper(credential->size + 1);
            Copy(SIZE_N, credential->issuerKey.R[P2], public.apdu.data);
            debugIndexedNumber("Initialised isserKey.R", credential->issuerKey.R, P2);
            break;

          default:
            debugWarning("Unknown parameter");
            debugInteger("P1", P1);
            APDU_returnSW(SW_WRONG_P1P2);
        }
        APDU_return();

      case INS_ISSUE_ATTRIBUTES:
        debugMessage("INS_ISSUE_ATTRIBUTES");
        if (matchState(STATE_ISSUE_PUBLIC_KEY) && issuance_checkPublicKey(credential)) {
          nextState();
        }
        checkState(STATE_ISSUE_ATTRIBUTES);
        APDU_checkLength(SIZE_M);
        APDU_checkP1range(1, credential->size);
        IfZero(SIZE_M, public.apdu.data,
          debugWarning("Attribute cannot be empty");
          APDU_returnSW(SW_WRONG_DATA);
        );

        Copy(SIZE_M, credential->attribute[P1 - 1], public.apdu.data);
        debugIndexedCLMessage("Initialised attribute", credential->attribute, P1 - 1);
        APDU_return();

      case INS_ISSUE_COMMITMENT:
        debugMessage("INS_ISSUE_COMMITMENT");
        if (!matchState(STATE_ISSUE_ATTRIBUTES) && !issuance_checkAttributes(credential)) {
          APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
        }
        APDU_checkLength(SIZE_STATZK);

        Copy(SIZE_STATZK, public.issue.nonce, public.apdu.data);
        debugNonce("Initialised nonce", public.issue.nonce);
        constructCommitment(credential, &masterSecret[0]);
        debugNumber("Returned U", public.apdu.data);

        nextState();
        APDU_returnLa(SIZE_N);

      case INS_ISSUE_COMMITMENT_PROOF:
        debugMessage("INS_ISSUE_COMMITMENT_PROOF");
        checkState(STATE_ISSUE_COMMITTED);
        APDU_checkLength(0);

        switch (P1) {
          case P1_PROOF_C:
            debugMessage("P1_COMMITMENT_PROOF_C");
            Copy(SIZE_H, public.apdu.data, session.issue.challenge);
            debugHash("Returned c", public.apdu.data);
            APDU_returnLa(SIZE_H);

          case P1_PROOF_VPRIMEHAT:
            debugMessage("P1_COMMITMENT_PROOF_VPRIMEHAT");
            Copy(SIZE_VPRIME_, public.apdu.data, session.issue.vPrimeHat);
            debugValue("Returned vPrimeHat", public.apdu.data, SIZE_VPRIME_);
            APDU_returnLa(SIZE_VPRIME_);

          case P1_PROOF_SHAT:
            debugMessage("P1_COMMITMENT_PROOF_SHAT");
            Copy(SIZE_S_, public.apdu.data, session.issue.sHat);
            debugValue("Returned s_A", public.apdu.data, SIZE_S_);
            APDU_returnLa(SIZE_S_);

          default:
            debugWarning("Unknown parameter");
            debugInteger("P1", P1);
            APDU_returnSW(SW_WRONG_P1P2);
        }

      case INS_ISSUE_CHALLENGE:
        debugMessage("INS_ISSUE_CHALLENGE");
        checkState(STATE_ISSUE_COMMITTED);
        APDU_checkLength(0);

        Copy(SIZE_STATZK, public.apdu.data, credential->proof.nonce);
        debugNonce("Returned nonce", public.apdu.data);

        nextState();
        APDU_returnLa(SIZE_STATZK);

      case INS_ISSUE_SIGNATURE:
        debugMessage("INS_ISSUE_SIGNATURE");
        if (matchState(STATE_ISSUE_CHALLENGED)) {
          nextState();
        }
        checkState(STATE_ISSUE_SIGNATURE);

        switch(P1) {
          case P1_SIGNATURE_A:
            debugMessage("P1_SIGNATURE_A");
            APDU_checkLength(SIZE_N);
            Copy(SIZE_N, credential->signature.A, public.apdu.data);
            debugNumber("Initialised signature.A", credential->signature.A);
            break;

          case P1_SIGNATURE_E:
            debugMessage("P1_SIGNATURE_E");
            APDU_checkLength(SIZE_E);
            Copy(SIZE_E, credential->signature.e, public.apdu.data);
            debugValue("Initialised signature.e", credential->signature.e, SIZE_E);
            break;

          case P1_SIGNATURE_V:
            debugMessage("P1_SIGNATURE_V");
            APDU_checkLength(SIZE_V);
            constructSignature(credential);
            debugValue("Initialised signature.v", credential->signature.v, SIZE_V);
            break;

          case P1_SIGNATURE_PROOF_C:
            debugMessage("P1_SIGNATURE_PROOF_C");
            APDU_checkLength(SIZE_H);
            Copy(SIZE_H, credential->proof.challenge, public.apdu.data);
            debugHash("Initialised c", credential->proof.challenge);
            break;

          case P1_SIGNATURE_PROOF_S_E:
            debugMessage("P1_SIGNATURE_PROOF_S_E");
            APDU_checkLength(SIZE_N);
            Copy(SIZE_N, credential->proof.response, public.apdu.data);
            debugNumber("Initialised s_e", credential->proof.response);
            break;

          default:
            debugWarning("Unknown parameter");
            APDU_returnSW(SW_WRONG_P1P2);
        }
        APDU_return();

      case INS_ISSUE_VERIFY:
        if (matchState(STATE_ISSUE_SIGNATURE) && issuance_checkSignature(credential)) {
          nextState();
        }
        checkState(STATE_ISSUE_VERIFY);

        if (!verifySignature(credential, &masterSecret[0], &session.vfySig)) {
          debugWarning("Signature invalid");
          APDU_returnSW(SW_DATA_INVALID);
        }
        if (!verifyProof(credential, &session.vfyPrf, &public.vfyPrf)) {
          debugWarning("Proof invalid");
          APDU_returnSW(SW_DATA_INVALID);
        }

        nextState();
        APDU_return();

      default:
        debugWarning("Unknown instruction");
        debugInteger("INS", INS);
        APDU_returnSW(SW_INS_NOT_SUPPORTED);
    }
  }
}

void startVerification(void) {
  unsigned char i;
  unsigned char macVfy = 0x00;
  unsigned char iv[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

  unsigned long dwPrevHashedBytes;
  unsigned short wLenMsgRem;
  unsigned short pRemainder;

  APDU_checkP1P2(0x0000);

  credential = &credentials[0];

  Clear(SM_SSC_BYTES, session.prove.SSC);

  // ICA secure channel K = SHA-256(nonceV || nonceC)

  memset(session.prove.bufferHash, 0, 64);  

  pRemainder = 0;
  dwPrevHashedBytes = 0;
  wLenMsgRem = 0;

  multosSecureHashIV(SIZE_STATZK, SHA_256, session.prove.mHatTemp, session.prove.nonceV, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);
  multosSecureHashIV(SIZE_STATZK, SHA_256, session.prove.mHatTemp, session.prove.nonceC, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  // K_ENC = H(K || 1)

  memset(session.prove.bufferHash, 0, 64);  

  pRemainder = 0;
  dwPrevHashedBytes = 0;
  wLenMsgRem = 0;
  i = 0x31;
  
  multosSecureHashIV(SIZE_H, SHA_256, session.prove.secKey, session.prove.mHatTemp, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);
  multosSecureHashIV(1, SHA_256, session.prove.secKey, &i, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  // K_MAC = H(K || 2)

  memset(session.prove.bufferHash, 0, 64);  

  pRemainder = 0;
  dwPrevHashedBytes = 0;
  wLenMsgRem = 0;
  i = 0x32;
  
  multosSecureHashIV(SIZE_H, SHA_256, session.prove.macKey, session.prove.mHatTemp, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);
  multosSecureHashIV(1, SHA_256, session.prove.macKey, &i, session.prove.bufferHash, &dwPrevHashedBytes, &wLenMsgRem, &pRemainder);

  Clear(SIZE_H, session.prove.mHatTemp);

//  if (verifyProtection(credential, public.verificationSetup.selection) && !CHV_verified(credPIN)) {
//    credential = NULL;
//   APDU_returnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
//  }

  macVfy = checkMAC();
            
  if (!macVfy) {
    APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
  } else {
    //multosBlockDecipherCBC(0x04, 16, public.apdu.data, public.apdu.data, 8, iv, 0x10, session.prove.secKey);           
    // Initialise the session
    session.prove.disclose = public.verificationSetup.selection;
    Copy(SIZE_H, public.prove.context, public.verificationSetup.context);

    // Create new log entry
    logEntry = (IRMALogEntry*) log_new_entry(&log);
    Copy(SIZE_TIMESTAMP, logEntry->timestamp, public.verificationSetup.timestamp);
    //Copy(AUTH_TERMINAL_ID_BYTES, logEntry->terminal, terminal.id);
    logEntry->action = ACTION_PROVE;
    logEntry->credential = credential->id;
    logEntry->details.prove.selection = session.prove.disclose;

    state = STATE_PROVE_CREDENTIAL;
  }
}

void processVerification(void) {
  unsigned char macVfy = 0x00;
  unsigned char iv[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

  // Verification requires the terminal to be authenticated.
  /* Implicit due to the fact that we've got a secure tunnel. */

  // Special case: start verification
  if (INS == INS_PROVE_CREDENTIAL) {
    debugMessage("INS_PROVE_CREDENTIAL");
    APDU_checkLength(sizeof(VerificationSetup));

    startVerification();
    Fill(40, public.apdu.data, public.apdu.data[3]);
    APDU_returnLa(40);

  // All other verification commands
  } else {

    // A credential should be selected for verification
    if (credential == NULL || !matchState(STATE_PROVE_CREDENTIAL)) {
      APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
    }

    switch (INS) {
      case INS_PROVE_COMMITMENT:
        debugMessage("INS_PROVE_COMMITMENT");
        checkState(STATE_PROVE_SETUP);
        APDU_checkLength(SIZE_STATZK + 6 + 8);

        macVfy = checkMAC();
            
        if (!macVfy) {
          APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
        } else {               
          multosBlockDecipherCBC(0x04, 16, public.apdu.data, public.apdu.data, 8, iv, 0x10, session.prove.secKey);

          constructProof(credential, &masterSecret[0]);
          // The PRNG is reseted at this point for generating
          // the same amount of randomness during the next
          // instructions.
          reset_PRNG();

          nextState();
          APDU_returnLa(SIZE_H);
        }
      case INS_PROVE_SIGNATURE:
        debugMessage("INS_PROVE_SIGNATURE");
        if (matchState(STATE_PROVE_COMMITTED)) {
          nextState();
        }
        checkState(STATE_PROVE_SIGNATURE);

        switch(P1) {
          case P1_SIGNATURE_A:
            APDU_checkLength(8); // MAC
            macVfy = checkMAC();
            
            if (!macVfy) {
              APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
            } else {               
              Copy(SIZE_N, public.apdu.data, public.prove.APrime);
              APDU_returnLa(SIZE_N);
            }
          case P1_SIGNATURE_E:
            APDU_checkLength(8); // MAC
            macVfy = checkMAC();
            
            if (!macVfy) {
              APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
            } else {               

            Copy(SIZE_E_, public.apdu.data, public.prove.eHat);
            debugValue("Returned e^", public.apdu.data, SIZE_E_);
            APDU_returnLa(SIZE_E_);
            }
          case P1_SIGNATURE_V_P_1: 
            APDU_checkLength(8); // MAC
            macVfy = checkMAC();
            
            if (!macVfy) {
              APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
            } else {               

            Copy(128, public.apdu.data, public.prove.vHat);
            APDU_returnLa(128);
            }
          case P1_SIGNATURE_V_P_2:
            APDU_checkLength(8); // MAC
            macVfy = checkMAC();
            
            if (!macVfy) {
              APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
            } else {               

            Copy(SIZE_V_ - 128, public.apdu.data, public.prove.vHat + 128);
            APDU_returnLa(SIZE_V_ - 128);
            }
          default:
            debugWarning("Unknown parameter");
            APDU_returnSW(SW_WRONG_P1P2);
        }

      case INS_PROVE_ATTRIBUTE:
        debugMessage("INS_PROVE_ATTRIBUTE");
        if (matchState(STATE_PROVE_SIGNATURE)) {
          nextState();
        }
        
        checkState(STATE_PROVE_ATTRIBUTES);
        APDU_checkLength(8); // MAC
        macVfy = checkMAC();
            
        if (!macVfy) {
          APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
        } else {               

          if (P1 > credential->size) {
            APDU_returnSW(SW_WRONG_P1P2);
          }

        /* dNYM */

        if (P2 == 0x03) {
          ModExp(SIZE_M, SIZE_N, masterSecret, credential->issuerKey.n, Rdom, public.apdu.data);          
          APDU_returnLa(SIZE_N);
        } 

        /* NYM */
        
        if (P2 == 0x04) {
          //ModExp(SIZE_M, SIZE_N, masterSecret, credential->issuerKey.n, credential->issuerKey.R[0], public.prove.buffer.number[0]);          
          //ModExp(SIZE_M, SIZE_N, r1, credential->issuerKey.n, Rr, public.prove.buffer.number[1]);          
          //ModMul(SIZE_N, public.prove.buffer.number[0], public.prove.buffer.number[1], credential->issuerKey.n);
          
          Copy(SIZE_N, public.apdu.data, session.prove.C1);
          APDU_returnLa(SIZE_N);
        } 

        /* r - HAT */
        
        if (P2 == 0x06) {
          reset_PRNG();

          ComputeHat();
          ComputeHat();
          crypto_compute_r(P1);
          Copy(SIZE_M_, public.apdu.data, session.prove.mHatTemp);
          
          APDU_returnLa(SIZE_M_);
        } 

          if (disclosed(P1)) {
            Copy(SIZE_M, public.apdu.data, credential->attribute[P1 - 1]);
            debugValue("Returned attribute", public.apdu.data, SIZE_M);
            APDU_returnLa(SIZE_M);
          } else {
            ComputeHat();
            crypto_compute_mHat(P1);
            Copy(SIZE_M_, public.apdu.data, session.prove.mHatTemp);

            debugValue("Returned response", public.apdu.data, SIZE_M_);
            APDU_returnLa(SIZE_M_);
          }
        }
      default:
        APDU_returnSW(SW_INS_NOT_SUPPORTED);
    }
  }
}

void processAdministration(void) {
  unsigned char i;

  if (!CHV_verified(cardPIN)) {
    APDU_returnSW(SW_SECURITY_STATUS_NOT_SATISFIED);
  }

  switch (INS) {
    case INS_ADMIN_CREDENTIALS:
      debugMessage("INS_ADMIN_CREDENTIALS");
      if (!CheckCase(1)) {
        APDU_ReturnSW(SW_WRONG_LENGTH);
      }
      APDU_checkP1P2(0x0000);

      for (i = 0; i < MAX_CRED; i++) {
        ((short*) public.apdu.data)[i] = credentials[i].id;
      }

      APDU_returnLa(2*MAX_CRED);

    case INS_ADMIN_CREDENTIAL:
      debugMessage("INS_ADMIN_CREDENTIAL");

      APDU_checkP1P2(0x0000);
      APDU_checkLength(sizeof(AdminSelect));

      // Lookup the given credential ID and select it if it exists
      for (i = 0; i < MAX_CRED; i++) {
        if (credentials[i].id == public.adminSelect.id) {
          credential = &credentials[i];
          APDU_returnSW(SW_NO_ERROR);
        }
      }
      APDU_returnSW(SW_REFERENCED_DATA_NOT_FOUND);

    case INS_ADMIN_ATTRIBUTE:
      debugMessage("INS_ADMIN_ATTRIBUTE");
      if (credential == NULL) {
        APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
      }

      if (P1 == 0 || P1 > credential->size) {
        APDU_returnSW(SW_WRONG_P1P2);
      }
      APDU_checkP2(0x00);
      APDU_checkLength(0);

      Copy(SIZE_M, public.apdu.data, credential->attribute[P1 - 1]);
      debugValue("Returned attribute", public.apdu.data, SIZE_M);
      APDU_returnLa(SIZE_M);

    case INS_ADMIN_REMOVE:
      debugMessage("INS_ADMIN_REMOVE");
      if (credential == NULL) {
        APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
      }

      APDU_checkP1P2(0x0000);
      APDU_checkLength(sizeof(AdminRemove));

      debugInteger("Removing credential", credential->id);
      ClearCredential(credential);
      debugMessage("Removed credential");

      // Create new log entry
      logEntry = (IRMALogEntry*) log_new_entry(&log);
      Copy(SIZE_TIMESTAMP, logEntry->timestamp, public.adminRemove.timestamp);
      Copy(AUTH_TERMINAL_ID_BYTES, logEntry->terminal, terminal.id);
      logEntry->action = ACTION_REMOVE;
      logEntry->credential = P1P2;

      APDU_return();

    case INS_ADMIN_FLAGS:
      debugMessage("INS_ADMIN_FLAGS");
      if (credential == NULL) {
        APDU_returnSW(SW_CONDITIONS_NOT_SATISFIED);
      }

      APDU_checkP1P2(0x0000);
      APDU_checkLength(sizeof(CredentialFlags));

      if (Lc > 0) {
        credential->userFlags = public.adminFlags.user;
        debugValue("Updated flags", (ByteArray) credential->userFlags.protect, sizeof(CredentialFlags));
        APDU_return();
      } else {
        public.adminFlags.user = credential->userFlags;
        public.adminFlags.issuer = credential->issuerFlags;
        debugValue("Returned flags", public.apdu.data, 2 * sizeof(CredentialFlags));
        APDU_returnLa(2 * sizeof(CredentialFlags));
      }

    case INS_ADMIN_LOG:
      debugMessage("INS_ADMIN_LOG");

      APDU_checkP2(0x00);
      APDU_checkLength(0);

      for (i = 0; i < 255 / sizeof(LogEntry); i++) {
        memcpy(public.apdu.data + i*sizeof(LogEntry), log_get_entry(&log, P1 + i), sizeof(LogEntry));
      }
      APDU_returnLa((255 / sizeof(LogEntry)) * sizeof(LogEntry));

    //////////////////////////////////////////////////////////////
    // Unknown instruction byte (INS)                           //
    //////////////////////////////////////////////////////////////

    default:
      debugWarning("Unknown instruction");
      debugInteger("CLA", CLA);
      debugInteger("INS", INS);
      debugInteger("P1", P1);
      debugInteger("P2", P2);
      debugInteger("Lc", Lc);
      debugValue("data", public.apdu.data, Lc);
      APDU_ReturnSW(SW_INS_NOT_SUPPORTED);
      break;
  }
}
