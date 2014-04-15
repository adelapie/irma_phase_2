"""
Copyright (c) 2013 Antonio de la Piedra
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
  
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
   
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""   

from charm.core.math.integer import integer,isPrime,random,randomPrime,randomBits,bitsize
from charm.toolbox.conversion import Conversion
from smartcard.CardConnection import CardConnection
from smartcard.System import readers
from smartcard.util import toHexString
from functools import wraps
from irma import pin
from idemix import protocol_ibm12
from copy import deepcopy

import irma_util
import binascii
import time
import sys

context = integer(randomBits(256))

# constants

CMD_SELECT = [0x00, 0xA4, 0x04, 0x00, 0x09, 0xF8, 0x49, 0x52, 0x4D, 0x41, 0x63, 0x61, 0x72, 0x64, 0x18]
CMD_GET_CRED_LIST = [0x80, 0x3A, 0x00, 0x00]
CMD_VERIFY_PIN_ATTR = [0x00, 0x20, 0x00, 0x00, 0x08]

PIN_ATTR_DEFAULT = [0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00]

CMD_PROVE_COMMITMENT = [0x80, 0x2A, 0x00, 0x00]
LEN_PC = [0x0A]

CMD_ISSUE_CRED = [0x80, 0x10, 0x00, 0x00, 0x2B]

CMD_PUBLIC_KEY_N = [0x80, 0x11, 0x00, 0x00, 0x80]
CMD_PUBLIC_KEY_Z = [0x80, 0x11, 0x02, 0x00, 0x80]
CMD_PUBLIC_KEY_S = [0x80, 0x11, 0x01, 0x00, 0x80]

CMD_PUBLIC_KEY_R0 = [0x80, 0x11, 0x03, 0x00, 0x80]
CMD_PUBLIC_KEY_R1 = [0x80, 0x11, 0x03, 0x01, 0x80]
CMD_PUBLIC_KEY_R2 = [0x80, 0x11, 0x03, 0x02, 0x80]
CMD_PUBLIC_KEY_R3 = [0x80, 0x11, 0x03, 0x03, 0x80]
CMD_PUBLIC_KEY_R4 = [0x80, 0x11, 0x03, 0x04, 0x80]
CMD_PUBLIC_KEY_R5 = [0x80, 0x11, 0x03, 0x05, 0x80]

CMD_ATTR_1 = [0x80, 0x12, 0x01, 0x00]
CMD_ATTR_2 = [0x80, 0x12, 0x02, 0x00]
CMD_ATTR_3 = [0x80, 0x12, 0x03, 0x00]
CMD_ATTR_4 = [0x80, 0x12, 0x04, 0x00]
CMD_ATTR_5 = [0x80, 0x12, 0x05, 0x00]

CMD_ISSUE_SIGNATURE_1 = [0x80, 0x1D, 0x01, 0x00, 0x80]
CMD_ISSUE_SIGNATURE_2 = [0x80, 0x1D, 0x02, 0x00, 0x4B]
CMD_ISSUE_SIGNATURE_3 = [0x80, 0x1D, 0x03, 0x00, 0xD5]
CMD_ISSUE_SIGNATURE_4 = [0x80, 0x1D, 0x04, 0x00, 0x20]
CMD_ISSUE_SIGNATURE_5 = [0x80, 0x1D, 0x05, 0x00, 0x80]

CMD_ISSUE_COMMITMENT = [0x80, 0x1A, 0x00, 0x00, 0x0A]

CMD_COMMIT_PROOF_A = [0x80, 0x1B, 0x01, 0x00]
CMD_COMMIT_PROOF_V = [0x80, 0x1B, 0x02, 0x00]
CMD_COMMIT_PROOF_S = [0x80, 0x1B, 0x03, 0x00]

CMD_CHALLENGE = [0x80, 0x1C, 0x00, 0x00]
CMD_VERIFY = [0x80, 0x1F, 0x00, 0x00]

STUDENT_CRED = [0x00, 0x64]
PARAM_CRED = [0x00, 0x01, 0x00, 0x00, 0x00] #0x01 
PARAM_CRED_1_ATTR = [0x00, 0x01, 0x00, 0x00, 0x00] 
CONTEXT_DEF = [0x4D, 0x2F, 0x73, 0x2C, 0xF0, 0x88, 0x6B, 0xDC, 0x28, 0x89, 0xA8, 0xDC, 0x84, 0xDE, 0xC7, 0xD4, 0x0D, 0x5F, 0xDF, 0xA4, 0x14, 0x8D, 0x63, 0x5F, 0xB2, 0x77, 0x7A, 0xD8, 0xDC, 0xD4, 0x35, 0x49]  
FINAL_CRED = [0x52, 0xD3, 0xBB, 0x91]

CMD_ISSUE_C = [0x80, 0x1B, 0x01, 0x00]
CMD_ISSUE_V = [0x80, 0x1B, 0x02, 0x00]
CMD_ISSUE_S = [0x80, 0x1B, 0x03, 0x00]
CMD_CHALLENGE = [0x80, 0x1C, 0x00, 0x00]

LEN_NONCE_BITS = 80

def issueCredentialX(connection, pk_i, sk_i, m, CRED_ID, DEBUG): 

  R = pk_i['R']
  M = m

  if DEBUG:  
    print "SELECT"

  (t, r, n) = irma_util.send_apdu(connection, CMD_SELECT)
  irma_util.print_details(DEBUG, CMD_SELECT, r, t, n)
  
  if DEBUG:
    print "CRED PIN VERIFY"

  r = pin.verifyPinAttr(connection)
  irma_util.print_details(DEBUG, CMD_SELECT, r, t, n)
  
  if DEBUG:
    print "INS_ISSUE_CREDENTIAL"
    
  context_IRMA = toHexString(CONTEXT_DEF).replace(" ", "")  
  
  (t, r, n) = irma_util.send_apdu(connection, CMD_ISSUE_CRED + CRED_ID + PARAM_CRED + CONTEXT_DEF + FINAL_CRED)
  irma_util.print_details(DEBUG, CMD_ISSUE_CRED + CRED_ID + PARAM_CRED + CONTEXT_DEF + FINAL_CRED, r, t, n)

  if DEBUG:  
    print "INS_PUBLIC_KEY"

  # N
  if DEBUG:  
    print "N:"
  
  (t, r, n) = irma_util.send_apdu(connection, CMD_PUBLIC_KEY_N + irma_util.int2APDU(int(pk_i['N'])))  
  irma_util.print_details(DEBUG, CMD_PUBLIC_KEY_N + irma_util.int2APDU(int(pk_i['N'])), r, t, n)

  # Z
  
  if DEBUG:    
    print "Z:"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PUBLIC_KEY_Z + irma_util.int2APDU(int(pk_i['Z'])))  
  irma_util.print_details(DEBUG, CMD_PUBLIC_KEY_Z + irma_util.int2APDU(int(pk_i['Z'])), r, t, n)

  # S
  if DEBUG:  
    print "S:"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PUBLIC_KEY_S + irma_util.int2APDU(int(pk_i['S'])))  
  irma_util.print_details(DEBUG, CMD_PUBLIC_KEY_S + irma_util.int2APDU(int(pk_i['S'])), r, t, n)

  # R
  if DEBUG:  
    print "R0:"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PUBLIC_KEY_R0 + irma_util.int2APDU(int(pk_i['Ro'])))  
  irma_util.print_details(DEBUG, CMD_PUBLIC_KEY_R0 + irma_util.int2APDU(int(pk_i['Ro'])), r, t, n)

  if DEBUG:  
    print "R1:"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PUBLIC_KEY_R1 + irma_util.int2APDU(int(R['1'])))
  irma_util.print_details(DEBUG, CMD_PUBLIC_KEY_R1 + irma_util.int2APDU(int(R['1'])), r, t, n)
  
  """
  if DEBUG:  
    print "R2"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PUBLIC_KEY_R2 + irma_util.int2APDU(int(R['2'])))  
  irma_util.print_details(DEBUG, CMD_PUBLIC_KEY_R2 + irma_util.int2APDU(int(R['2'])), r, t, n)

  if DEBUG:  
    print "R3"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PUBLIC_KEY_R3 + irma_util.int2APDU(int(R['3'])))  
  irma_util.print_details(DEBUG, CMD_PUBLIC_KEY_R3 + irma_util.int2APDU(int(R['3'])), r, t, n)

  if DEBUG:  
    print "R4"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PUBLIC_KEY_R4 + irma_util.int2APDU(int(R['4'])))  
  irma_util.print_details(DEBUG, CMD_PUBLIC_KEY_R4 + irma_util.int2APDU(int(R['4'])), r, t, n)

  if DEBUG:  
    print "R5"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PUBLIC_KEY_R5 + irma_util.int2APDU(int(R['5'])))
  irma_util.print_details(DEBUG, CMD_PUBLIC_KEY_R5 + irma_util.int2APDU(int(R['5'])), r, t, n)
  """
  
  if DEBUG:
    print "ATTRIBUTES"
    print "ATTR_0:"

  str_ins = "801201002000000000000000000000000000000000000000000000000076616c6964617465".decode("hex")

  CMD_PUBLIC_KEY_ATTR_0 = map(ord, str_ins)
  
  if DEBUG:
    print toHexString(CMD_PUBLIC_KEY_ATTR_0)

  data, sw1, sw2 = connection.transmit(CMD_PUBLIC_KEY_ATTR_0)
  
  """
  if DEBUG:
  
    print "D =",toHexString(data)
    print "R = %x %x" % (sw1, sw2)

    print "ATTR_1:"

  str_ins = "80120200200000000000000000000000000000000000000000000007369676e61a74757265".decode("hex")

  CMD_PUBLIC_KEY_ATTR_1 = map(ord, str_ins)
  
  if DEBUG:
    print toHexString(CMD_PUBLIC_KEY_ATTR_1)

  data, sw1, sw2 = connection.transmit(CMD_PUBLIC_KEY_ATTR_1)

  if DEBUG:

    print "D =",toHexString(data)
    print "R = %x %x" % (sw1, sw2)

    print "ATTR_2"

  str_ins = "80120300200000000000000000000000000000000000000000000000000000000064617465".decode("hex")
  
  CMD_PUBLIC_KEY_ATTR_2 = map(ord, str_ins)
  
  if DEBUG:
    print toHexString(CMD_PUBLIC_KEY_ATTR_2)

  data, sw1, sw2 = connection.transmit(CMD_PUBLIC_KEY_ATTR_2)
  
  if DEBUG:

    print "D =",toHexString(data)
    print "R = %x %x" % (sw1, sw2)

    print "ATTR_3"

  str_ins = "80120400200000000000000000000000000000000000000000000000000000006f74686572".decode("hex")

  CMD_PUBLIC_KEY_ATTR_3 = map(ord, str_ins)
  
  if DEBUG:
    print toHexString(CMD_PUBLIC_KEY_ATTR_3)

  data, sw1, sw2 = connection.transmit(CMD_PUBLIC_KEY_ATTR_3)

  if DEBUG:
    print "D =",toHexString(data)
    print "R = %x %x" % (sw1, sw2)

  if DEBUG:

    print "ATTR_4"

  str_ins = "80120500200000000000000000000000000000000000000000000000000000000000619410".decode("hex")

  CMD_PUBLIC_KEY_ATTR_4 = map(ord, str_ins)
  
  if DEBUG:
    print toHexString(CMD_PUBLIC_KEY_ATTR_4)

  data, sw1, sw2 = connection.transmit(CMD_PUBLIC_KEY_ATTR_4)
  
  if DEBUG:

    print "D =",toHexString(data)
    print "R = %x %x" % (sw1, sw2)
  """
  
  if DEBUG:  
    print "ISSUE_COMMITMENT"
  
  NONCE_1 = irma_util.gen_nonce(LEN_NONCE_BITS, 1)
  
  (t, r, n) = irma_util.send_apdu(connection, CMD_ISSUE_COMMITMENT + NONCE_1)
  irma_util.print_details(DEBUG, CMD_ISSUE_COMMITMENT + NONCE_1, r, t, n)

  (data, t1, t2) = r

  U = irma_util.APDU2integer(data) % pk_i['N']

  if DEBUG:      
    print "C"  
  
  (t, r, n) = irma_util.send_apdu(connection, CMD_ISSUE_C)
  irma_util.print_details(DEBUG, CMD_ISSUE_C, r, t, n)

  (data, t1, t2) = r

  c = irma_util.APDU2integer(data)

  if DEBUG:  
    print "V"  
  
  (t, r, n) = irma_util.send_apdu(connection, CMD_ISSUE_V)
  irma_util.print_details(DEBUG, CMD_ISSUE_V, r, t, n)

  (data, t1, t2) = r

  v = irma_util.APDU2integer(data)

  if DEBUG:  
    print "S"  

  (t, r, n) = irma_util.send_apdu(connection, CMD_ISSUE_S)
  irma_util.print_details(DEBUG, CMD_ISSUE_S, r, t, n)

  (data, t1, t2) = r
  
  s = irma_util.APDU2integer(data)

  if DEBUG:  
    print "CHALLENGE"  
  
  (t, r, n) = irma_util.send_apdu(connection, CMD_CHALLENGE)
  irma_util.print_details(DEBUG, CMD_CHALLENGE, r, t, n)

  (data, t1, t2) = r

  nonce_2 = irma_util.APDU2integer(data)
  
  # U, c, v, s, nonce_2

  nonce_1 = irma_util.APDU2integer(NONCE_1)
    
  p1 = { 'c':c, 'vPrimeHat':v, 'sHat':s, 'U':U }      
      
  issuer_irma_2 = protocol_ibm12.Issuer(1, 1, 1, 1024, irma_util.hexString2integer(context_IRMA))
  issuer_irma_2.setKeyPair(pk_i, sk_i)

  P1_check = issuer_irma_2.roundNumber1IRMA(p1, nonce_1)

  (partSig, P2) = issuer_irma_2.roundNumber2IRMA(p1['U'], M, nonce_2)

  if DEBUG:  
    print "ISSUE_SIGNATURE - A"

  (t, r, n) = irma_util.send_apdu(connection, CMD_ISSUE_SIGNATURE_1 + irma_util.int2APDU(int(partSig['A'])))
  irma_util.print_details(DEBUG, CMD_ISSUE_SIGNATURE_1 + irma_util.int2APDU(int(partSig['A'])), r, t, n)

  if DEBUG:  
    print "ISSUE_SIGNATURE - E"

  (t, r, n) = irma_util.send_apdu(connection, CMD_ISSUE_SIGNATURE_2 + irma_util.int2APDU(int(partSig['e'])))
  irma_util.print_details(DEBUG, CMD_ISSUE_SIGNATURE_2 + irma_util.int2APDU(int(partSig['e'])), r, t, n)

  if DEBUG:  
    print "ISSUE_SIGNATURE - v"

  (t, r, n) = irma_util.send_apdu(connection, CMD_ISSUE_SIGNATURE_3 + irma_util.int2APDU(int(partSig['vPrimePrime'])))
  irma_util.print_details(DEBUG, CMD_ISSUE_SIGNATURE_3 + irma_util.int2APDU(int(partSig['vPrimePrime'])), r, t, n)

  if DEBUG:  
    print "ISSUE_SIGNATURE - c"

  hex_c_prime = P2['cPrime']

  (t, r, n) = irma_util.send_apdu(connection, CMD_ISSUE_SIGNATURE_4 + irma_util.hexString2APDU(hex_c_prime))
  irma_util.print_details(DEBUG, CMD_ISSUE_SIGNATURE_4 + irma_util.hexString2APDU(hex_c_prime), r, t, n)

  (data, r1, r2) = r

  if irma_util.isAPDUSW1SW2(r1, r2, irma_util.APDU_ERR):
    print "BUG C, 6700"
    print "cPrime", P2['cPrime']
    
    sys.exit(0)

  if DEBUG:  
    print "ISSUE_SIGNATURE - Se"

  (t, r, n) = irma_util.send_apdu(connection, CMD_ISSUE_SIGNATURE_5 + irma_util.int2APDU(int(P2['Se'])))
  irma_util.print_details(DEBUG, CMD_ISSUE_SIGNATURE_5 + irma_util.int2APDU(int(P2['Se'])), r, t, n)

  # fix size all XXXX

  if DEBUG:  
    print "VERIFY ISSUE"

  (t, r, n) = irma_util.send_apdu(connection, CMD_VERIFY)
  irma_util.print_details(DEBUG, CMD_VERIFY, r, t, n)
 
  (data, r1, r2) = r
      
  return (P1_check, irma_util.isAPDUSW1SW2(r1, r2, irma_util.APDU_OK))
  
