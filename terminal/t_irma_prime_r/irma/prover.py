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

import hashlib
import binascii
import time
import irma_util

PAD_ATTR = 16
PAD_MS = PAD_ATTR - 10

PAD_E = PAD_MS + 1
PAD_A = PAD_ATTR
PAD_C = PAD_ATTR

PAD_V_1 = PAD_ATTR
PAD_V_2 = 1

CMD_GEN_KEY = [0x70, 0x01, 0x00, 0x00, 0x00]

CMD_GET_CRED_LIST = [0x80, 0x3A, 0x00, 0x00]
CMD_VERIFY_PIN_ATTR = [0x00, 0x20, 0x00, 0x00, 0x08]
CMD_PROVE_COMMITMENT = [0x80, 0x2A, 0x00, 0x00]
CMD_SELECT = [0x00, 0xA4, 0x04, 0x00, 0x09, 0xF8, 0x49, 0x52, 0x4D, 0x41, 0x63, 0x61, 0x72, 0x64, 0x18]
CMD_PROVE_CREDENTIAL = [0x80, 0x20, 0x00, 0x00, 0x28]
CMD_GET_CHALLENGE = [0x00, 0xB4, 0x00, 0x00]
CMD_GEN_SIG = [0x00, 0xB5, 0x00, 0x00]

CMD_GET_A = [0x80, 0x2B, 0x01, 0x00]
CMD_GET_E = [0x80, 0x2B, 0x02, 0x00]
CMD_GET_V = [0x80, 0x2B, 0x03, 0x00]

CMD_GET_V_P_1 = [0x80, 0x2B, 0xd3, 0x00]
CMD_GET_V_P_2 = [0x80, 0x2B, 0xd4, 0x00]

CMD_GET_V_P_1_2 = [0x80, 0x2B, 0xe3, 0x00]
CMD_GET_V_P_2_2 = [0x80, 0x2B, 0xe4, 0x00]

CMD_GET_A_X = [0x80, 0x2B, 0xAA, 0x00]
CMD_GET_E_X = [0x80, 0x2B, 0xAB, 0x00]
CMD_GET_V_X = [0x80, 0x2B, 0xAC, 0x00]

CMD_GET_ATTR_0 = [0x80, 0x2C, 0x00, 0x00]
CMD_GET_ATTR_1 = [0x80, 0x2C, 0x01, 0x00]
CMD_GET_ATTR_2 = [0x80, 0x2C, 0x02, 0x00]
CMD_GET_ATTR_3 = [0x80, 0x2C, 0x03, 0x00]
CMD_GET_ATTR_4 = [0x80, 0x2C, 0x04, 0x00]
CMD_GET_ATTR_5 = [0x80, 0x2C, 0x05, 0x00]

CMD_GET_MS_COMMITMENT = [0x80, 0x2C, 0x00, 0x02]
CMD_GET_MS_COMMITMENT_2 = [0x80, 0x2C, 0x00, 0x03]

CMD_GET_C = [0x80, 0x2C, 0x00, 0x07]

CMD_GET_C_TILDE = [0x80, 0x2C, 0x00, 0x23]
CMD_GET_H_HAT = [0x80, 0x2C, 0x00, 0x24]

CMD_GET_R_HAT = [0x80, 0x2C, 0x00, 0x06]

CMD_GET_ATTR_0_2 = [0x80, 0x2C, 0x00, 0x01]
CMD_GET_ATTR_1_2 = [0x80, 0x2C, 0x01, 0x01]
CMD_GET_ATTR_2_2 = [0x80, 0x2C, 0x02, 0x01]
CMD_GET_ATTR_3_2 = [0x80, 0x2C, 0x03, 0x01]
CMD_GET_ATTR_4_2 = [0x80, 0x2C, 0x04, 0x01]
CMD_GET_ATTR_5_2 = [0x80, 0x2C, 0x05, 0x01]

PIN_ATTR_DEFAULT = [0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00]
LEN_PC = [0x0A]
LEN_2_NONCE = [0x14]
LEN_NONCE_BITS = 80

STUDENT_CRED = [0x00, 0x64]
CRED_SEL = [0x00, 0x3e] #0x3e
CRED_SEL_1 = [0x00, 0x01]
CRED_SEL_HIDE = [0x00, 0x02]
TIME_STAMP = [0x52, 0xCD, 0x9E, 0xE5]

def proveCommitment(connection, pk_i, CRED_ID, DEBUG): 
  
  NONCE = irma_util.gen_nonce(LEN_NONCE_BITS, 1)
  CONTEXT = irma_util.gen_context(1)
  
  if DEBUG:
    print "SELECT"      
        
  (t, r, n) = irma_util.send_apdu(connection, CMD_SELECT)
  irma_util.print_details(DEBUG, CMD_SELECT, r, t, n)
  
  if DEBUG:
    print "INS_PROVE_CREDENTIAL"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PROVE_CREDENTIAL + CRED_ID + CRED_SEL + CONTEXT + TIME_STAMP)
  irma_util.print_details(DEBUG, CMD_PROVE_CREDENTIAL + CRED_ID + CRED_SEL + CONTEXT + TIME_STAMP, r, t, n)

  if DEBUG:    
    print "INS_PROVE_COMMITMENT"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PROVE_COMMITMENT + LEN_PC + NONCE)
  irma_util.print_details(DEBUG, CMD_PROVE_COMMITMENT + LEN_PC + NONCE, r, t, n)
  
  data, sw1, sw2 = r
  c = irma_util.APDU2integer(data)

  if DEBUG:  
    print "INS_GET_A"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_A)
  irma_util.print_details(DEBUG, CMD_GET_A, r, t, n)

  data, sw1, sw2 = r
  a = irma_util.APDU2integer(data) 

  if DEBUG:
    print "INS_GET_E"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_E)
  irma_util.print_details(DEBUG, CMD_GET_E, r, t, n)

  data, sw1, sw2 = r
  e = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_V"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_V)
  irma_util.print_details(DEBUG, CMD_GET_V, r, t, n)

  data, sw1, sw2 = r
  v = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_ATTR (ms)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_0)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_0, r, t, n)

  data, sw1, sw2 = r
  ms = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_ATTR (m1)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_1)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_1, r, t, n)

  data, sw1, sw2 = r
  m1 = irma_util.APDU2integer(data)

  a = a % pk_i['N']
  ms = ms % pk_i['N'] 
    
  input = {'pChat':c, 'n3':irma_util.APDU2integer(NONCE), 'pAprime':a, 'pEhat':e, 'pVprimeHat':v, 'mHatMs':ms  }
  m = { '1':m1 }
  
  verifier = protocol_ibm12.Verifier(pk_i, irma_util.APDU2integer(CONTEXT))
  return (data, sw1, sw2, verifier.verifyAllIRMA(m, input))

def proveCommitmentHideAll(connection, pk_i, CRED_ID, DEBUG): 
  
  NONCE = irma_util.gen_nonce(LEN_NONCE_BITS, 1)
  CONTEXT = irma_util.gen_context(1)
  
  if DEBUG:
    print "SELECT"      
        
  (t, r, n) = irma_util.send_apdu(connection, CMD_SELECT)
  irma_util.print_details(DEBUG, CMD_SELECT, r, t, n)
  
  if DEBUG:
    print "INS_PROVE_CREDENTIAL"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PROVE_CREDENTIAL + CRED_ID + CRED_SEL_HIDE + CONTEXT + TIME_STAMP)
  irma_util.print_details(DEBUG, CMD_PROVE_CREDENTIAL + CRED_ID + CRED_SEL_HIDE + CONTEXT + TIME_STAMP, r, t, n)

  if DEBUG:    
    print "INS_PROVE_COMMITMENT"

  (t, r, n) = irma_util.send_apdu(connection, CMD_PROVE_COMMITMENT + LEN_PC + NONCE)
  irma_util.print_details(DEBUG, CMD_PROVE_COMMITMENT + LEN_PC + NONCE, r, t, n)
  
  data, sw1, sw2 = r
  c = irma_util.APDU2integer(data)

  if DEBUG:  
    print "INS_GET_A"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_A)
  irma_util.print_details(DEBUG, CMD_GET_A, r, t, n)

  data, sw1, sw2 = r
  a = irma_util.APDU2integer(data) 

  if DEBUG:
    print "INS_GET_E"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_E)
  irma_util.print_details(DEBUG, CMD_GET_E, r, t, n)

  data, sw1, sw2 = r
  e = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_V"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_V)
  irma_util.print_details(DEBUG, CMD_GET_V, r, t, n)

  data, sw1, sw2 = r
  v = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_ATTR (ms)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_0)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_0, r, t, n)

  data, sw1, sw2 = r
  ms = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_ATTR (m1)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_1)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_1, r, t, n)

  data, sw1, sw2 = r
  m1 = irma_util.APDU2integer(data)

  """ XXXX: DEBUG
  if DEBUG:
    print "tilde{C} = (Z^mr)^tilde{m_h} * S^tilde{r}"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_C_TILDE)
  irma_util.print_details(DEBUG, CMD_GET_C_TILDE, r, t, n)

  data, sw1, sw2 = r
  irma_c_tilde = irma_util.APDU2integer(data)
  """
  
  if DEBUG:
    print "C = Z^m S^r"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_C)
  irma_util.print_details(DEBUG, CMD_GET_C, r, t, n)

  data, sw1, sw2 = r
  C = irma_util.APDU2integer(data)

  if DEBUG:
    print "hat{r}"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_R_HAT)
  irma_util.print_details(DEBUG, CMD_GET_R_HAT, r, t, n)

  data, sw1, sw2 = r
  r_hat = irma_util.APDU2integer(data)

  if DEBUG:
    print "hat{h}"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_H_HAT)
  irma_util.print_details(DEBUG, CMD_GET_H_HAT, r, t, n)

  data, sw1, sw2 = r
  h_hat = irma_util.APDU2integer(data)
  
  a = a % pk_i['N']
  C = C % pk_i['N']

  ms = ms % pk_i['N'] 
  m1 = m1 % pk_i['N'] 

  print "RECEIVED"
  
  print "C", C
  print "r_hat", r_hat
  print "ms", ms
  print "m", m1
  
  # Calculo de \tilde{Co}
  
  print "SIMULATION Co"

  # SIMULATION:
  # C, Co, hat_r
  """ 
  mi_m = integer(int("00000000000000000000000000000000000000000000000076616c6964617465", 16))
  mi_r = integer(int("0a0a0a0a0a0a0a0a0a0a0a0a00000000000000000000112abcddc31Acd010643", 16))
  mi_m_h = integer(int("000000000000000000000000000000000000000000000000000000000000000F", 16))
  mi_m_r = integer(int("0000000000000000000000000000000000000000000000000000000000000002", 16))
  
  m_tilde  = integer(int("0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101", 16))
  r_tilde  = integer(int("0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202", 16))
  ms_tilde = integer(int("0303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303", 16))
  mh_tilde = integer(int("0404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404", 16))

  mi_hat_m = m_tilde + mi_m*c
  mi_hat_r = r_tilde + mi_r*c
  mi_hat_mh = (mh_tilde + mi_m_h*c)
  
  mi_Co = ((pk_i['Z'] ** m_tilde) * (pk_i['S'] ** r_tilde)) % pk_i['N']
  mi_C  = ((pk_i['Z'] ** mi_m) * (pk_i['S'] ** mi_r)) % pk_i['N']
    
  print "mi_m", mi_m
  print "mi_r", mi_r
  print "C = Z^m S^r", mi_C
  print "Co = Z^tilde_m S^tilde_r", hex(int(mi_Co))
  #print "Co = C^(c * -1) Z^hat_m S^hat_r", hex(int(mi_Co_calculado))

  print "mi hat m", hex(int(mi_hat_m))
  print "mi hat r", hex(int(mi_hat_r)) 

  # constantes
  """
  rev_attr_1 = pk_i['Z'] ** 2 % pk_i['N']
  print "const - rev_attr_1", hex(int(rev_attr_1))
  

  #print "SIMULATION tilde{C}"

  #C = (pk_i['Z'] ** 30) * (pk_i['S'] ** mi_r)
  
  #C_tilde = (((rev_attr_1) ** mh_tilde) * (pk_i['S'] ** r_tilde)) % pk_i['N']

  #print "su c tilde", C_tilde
  
  #print "h_hat tarjeta", h_hat
  #print "h_hat mia", mi_hat_mh

  #C_tilde_prima = ((C ** (-1 * c)) * ((pk_i['Z'] ** 2) ** (mh_tilde + c*15)) * (pk_i['S'] ** (r_tilde + c*mi_r))) % pk_i['N']
  #print "mi c tilde", C_tilde_prima
  #print "mi c tilde - hex", hex(int(C_tilde_prima))
  #print "tarjeta - hex", hex(int(irma_c_tilde))  

  # \tilde{Co}

  mi_Co_calculado = (C ** (-1 * c) ) * (pk_i['Z'] ** m1) * (pk_i['S'] ** r_hat)

  # \tilde{C}
  
  C_tilde_prima = ((C ** (-1 * c)) * ((pk_i['Z'] ** 2) ** h_hat) * (pk_i['S'] ** r_hat)) % pk_i['N']
    
  input = { 'pChat':c, 'n3':irma_util.APDU2integer(NONCE), 'pAprime':a, 'pEhat':e, 'pVprimeHat':v, 'mHatMs':ms, 'C':C, 'Co':mi_Co_calculado, 'C_t':C_tilde_prima }
  m = { '1':m1 }
  
  verifier = protocol_ibm12.Verifier(pk_i, irma_util.APDU2integer(CONTEXT))
  return (data, sw1, sw2, verifier.verifyHideAllIRMA_PRIME(m, input))

