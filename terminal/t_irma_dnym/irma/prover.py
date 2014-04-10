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

CMD_GET_NYM_1 = [0x80, 0x2C, 0x00, 0x04]
CMD_GET_NYM_2 = [0x80, 0x2C, 0x00, 0x05]
CMD_GET_NYM_R = [0x80, 0x2C, 0x00, 0x06]

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
CRED_SEL = [0x00, 0x3E]
CRED_SEL_1 = [0x00, 0x01]
CRED_SEL_HIDE = [0x00, 0x02]
TIME_STAMP = [0x52, 0xCD, 0x9E, 0xE5]

def proveDNYM(connection, pk_i, CRED_ID, DEBUG, Rdom, Rr, r1): 
  
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

  if DEBUG:
    print "INS_GET_ATTR (m2)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_2)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_2, r, t, n)

  data, sw1, sw2 = r
  m2 = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_ATTR (m3)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_3)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_3, r, t, n)

  data, sw1, sw2 = r
  m3 = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_ATTR (m4)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_4)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_4, r, t, n)

  data, sw1, sw2 = r
  m4 = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_ATTR (m5)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_5)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_5, r, t, n)

  data, sw1, sw2 = r
  m5 = irma_util.APDU2integer(data)

  if DEBUG:
    print "MS Ro^ms"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_MS_COMMITMENT_2)
  irma_util.print_details(DEBUG, CMD_GET_MS_COMMITMENT_2, r, t, n)

  data, sw1, sw2 = r
  m_com_s = irma_util.APDU2integer(data)

  if DEBUG:
    print "NYM - 1"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_NYM_1)
  irma_util.print_details(DEBUG, CMD_GET_NYM_1, r, t, n)

  data, sw1, sw2 = r
  NYM_1 = irma_util.APDU2integer(data)
  
  if DEBUG:
    print "NYM - R"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_NYM_R)
  irma_util.print_details(DEBUG, CMD_GET_NYM_R, r, t, n)

  data, sw1, sw2 = r
  NYM_R = irma_util.APDU2integer(data)

  a = a % pk_i['N']
  ms = ms % pk_i['N'] 
  m_com_s = m_com_s % pk_i['N'] 

  MS = m_com_s
  domNYM = Rdom % pk_i['N']
  
  That1 = (MS ** (-1 * c)) % pk_i['N']
  That2 = (domNYM ** ms) % pk_i['N']
  ThatB = (That1 * That2) % pk_i['N']

  Rr = Rr % pk_i['N']

  NYM_1 = NYM_1 % pk_i['N'] 
  NYM_R = NYM_R % pk_i['N']

  d1 = (NYM_1 ** (-1 * c)) % pk_i['N']
  d2 = (pk_i['Ro'] ** ms) % pk_i['N']
  d3 = (Rr ** NYM_R) % pk_i['N']
  
  tilde_d_nym = (d1 * d2 * d3) % pk_i['N']

  input = {'pChat':c, 'n3':irma_util.APDU2integer(NONCE), 'pAprime':a, 'pEhat':e, 'pVprimeHat':v, 'mHatMs':ms, 'm_com_s':m_com_s, 'DOM1':ThatB, 'NYM1':tilde_d_nym, 'NYM2':NYM_1}
  m = { '1':m1, '2':m2, '3':m3, '4':m4, '5':m5 }
      
  verifier = protocol_ibm12.Verifier(pk_i, irma_util.APDU2integer(CONTEXT))
  return (data, sw1, sw2, verifier.verifyAllIRMA_NYM(m, input))

def proveDNYM_H(connection, pk_i, CRED_ID, DEBUG, Rdom, Rr, r1): 
  
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

  if DEBUG:
    print "INS_GET_ATTR (m2)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_2)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_2, r, t, n)

  data, sw1, sw2 = r
  m2 = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_ATTR (m3)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_3)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_3, r, t, n)

  data, sw1, sw2 = r
  m3 = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_ATTR (m4)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_4)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_4, r, t, n)

  data, sw1, sw2 = r
  m4 = irma_util.APDU2integer(data)

  if DEBUG:
    print "INS_GET_ATTR (m5)"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_ATTR_5)
  irma_util.print_details(DEBUG, CMD_GET_ATTR_5, r, t, n)

  data, sw1, sw2 = r
  m5 = irma_util.APDU2integer(data)

  if DEBUG:
    print "MS Ro^ms"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_MS_COMMITMENT_2)
  irma_util.print_details(DEBUG, CMD_GET_MS_COMMITMENT_2, r, t, n)

  data, sw1, sw2 = r
  m_com_s = irma_util.APDU2integer(data)

  if DEBUG:
    print "NYM - 1"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_NYM_1)
  irma_util.print_details(DEBUG, CMD_GET_NYM_1, r, t, n)

  data, sw1, sw2 = r
  NYM_1 = irma_util.APDU2integer(data)
  
  if DEBUG:
    print "NYM - R"

  (t, r, n) = irma_util.send_apdu(connection, CMD_GET_NYM_R)
  irma_util.print_details(DEBUG, CMD_GET_NYM_R, r, t, n)

  data, sw1, sw2 = r
  NYM_R = irma_util.APDU2integer(data)

  a = a % pk_i['N']
  ms = ms % pk_i['N'] 
  
  m2 = m2 % pk_i['N'] 
  m3 = m3 % pk_i['N'] 
  m4 = m4 % pk_i['N'] 
  m5 = m5 % pk_i['N'] 
  
  m_com_s = m_com_s % pk_i['N'] 

  MS = m_com_s
  domNYM = Rdom % pk_i['N']
  
  That1 = (MS ** (-1 * c)) % pk_i['N']
  That2 = (domNYM ** ms) % pk_i['N']
  ThatB = (That1 * That2) % pk_i['N']

  Rr = Rr % pk_i['N']

  NYM_1 = NYM_1 % pk_i['N'] 
  NYM_R = NYM_R % pk_i['N']

  d1 = (NYM_1 ** (-1 * c)) % pk_i['N']
  d2 = (pk_i['Ro'] ** ms) % pk_i['N']
  d3 = (Rr ** NYM_R) % pk_i['N']
  
  tilde_d_nym = (d1 * d2 * d3) % pk_i['N']

  input = {'pChat':c, 'n3':irma_util.APDU2integer(NONCE), 'pAprime':a, 'pEhat':e, 'pVprimeHat':v, 'mHatMs':ms, 'm_com_s':m_com_s, 'DOM1':ThatB, 'NYM1':tilde_d_nym, 'NYM2':NYM_1}
  m = { '1':m1, '2':m2, '3':m3, '4':m4, '5':m5 }
      
  verifier = protocol_ibm12.Verifier(pk_i, irma_util.APDU2integer(CONTEXT))
  return (data, sw1, sw2, verifier.verifyAllIRMA_NYM_H(m, input))



