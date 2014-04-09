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

from irma import management
from irma import irma_util
from irma import issuer
from irma import prover

import binascii
import json
import time
import sys

def issuer_pk_to_file(pk_i, file):
  pk_str = {}
  R_str = {}
    
  R = pk_i['R']
    
  for i in range(1, len(R) + 1): 
    R_str[str(i)] = int(R[str(i)])
  
  pk_str['R'] =  R_str
  pk_str['N'] =  int(pk_i['N'])
  pk_str['S'] =  int(pk_i['S'])
  pk_str['Z']=   int(pk_i['Z'])
  pk_str['Ro'] = int(pk_i['Ro'])
  
  with open(file, 'w') as f:
      json.dump(pk_str, f)

def file_to_issuer_pk(file):

  with open(file) as f:
    pk_str = json.load(f)

  pk_i = {}
  R = {}
  
  R_str = pk_str['R']

  pk_i['N'] =  integer(pk_str['N'])

  for i in range(1, len(R_str) + 1): 
    R[str(i)] = integer(R_str[str(i)]) % pk_i['N']
    
  pk_i['R'] = R
  pk_i['S'] =  integer(pk_str['S']) % pk_i['N']
  pk_i['Z'] =  integer(pk_str['Z']) % pk_i['N']
  pk_i['Ro'] = integer(pk_str['Ro']) % pk_i['N']

  return pk_i

def issuer_sk_to_file(sk_i, file):
  sk_str = {}
  
  sk_str['p'] =  int(sk_i['p'])
  sk_str['q'] =  int(sk_i['q'])
  
  with open(file, 'w') as f:
      json.dump(sk_str, f)

def file_to_issuer_sk(file):

  with open(file) as f:
    sk_str = json.load(f)

  sk_i = {}
    
  sk_i['p'] =  integer(sk_str['p']) 
  sk_i['q'] =  integer(sk_str['q']) 

  return sk_i
  
if __name__ == '__main__':
  
  r=readers()
  connection = r[0].createConnection()
  connection.connect()
  
  pk_i_1 = file_to_issuer_pk("issuer_1_pk.json")
  sk_i_1 = file_to_issuer_sk("issuer_1_sk.json")

  pk_i_2 = file_to_issuer_pk("issuer_2_pk.json")
  sk_i_2 = file_to_issuer_sk("issuer_2_sk.json")

  m1_1 = integer(int("00000000000000000000000000000000000000000000000076616c6964617465", 16)) # validate
  m2_1 = integer(int("0000000000000000000000000000000000000000000007369676e61a74757265", 16)) # signature
  m3_1 = integer(int("0000000000000000000000000000000000000000000000000000000064617465", 16)) # date
  m4_1 = integer(int("0000000000000000000000000000000000000000000000000000006f74686572", 16)) # other
  m5_1 = integer(int("0000000000000000000000000000000000000000000000000000000000619410", 16)) # exp. date

  m_student_1 = { '1':m1_1, '2':m2_1, '3':m3_1, '4':m4_1, '5':m5_1 }
  
  (c1, c2) = issuer.issueCredentialX(connection, pk_i_1, sk_i_1, m_student_1, [0x00, 0x01], 0)
  print "Issuing root credential:", c1, c2
 
  #(t, r, n, ok_prove) = prover.proveCommitment(connection, pk_i_1, [0x00, 0x01], 1)
  #print "Verifying CRED #1:", ok_prove

  (t, r, n, ok_prove) = prover.proveCommitmentHideAll(connection, pk_i_1, [0x00, 0x01], 1)
  print "Verifying CRED #1:", ok_prove
