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

from Crypto.Cipher import AES

import hashlib
import binascii
import time

APDU_OK = [0x90, 0x00]
APDU_ERR = [0x67, 0x00]

def hexString2integer(val):
  return integer(int(val, 16))  

def APDU2integer(val):
  v = toHexString(val).replace(" ", "")
  return hexString2integer(v)

def hexString2APDU(val):
  st = val.decode("hex")
  return map(ord, st)

def timing_val(func):
  def wrapper(*arg,**kw):
    '''source: http://www.daniweb.com/code/snippet368.html'''
    t1 = time.time()
    res = func(*arg,**kw)
    t2 = time.time()
    return (t2-t1),res,func.func_name
  return wrapper  

@timing_val
def send_apdu(connection, apdu):
  return connection.transmit(apdu)

def print_details(debug, apdu, result, t, n):
  (data, sw1, sw2) = result

  if debug == 1:
    print "C =", toHexString(apdu)
    print "D =",toHexString(data)
    print "R = %x %x" % (sw1, sw2)
    print '%s took %0.3f ms.' % (n, t*1000.)

def gen_nonce(len_nonce, apdu):
  n3 = integer(randomBits(len_nonce))
  n3 = int(n3)
  
  n3_hex = int2hex(n3)
  
  if apdu == 1:
    return map(ord, n3_hex)
  else:
    return n3_hex

def gen_context(apdu):
  n3 = integer(randomBits(256))
  n3 = int(n3)
  
  n3_hex = int2hex(n3)
  
  if apdu == 1:
    return map(ord, n3_hex)
  else:
    return n3_hex

def int2hex(val):
  val_hex = format(val, 'x')
  length = len(val_hex)
  encoded = val_hex.zfill(length+length%2)

  hex_enc = encoded.decode('hex')

  return hex_enc

def int2APDU(val):
  val_hex = format(val, 'x')
  length = len(val_hex)
  encoded = val_hex.zfill(length+length%2)
  
  return map(ord, encoded.decode('hex'))

def isAPDUSW1SW2(sw1, sw2, val):
  test = [sw1, sw2]
  
  return set(test) == set(val)

def dec_att(k, ct, pad):

  # TODO: check MAC

  key = k.decode("hex")
            
  aes = AES.new(key, AES.MODE_ECB)
      
  val_hex = format(int(ct), 'x')
  length = len(val_hex)
  encoded = val_hex.zfill(length+length%2)
    
  pt = aes.decrypt(encoded.decode("hex"))
  pt = pt[:-pad]
      
  c = int(pt.encode("hex"), 16)

  return c
  