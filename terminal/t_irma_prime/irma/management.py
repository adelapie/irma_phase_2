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

from smartcard.System import readers
from smartcard.util import toHexString
from functools import wraps
from irma import pin
import time

# constants

CMD_GET_CRED_LIST = [0x80, 0x3A, 0x00, 0x00]
CMD_SEL_CRED = [0x80, 0x30, 0x00, 0x01]

CMD_VERIFY_PIN_ATTR = [0x00, 0x20, 0x00, 0x00, 0x08]

PIN_ATTR_DEFAULT = [0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00]

def timing_val(func):
  def wrapper(*arg,**kw):
    '''source: http://www.daniweb.com/code/snippet368.html'''
    t1 = time.time()
    res = func(*arg,**kw)
    t2 = time.time()
    return (t2-t1),res,func.func_name
  return wrapper  

@timing_val
def getAttribute(): 
  r=readers()
  connection = r[0].createConnection()
  connection.connect()
  
  GETATTR = [0x80, 0x2B, 0x00, 0x00]

  data, sw1, sw2 = connection.transmit( GETATTR )
  return (data, sw1, sw2)

@timing_val
def getCredentials(connection): 

  pin.verifyPinAdmin(connection)
  data, sw1, sw2 = connection.transmit( CMD_GET_CRED_LIST )
  return (data, sw1, sw2)

                       
@timing_val
def selectCredential(connection): 

  (p1, p2, p3) = pin.verifyPinAdmin(connection)
  print "select cred"
  
  (b1, b2, b3) = connection.transmit( CMD_SEL_CRED )

  print b1
  print hex(b2)
  print hex(b3)
  
  
  #return (data, sw1, sw2)

                       
