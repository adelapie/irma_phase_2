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
import time

# constants

CMD_VERIFY_PIN_ATTR = [0x00, 0x20, 0x00, 0x00, 0x08]
CMD_VERIFY_PIN_ADMI = [0x00, 0x20, 0x00, 0x01, 0x08]
CMD_SELECT_IRMA = [0x00, 0xA4, 0x04, 0x0C, 0x09, 0xF8, 0x49, 0x52, 0x4D, 0x41, 0x63, 0x61, 0x72, 0x64]

PIN_ATTR_DEFAULT = [0x30, 0x30, 0x30, 0x30]
PIN_ADMI_DEFAULT = [0x30, 0x30, 0x30, 0x30, 0x30, 0x30]

def timing_val(func):
  def wrapper(*arg,**kw):
    '''source: http://www.daniweb.com/code/snippet368.html'''
    t1 = time.time()
    res = func(*arg,**kw)
    t2 = time.time()
    return (t2-t1),res,func.func_name
  return wrapper  

#@timing_val
def verifyPinAttr(connection): 

  DATA2 = [0x00, 0x20, 0x00, 0x00, 0x08, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00]

  data, sw1, sw2 = connection.transmit( CMD_SELECT_IRMA )
  data, sw1, sw2 = connection.transmit( CMD_VERIFY_PIN_ATTR + PIN_ATTR_DEFAULT + [0x00, 0x00, 0x00, 0x00])
  
  return (data, sw1, sw2)

#@timing_val
def verifyPinAdmin(connection): 

  data, sw1, sw2 = connection.transmit( CMD_SELECT_IRMA )
  data, sw1, sw2 = connection.transmit( CMD_VERIFY_PIN_ADMI + PIN_ADMI_DEFAULT + [0x00, 0x00])
  
  return (data, sw1, sw2)

                       
