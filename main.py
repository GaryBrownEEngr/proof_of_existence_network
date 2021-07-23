
import math
import time
import datetime
import numpy as np
import struct

import pycoin
import hashlib
import unittest

import cryptography
from cryptography.hazmat.primitives.asymmetric import ec as elliptic_curve
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import cryptography.hazmat.primitives.asymmetric as asymmetric


"""
 8 bytes: UTC time to nearest second
64 bytes: SHA3-512 hash of previous block
list of 
"""




class Signing:
    """
    example extracted from: https://medium.com/asecuritysite-when-bob-met-alice/ecdsa-python-and-hazmat-2eee60caab34
    """
    def __init__(self, password=1):
        self.private_key = elliptic_curve.generate_private_key(elliptic_curve.SECP256K1())

        #private_vals = private_key.private_numbers()
        #no_bits=private_vals.private_value.bit_length()
        #print (f"Private key value: {private_vals.private_value}. Number of bits {no_bits}")
        self.public_key = self.private_key.public_key()
        #pub=public_key.public_numbers()
    
    
    
    def sign(self):
        data = b'abc'
        try:
            signature = self.private_key.sign(data, elliptic_curve.ECDSA(hashes.SHA3_512()))
            print(len(signature), signature)
            a = asymmetric.utils.decode_dss_signature(signature)
            print(a)
            
            #print("Good Signature: ",binascii.b2a_hex(signature).decode())
            self.public_key.verify(signature, data, elliptic_curve.ECDSA(hashes.SHA3_512()))
        except cryptography.exceptions.InvalidSignature:
            print("A bad signature failed")
        else:
            print("Good signature verified")
    
    

class TestSigning(unittest.TestCase):
    def test_abc(self):
        a = Signing()
        a.sign()
        print(repr(a.private_key))
        
        
    
    
    
    
# bitcoin uses Secp256k1 as parameters https://en.bitcoin.it/wiki/Secp256k1
def encrypt():
    private_key = elliptic_curve.generate_private_key(elliptic_curve.SECP256K1())

    private_vals = private_key.private_numbers()
    no_bits=private_vals.private_value.bit_length()
    print (f"Private key value: {private_vals.private_value}. Number of bits {no_bits}")
    public_key = private_key.public_key()
    pub=public_key.public_numbers()






def get_seconds_from_unix_epoch():
    now = datetime.datetime.now(datetime.timezone.utc)
    float_value = now.timestamp()
    int_value = int(float_value)
    return int_value
    
    
class Testget_get_seconds_from_unix_epoch(unittest.TestCase):
    def test_1(self):
        value = get_seconds_from_unix_epoch()
        self.assertEqual(isinstance(value, int), True)
        self.assertGreater(value, 1626590550)
        self.assertLess(value, 1626590550+3600*24*365*2) # 2 year from now.




def hash_binary_to_str(hash_bin):
    """
    Parameters:
            hash_bin (bytes): sha3-512 hash bytes that we want to turn into string form.

    Returns:
            (bytes): the string form of the hash
    """
    assert( isinstance(hash_bin, bytes))
    assert(len(hash_bin) == 64)
    
    list_of_strings = []
    for byte in hash_bin:
        list_of_strings += "{:02x}".format(byte)
    result = "".join(list_of_strings)
    return result
    
    
def hash_str_to_binary(hash_str):
    """
    Parameters:
            hash_str (str): sha3-512 hash string that we want to turn into binary form.

    Returns:
            (bytes): the bytes form of the hash
    """
    assert(len(hash_str) == 64*2)
    
    values = []
    for n in range(0,len(hash_str),2):
        two_nibbles = hash_str[n:n+2]
        values.append( int(two_nibbles,16) )
    return bytes(values)

    
class Hash:
    def __init__(self, data):
        """
        Parameters:
                data (bytes): the data to perform a sha3-512 hash on

        Returns:
                (str): the hash as a string
        """
        assert( isinstance(data, bytes))
        self.data = data
        self.__hash_handle = hashlib.sha3_512(self.data)
        self.as_str = self.__hash_handle.hexdigest()
        self.as_bytes = self.__hash_handle.digest()


        
        
#def get_hash(data):
#    """
#    Parameters:
#            data (bytes): the data to perform a sha3-512 hash on
#
#    Returns:
#            (str): the hash as a string
#    """
#    assert( isinstance(data, bytes))
#    
#    hash = hashlib.sha3_512(data).hexdigest()
#    return hash


class Testget_hash(unittest.TestCase):
    def test_abc(self):
        # https://codebeautify.org/sha3-512-hash-generator
        expected_hash = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        h = Hash(b'abc')
        self.assertEqual(h.as_str, expected_hash)
        
        # Hash the previous hash and check the result.
        expected_hash2 = "0fcda938dd7382fa650ae1931a6e9d6fa6643fa3361de87a97a022b6444e03fb39497316dd0fb0bb5947506d7e1f50a6ccfea47e14a9f5a8513e64419c6a5997"
        h2 = Hash(h.as_str.encode())
        self.assertEqual(h2.as_str, expected_hash2)
        
        
        
        bin_hash = hash_str_to_binary(h2.as_str)
        self.assertEqual(bin_hash, h2.as_bytes)
        str_hash = hash_binary_to_str(bin_hash)
        self.assertEqual(str_hash, h2.as_str)
        
        
        

def pack_block(time, prev_block_hash, hash_set):
    assert(isinstance(time, int))
    assert(time > 1626590550)
    assert(time < 1626590550 + 3600*24*365*50)
    assert(isinstance(prev_block_hash, bytes))
    assert(len(prev_block_hash) == 64)
    
    assert(isinstance(hash_set, list))
    assert(len(hash_set) == 29 )
    for hash in hash_set:
        assert(isinstance(hash, bytes))
        assert(len(hash) == 64)
    
    
    time_bytes = struct.pack("<Q", time)
    print(time_bytes)
    
class Testpack_block(unittest.TestCase):
    def test_1(self):
        time = get_seconds_from_unix_epoch()
        prev_block_hash = Hash(b"abc").as_bytes
        
        
        #pack_block(time, prev_block_hash, [])
    
        
    
    


class Anchor:
    def __init__(self):
    
    
    
    
    
        pass
        
    
    





def main():
    pass
    
    
    
    

if __name__ == '__main__':
    #print(get_seconds_from_unix_epoch())
    print(math.log(1626590714,2))
    unittest.main()



























