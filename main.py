

# built in modules
import datetime
import io
import random
import struct
import os

import hashlib
import unittest

# pip installed modules




# Project modules
import public_private_key_lib


# https://www.freecodecamp.org/news/create-cryptocurrency-using-python/

# https://medium.com/@kiknaio/what-is-proof-of-existence-and-how-will-it-help-to-protect-intellectual-or-private-property-77aa97a3fbb1
# https://poex.io/




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
        """
        assert( isinstance(data, bytes))
        self.data = data
        self.__hash_handle = hashlib.sha3_512(self.data)
        self.as_str = self.__hash_handle.hexdigest()
        self.as_bytes = self.__hash_handle.digest()




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
        




class Block:
    BLOCK_SIZE = 1024*2
    HASHES_PER_BLOCK = 29

    def __init__(self):
        self.time = None
        self.pad = None
        self.prev_block_hash = None
        self.hash_set = [None]*Block.HASHES_PER_BLOCK
        self.signature = None

    def __eq__(self, other):
        if self.time != other.time or self.pad != other.pad or self.prev_block_hash != other.prev_block_hash  or self.signature != other.signature:
            return False

        for n in range(len(self.hash_set)):
            if self.hash_set[n] != other.hash_set[n]:
                return False

        return True

    def __repr__(self):
        output = []
        output.append(F"Block(\n\ttime={self.time}\n")
        output.append(F"\tpad={repr(self.pad)}\n")
        output.append(F"\tprev_block_hash={repr(self.prev_block_hash)}\n")
        output.append(F"\thash_set=\n")
        for n in range(len(self.hash_set)):
            output.append(F"\t\thash_set[{n}]={repr(self.hash_set[n])}\n")
        output.append(F"\tsignature={repr(self.signature)}\n")
        output.append(F"\t)\n")
        return "".join(output)


    def fill_with_valid_zeros(self):
        self.time = 1626590551
        self.pad = bytes([0]*40)
        self.prev_block_hash = bytes([0]*64)

        for n in range(len(self.hash_set)):
            self.hash_set[n] = bytes([0]*64)

        self.signature = bytes([0]*72)


    def fill_with_valid_random(self):
        self.time = 1626590551 + random.randrange(0, 3600 * 24 * 365 * 50)

        self.pad = random.randbytes(40)
        self.prev_block_hash = random.randbytes(64)

        for n in range(len(self.hash_set)):
            self.hash_set[n] = random.randbytes(64)

        self.signature = random.randbytes(random.randrange(70, 74))


    def read_from_bytes(self, data):
        assert(len(data) == 2048)
        n = 0
        m = n + 8
        self.time = struct.unpack_from("<Q", data, n)[0]
        n = m
        m = n + 40
        self.pad = data[n:m]
        n = m
        m = n + 64
        self.prev_block_hash = data[n:m]
        for hash_index in range(len(self.hash_set)):
            n = m
            m = n + 64
            self.hash_set[hash_index] = data[n:m]
        n = m
        m = n + 1
        signature_length = struct.unpack_from("<B", data, n)[0]
        assert(64 < signature_length <= 79)
        n = m
        m = n + 79
        self.signature = data[n:m]
        self.signature = self.signature[:signature_length]
        assert(self.verify_block())

    def write_to_bytes(self):
        assert(self.verify_block())
        output = io.BytesIO()
        output.write(struct.pack("<Q", self.time))
        output.write(self.pad)
        output.write(self.prev_block_hash)

        for item in self.hash_set:
            output.write(item)
        output.write(struct.pack("<B", len(self.signature)))
        output.write(self.signature)

        for n in range(len(self.signature), 79):
            output.write(struct.pack("<B", 0))

        result = output.getvalue()
        assert(len(result) == 2048)
        return result


    def verify_block(self):
        try:
            assert (isinstance(self.time, int))
            assert (self.time > 1626590550)
            assert (self.time < 1626590550 + 3600 * 24 * 365 * 50)

            assert (isinstance(self.pad, bytes))
            assert (len(self.pad) == 40)

            assert (isinstance(self.prev_block_hash, bytes))
            assert (len(self.prev_block_hash) == 64)

            assert (isinstance(self.hash_set, list))
            assert (len(self.hash_set) == Block.HASHES_PER_BLOCK)
            for x in self.hash_set:
                assert (isinstance(x, bytes))
                assert (len(x) == 64)

            assert (64 < len(self.signature) <= 79)
            return True
        except AssertionError:
            return False


    def sign_block(self, private_key):
        byte_stream = self.write_to_bytes()
        # Don't include the signature bytes at the end.
        byte_stream = byte_stream[:-(79+1)]
        assert(len(byte_stream) == 2048-(79+1))

        signature = private_key.sign_data(byte_stream)
        self.signature = signature


    def verify_signature(self, public_or_private_key):
        byte_stream = self.write_to_bytes()
        # Don't include the signature bytes at the end.
        byte_stream = byte_stream[:-(79 + 1)]
        assert (len(byte_stream) == 2048 - (79 + 1))

        return public_or_private_key.is_signature_valid(self.signature, byte_stream)

    def get_block_hash(self):
        return Hash(self.write_to_bytes()).as_bytes



class TestRandomUnpackPack(unittest.TestCase):
    def test_1(self):
        a = Block()
        a.fill_with_valid_zeros()
        #a.fill_with_valid_random()
        b = a.write_to_bytes()
        c = Block()
        c.read_from_bytes(b)
        #sig = list(a.signature)
        #sig[0] = 0xFF
        #a.signature = bytes(sig)
        self.assertEqual(a, c)



        password = "abc_123_password_bacon"
        private_file = "private_key_test.bin"
        public_file = "public_key_test.txt"

        if os.path.exists(private_file):
            os.remove(private_file)
        if os.path.exists(public_file):
            os.remove(public_file)

        private_key = public_private_key_lib.PrivateKey(password=password, private_key_file_path=private_file,
                                 public_key_file_path=public_file)
        self.assertFalse(private_key.was_key_loaded_from_file())
        public_key = public_private_key_lib.PublicKey(public_key_file_path=public_file)

        a.sign_block(private_key)
        self.assertTrue(a.verify_signature(public_key))
        self.assertTrue(a.verify_signature(private_key))

        print(a)



class BlockChain:
    def __init__(self, saved_blockchain_path, private_key=None, public_key=None):
        self.saved_blockchain_path = saved_blockchain_path
        self.private_key = private_key
        self.public_key = public_key

        # Open and read the newest block, or else create the first block
        if os.path.exists(self.saved_blockchain_path):
            file_size = os.path.getsize(self.saved_blockchain_path)
            with open(self.saved_blockchain_path, "rb") as file_handle:
                file_handle.seek(file_size - Block.BLOCK_SIZE)
                self.binary_block_data = file_handle.read()
        else:
            self.binary_block_data = b""


        # get or build the first block
        self.newest_block = Block()
        if len(self.binary_block_data):
            assert(len(self.binary_block_data) == Block.BLOCK_SIZE)
            print("Loading newest block from file")
            self.newest_block.read_from_bytes(self.binary_block_data[-Block.BLOCK_SIZE:])
        else:
            print("Generating first block")
            self.newest_block.fill_with_valid_random()
            self.newest_block.time = get_seconds_from_unix_epoch()
            self.newest_block.prev_block_hash = bytes([0]*64)
            self.newest_block.sign_block(self.private_key)
            self.__write_block_to_file(self.newest_block)


        if self.private_key is not None:
            self.newest_block.verify_signature(self.private_key)
        else:
            self.newest_block.verify_signature(self.public_key)


    def __write_block_to_file(self, block):
        with open(self.saved_blockchain_path, "ab") as file_handle:
            file_handle.write(block.write_to_bytes())

    def add_block_to_blockchain(self, new_block):
        assert(isinstance(new_block, Block))
        assert(new_block.verify_block())

        new_block.prev_block_hash = self.newest_block.get_block_hash()
        new_block.sign_block(self.private_key)
        assert(new_block.verify_signature(self.private_key))

        self.__write_block_to_file(new_block)
        self.newest_block = new_block


class TestBlockchain(unittest.TestCase):
    def test_1(self):
        password = "abc_123_password_bacon"
        private_file = "private_key_test.bin"
        public_file = "public_key_test.txt"

        if os.path.exists(private_file):
            os.remove(private_file)
        if os.path.exists(public_file):
            os.remove(public_file)

        private_key = public_private_key_lib.PrivateKey(password=password, private_key_file_path=private_file,
                                 public_key_file_path=public_file)
        self.assertFalse(private_key.was_key_loaded_from_file())
        public_key = public_private_key_lib.PublicKey(public_key_file_path=public_file)

        saved_blockchain_path = "test_blockchain1.bin"
        if os.path.exists(saved_blockchain_path):
            os.remove(saved_blockchain_path)

        bc = BlockChain(saved_blockchain_path=saved_blockchain_path, private_key=private_key)
        bc2 = BlockChain(saved_blockchain_path="test_blockchain1.bin", public_key=public_key)
        self.assertEqual(bc.newest_block, bc2.newest_block)
        #print(bc2.newest_block)

        new_block = Block()
        new_block.fill_with_valid_random()
        bc.add_block_to_blockchain(new_block)
        bc3 = BlockChain(saved_blockchain_path="test_blockchain1.bin", public_key=public_key)
        self.assertEqual(bc.newest_block, bc3.newest_block)
        #print(bc3.newest_block)
    




class ManyToOneAggregator:
    def __init__(self, max_number_of_files_per_commit, private_key):
        self.max_number_of_files_per_commit = max_number_of_files_per_commit
        self.private_key = private_key

        number_of_bottom_row_chains = (self.max_number_of_files_per_commit // Block.HASHES_PER_BLOCK) + 1

        self.levels = []
        n = number_of_bottom_row_chains
        while True:
            x = []
            for m in range(n):
                path = F"AggregatorBlockchain{}{}.bin"
                x.append(BlockChain)
            self.levels.append()




        pass


















if __name__ == '__main__':
    unittest.main()



























