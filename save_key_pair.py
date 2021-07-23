# https://nitratine.net/blog/post/python-encryption-and-decryption-with-pycryptodome/

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import io
import pickle
import unittest


def generate_salt():
    from Crypto.Random import get_random_bytes
    print("New salt: ", get_random_bytes(32))  # Print the salt to be copied to your script


def derive_key_from_password(password):
    assert(isinstance(password, str))
    salt = b'\x9eg\x86e\xcb\xcf1\xcaG4=B\x85\xf0\x0e\x19\xa4\x17M\xfc\xf5\xbf;\'\x15_\xbfT\x8a"\xf971\x8a'
    key = PBKDF2(password, salt, dkLen=32)  # Your key that you can encrypt with
    return key


def pickle_to_stream(class_handle):
    binary_stream = io.BytesIO()
    pickle.dump(class_handle, binary_stream)
    return binary_stream


def unpickle_from_stream(binary_stream):
    assert (isinstance(binary_stream, io.BytesIO))
    class_handle = pickle.load(binary_stream)
    return class_handle


def save_bytes_to_file(data, path):
    assert (isinstance(data, bytes))
    assert (isinstance(path, str))

    with open(path, "wb") as file:
        file.write(data)


def read_bytes_from_file(path):
    assert (isinstance(path, str))

    with open(path, "rb") as file:
        data = file.read()
    return data


def encrypt_data(key, data):
    assert(isinstance(key, bytes))
    assert(isinstance(data, bytes))
    assert (len(key) == 32)

    cipher = AES.new(key, AES.MODE_CFB)  # CFB mode
    ciphered_data = cipher.encrypt(data)  # Only need to encrypt the data, no padding required for this mode

    binary_stream = io.BytesIO()
    binary_stream.write(cipher.iv)
    binary_stream.write(ciphered_data)
    return binary_stream.getvalue()


def decrypt_data(key, data):
    assert (isinstance(data, bytes))
    assert (isinstance(key, bytes))
    assert (len(key) == 32)

    iv = data[:16]
    ciphered_data = data[16:]

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    original_data = cipher.decrypt(ciphered_data)  # No need to un-pad
    return original_data



def pickle_encrypt_save_a_class(class_handle, path, key):
    assert (isinstance(path, str))
    assert (isinstance(key, bytes))
    assert (len(key) == 32)

    pickle_data = pickle_to_stream(class_handle)
    cipher_text = encrypt_data(key, pickle_data.getvalue())
    save_bytes_to_file(cipher_text, path)


def load_decrypt_unpickle_a_class(path, key):
    assert (isinstance(path, str))
    assert (isinstance(key, bytes))
    assert (len(key) == 32)

    read_cipher_text = read_bytes_from_file(path)
    read_pickle_data = decrypt_data(key, read_cipher_text)
    stream_to_unpickle = io.BytesIO()
    stream_to_unpickle.write(read_pickle_data)
    stream_to_unpickle.seek(0)
    re_derived_test_class = unpickle_from_stream(stream_to_unpickle)
    return re_derived_test_class



class TestEncryptDecrypt(unittest.TestCase):
    def test_1(self):
        data_in = b"abc123 your bacon is so good I will eat it all!."
        password = "password 123abc good!"
        key = derive_key_from_password(password)
        cipher_text = encrypt_data(key, data_in)
        print(cipher_text)
        data_out = decrypt_data(key, cipher_text)
        self.assertEqual(data_in, data_out)
        print(data_out)


class TestOneClass:
    def __init__(self):
        self.a = 123
        self.b = "123"
        self.c = None

    def __eq__(self, other):
        return self.a == other.a and self.b == other.b and self.c == other.c


class TestPickleUnpickle(unittest.TestCase):
    def test_1(self):
        password = "password 123abc good!"
        key = derive_key_from_password(password)

        test_class = TestOneClass()
        pickle_encrypt_save_a_class(test_class, "path.bin", key)
        re_loaded_test_class = load_decrypt_unpickle_a_class("path.bin", key)

        self.assertEqual(test_class, re_loaded_test_class)

        test_class.a = 321
        print(test_class.a, re_loaded_test_class.a)





if __name__ == '__main__':
    # generate_salt()
    unittest.main()





