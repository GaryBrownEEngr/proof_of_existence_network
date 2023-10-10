# https://nitratine.net/blog/post/python-encryption-and-decryption-with-pycryptodome/

# built in modules
import io
import pickle
import unittest

# pip installed modules
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


# Project modules




def save_private_key(pk, filename, password):
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cipher_text = encrypt_data(password, pem)
    with open(filename, 'wb') as pem_out:
        pem_out.write(cipher_text)


def save_public_key(pk, filename):
    pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def load_private_key(filename, password):
    with open(filename, 'rb') as pem_in:
        cipher_text = pem_in.read()

    pemlines = decrypt_data(password, cipher_text)
    private_key = load_pem_private_key(pemlines, password=None)
    return private_key


def load_public_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()

    public_key = load_pem_public_key(pemlines)
    return public_key










def generate_salt():
    from Crypto.Random import get_random_bytes
    salt = get_random_bytes(32)
    # print("New salt: ", salt)  # Print the salt to be copied to your script
    return salt


def derive_key_from_password(password, salt):
    assert(isinstance(password, str))
    assert (isinstance(salt, bytes))
    assert (len(salt) == 32)
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


def encrypt_data(password, data):
    assert(isinstance(password, str))
    assert(isinstance(data, bytes))

    salt = generate_salt()
    key = derive_key_from_password(password, salt)


    cipher = AES.new(key, AES.MODE_CFB)  # CFB mode
    ciphered_data = cipher.encrypt(data)  # Only need to encrypt the data, no padding required for this mode

    binary_stream = io.BytesIO()
    binary_stream.write(salt)
    binary_stream.write(cipher.iv)
    binary_stream.write(ciphered_data)
    return binary_stream.getvalue()


def decrypt_data(password, data):
    assert (isinstance(password, str))
    assert (isinstance(data, bytes))

    salt = data[:32]
    iv = data[32:32+16]
    ciphered_data = data[32+16:]

    key = derive_key_from_password(password, salt)

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    original_data = cipher.decrypt(ciphered_data)  # No need to un-pad
    return original_data



def pickle_encrypt_save_a_class(class_handle, path, password):
    assert (isinstance(path, str))
    assert (isinstance(password, str))

    pickle_data = pickle_to_stream(class_handle)
    cipher_text = encrypt_data(password, pickle_data.getvalue())
    save_bytes_to_file(cipher_text, path)


def load_decrypt_unpickle_a_class(path, password):
    assert (isinstance(path, str))
    assert (isinstance(password, str))

    read_cipher_text = read_bytes_from_file(path)
    read_pickle_data = decrypt_data(password, read_cipher_text)
    stream_to_unpickle = io.BytesIO()
    stream_to_unpickle.write(read_pickle_data)
    stream_to_unpickle.seek(0)
    re_derived_test_class = unpickle_from_stream(stream_to_unpickle)
    return re_derived_test_class



class TestEncryptDecrypt(unittest.TestCase):
    def test_1(self):
        data_in = b"abc123 your bacon is so good I will eat it all!."
        password = "password 123abc good!"
        cipher_text = encrypt_data(password, data_in)
        print(cipher_text)
        data_out = decrypt_data(password, cipher_text)
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

        test_class = TestOneClass()
        pickle_encrypt_save_a_class(test_class, "path.bin", password)
        re_loaded_test_class = load_decrypt_unpickle_a_class("path.bin", password)

        self.assertEqual(test_class, re_loaded_test_class)

        test_class.a = 321
        print(test_class.a, re_loaded_test_class.a)





if __name__ == '__main__':
    # generate_salt()
    unittest.main()





