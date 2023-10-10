

# built in modules
import unittest
import os

# pip installed modules
import cryptography
from cryptography.hazmat.primitives.asymmetric import ec as elliptic_curve
from cryptography.hazmat.primitives import hashes


# Project modules
import save_key_pair




# https://stackoverflow.com/questions/45146504/python-cryptography-module-save-load-rsa-keys-to-from-file


# bitcoin uses Secp256k1 as parameters https://en.bitcoin.it/wiki/Secp256k1
class PrivateKey:
    """
    example extracted from: https://medium.com/asecuritysite-when-bob-met-alice/ecdsa-python-and-hazmat-2eee60caab34
    """
    def __init__(self, password, private_key_file_path, public_key_file_path):
        try:
            self.private_key = save_key_pair.load_private_key(private_key_file_path, password)
            self.loaded_from_file = True
            #print("sucessfully loaded the private key")
        except:
            self.private_key = elliptic_curve.generate_private_key(elliptic_curve.SECP256K1())
            save_key_pair.save_public_key(self.private_key.public_key(), public_key_file_path)
            save_key_pair.save_private_key(self.private_key, private_key_file_path, password)
            self.loaded_from_file = False
            print("Generated a key and saved it to the file.")

        self.public_key = self.private_key.public_key()

    def is_signature_valid(self, signature, data_that_was_signed):
        try:
            self.public_key.verify(signature, data_that_was_signed, elliptic_curve.ECDSA(hashes.SHA3_512()))
        except cryptography.exceptions.InvalidSignature:
            return False
        else:
            return True

    def sign_data(self, data):
        signature = self.private_key.sign(data, elliptic_curve.ECDSA(hashes.SHA3_512()))
        return signature

    def was_key_loaded_from_file(self):
        return self.loaded_from_file


class PublicKey:
    def __init__(self, public_key_file_path):
        self.public_key = save_key_pair.load_public_key(public_key_file_path)


    def is_signature_valid(self, signature, data_that_was_signed):
        try:
            self.public_key.verify(signature, data_that_was_signed, elliptic_curve.ECDSA(hashes.SHA3_512()))
        except cryptography.exceptions.InvalidSignature:
            return False
        else:
            return True





class TestSigning(unittest.TestCase):
    def test_abc(self):
        data = b'abc'

        password = "abc_123_password_bacon"
        private_file = "private_key_test.bin"
        public_file = "public_key_test.txt"

        if os.path.exists(private_file):
            os.remove(private_file)
        if os.path.exists(public_file):
            os.remove(public_file)

        private_key = PrivateKey(password=password, private_key_file_path=private_file, public_key_file_path=public_file)
        self.assertFalse(private_key.was_key_loaded_from_file())
        new_signature = private_key.sign_data(data)
        self.assertTrue(private_key.verify_signature(new_signature, data))
        public_key = PublicKey(public_key_file_path=public_file)
        self.assertTrue(public_key.is_signature_valid(new_signature, data))

        bad_sig = b"0D\x02 ('\xb4\xa7s\x15Sy\xd0>x\xb7\x93\x9d\xf8L>\xf3, \x99\x18\x81F\xfb\x7f\x88~xG\t[\x02 ;\xdd\xbbI\xa3\x08O\x88I\xee\xb7Ze\xed9F\x0b\x12o\xaab~\x10\x0b\x16\xab\x9e-\xd9\xd2\x1fL"
        self.assertFalse(private_key.verify_signature(bad_sig, data))
        self.assertFalse(public_key.is_signature_valid(bad_sig, data))

        private_key2 = PrivateKey(password=password, private_key_file_path=private_file, public_key_file_path=public_file)
        self.assertTrue(private_key2.was_key_loaded_from_file())
        self.assertTrue(private_key2.verify_signature(new_signature, data))
        self.assertFalse(private_key2.verify_signature(bad_sig, data))



if __name__ == '__main__':
    unittest.main()

