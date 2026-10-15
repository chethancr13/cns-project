import unittest
import os
import sys
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gnupg_crypto import OpenPGPSecretKeyEngine

# Suppress minor third-party deprecation warning
warnings.filterwarnings("ignore")


class TestGnuPGDecryption(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = OpenPGPSecretKeyEngine(key_size=2048)
        cls.passphrase = "UnitTestPassphrase2026!"
        cls.sec_key, cls.pub_key = cls.engine.generate_keypair(
            "TestUser", "test@domain.com", cls.passphrase
        )

    def test_asymmetric_decryption_success(self):
        message = "Test message for CNS Project GnuPG verification."
        ciphertext = self.engine.encrypt_asymmetric(message, self.pub_key)
        decrypted = self.engine.decrypt_asymmetric(ciphertext, self.sec_key, self.passphrase)
        self.assertEqual(decrypted, message)

    def test_asymmetric_wrong_passphrase_fails(self):
        message = "Secret payload"
        ciphertext = self.engine.encrypt_asymmetric(message, self.pub_key)
        with self.assertRaises(Exception):
            self.engine.decrypt_asymmetric(ciphertext, self.sec_key, "WrongPassword")

    def test_symmetric_decryption_success(self):
        message = "Symmetric encryption payload test"
        secret_key = "SharedKey#12345"
        ciphertext = self.engine.encrypt_symmetric(message, secret_key)
        decrypted = self.engine.decrypt_symmetric(ciphertext, secret_key)
        self.assertEqual(decrypted, message)

    def test_symmetric_wrong_key_fails(self):
        message = "Symmetric payload"
        ciphertext = self.engine.encrypt_symmetric(message, "CorrectKey")
        with self.assertRaises(Exception):
            self.engine.decrypt_symmetric(ciphertext, "WrongKey")


if __name__ == "__main__":
    unittest.main()
