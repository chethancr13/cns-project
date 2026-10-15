import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from digital_signature import (
    RSADigitalSignature,
    ECDSADigitalSignature,
    KeySerializer
)


class TestDigitalSignature(unittest.TestCase):
    def test_rsa_signing_and_verification(self):
        engine = RSADigitalSignature(key_size=2048)
        priv, pub = engine.generate_keypair()
        data = b"Critical CNS Engineering Project Submission"
        sig = RSADigitalSignature.sign(data, priv)
        
        # Valid verification
        self.assertTrue(RSADigitalSignature.verify(data, sig, pub))
        
        # Tampered data
        self.assertFalse(RSADigitalSignature.verify(data + b"tamper", sig, pub))

    def test_ecdsa_signing_and_verification(self):
        priv, pub = ECDSADigitalSignature.generate_keypair()
        data = b"Elliptic Curve Sign Test"
        sig = ECDSADigitalSignature.sign(data, priv)

        # Valid verification
        self.assertTrue(ECDSADigitalSignature.verify(data, sig, pub))

        # Tampered signature
        corrupted_sig = bytearray(sig)
        corrupted_sig[5] ^= 0xFF
        self.assertFalse(ECDSADigitalSignature.verify(data, bytes(corrupted_sig), pub))

    def test_pem_serialization(self):
        engine = RSADigitalSignature(key_size=2048)
        priv, pub = engine.generate_keypair()

        priv_pem = KeySerializer.export_private_key_pem(priv)
        pub_pem = KeySerializer.export_public_key_pem(pub)

        loaded_priv = KeySerializer.load_private_key_pem(priv_pem)
        loaded_pub = KeySerializer.load_public_key_pem(pub_pem)

        data = b"Testing PEM serialization round-trip"
        sig = RSADigitalSignature.sign(data, loaded_priv)
        self.assertTrue(RSADigitalSignature.verify(data, sig, loaded_pub))


if __name__ == "__main__":
    unittest.main()
