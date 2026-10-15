import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from otp_engine import OneTimePadEngine


class TestOneTimePad(unittest.TestCase):
    def test_encryption_decryption_text(self):
        msg = "The eagle flies at midnight."
        c, k = OneTimePadEngine.encrypt_text(msg)
        self.assertEqual(len(c), len(k))
        dec = OneTimePadEngine.decrypt_text(c, k)
        self.assertEqual(dec, msg)

    def test_encryption_decryption_binary(self):
        raw_bytes = bytes([0x00, 0xFF, 0x5A, 0xA5, 0x12, 0x34])
        key = OneTimePadEngine.generate_key(len(raw_bytes))
        c = OneTimePadEngine.encrypt_bytes(raw_bytes, key)
        p = OneTimePadEngine.decrypt_bytes(c, key)
        self.assertEqual(p, raw_bytes)

    def test_length_mismatch_raises_error(self):
        raw_bytes = b"Hello"
        short_key = b"123"
        with self.assertRaises(ValueError):
            OneTimePadEngine.encrypt_bytes(raw_bytes, short_key)

    def test_two_time_pad_leakage(self):
        p1 = b"ATTACK"
        p2 = b"DEFEND"
        key = OneTimePadEngine.generate_key(len(p1))
        c1 = OneTimePadEngine.encrypt_bytes(p1, key)
        c2 = OneTimePadEngine.encrypt_bytes(p2, key)
        leaked = OneTimePadEngine.two_time_pad_leak(c1, c2)
        expected = bytes(a ^ b for a, b in zip(p1, p2))
        self.assertEqual(leaked, expected)


if __name__ == "__main__":
    unittest.main()
