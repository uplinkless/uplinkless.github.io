"""Unit tests for verify.py. Run: python -m unittest test_verify -v"""
import struct
import unittest

import verify as v


class CompareCode(unittest.TestCase):
    def test_relocated_pointer_is_not_a_difference(self):
        orig = bytearray(32)
        struct.pack_into("<Q", orig, 8, 0x140001000)
        dumped = bytearray(orig)
        struct.pack_into("<Q", dumped, 8, 0x7FF600001000)
        self.assertEqual(v.compare_code(bytes(orig), bytes(dumped), [8], 0x7FF600001000 - 0x140001000), 0)

    def test_counts_real_differences(self):
        orig = bytes(16)
        dumped = bytes(15) + b"\x01"
        self.assertEqual(v.compare_code(orig, dumped, [], 0), 1)

    def test_wrong_pointer_counts_as_eight(self):
        orig = bytearray(16)
        struct.pack_into("<Q", orig, 0, 0x140001000)
        dumped = bytearray(16)
        struct.pack_into("<Q", dumped, 0, 0x140009999)
        self.assertEqual(v.compare_code(bytes(orig), bytes(dumped), [0], 0), 8)


if __name__ == "__main__":
    unittest.main()
