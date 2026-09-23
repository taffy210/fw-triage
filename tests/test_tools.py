"""
Stdlib unittest suite for the fw-triage tools. No dependencies, matching the
tools themselves. Run from the repo root:

    python -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crypto_indicators  # noqa: E402
import entropy  # noqa: E402
import xor_sweep  # noqa: E402


class TestXorSweep(unittest.TestCase):
    def test_entropy_is_invariant_under_single_byte_xor(self):
        # The reason the old entropy-drop heuristic could never work: XOR with a
        # constant only relabels symbols, so entropy is identical for every key.
        data = bytes(range(256)) * 4
        base = xor_sweep.entropy(data)
        for k in (0x01, 0x42, 0xFF):
            xored = bytes(b ^ k for b in data)
            self.assertAlmostEqual(xor_sweep.entropy(xored), base, places=9)

    def test_printable_ratio_bounds(self):
        self.assertEqual(xor_sweep.printable_ratio(b"hello world\n"), 1.0)
        self.assertEqual(xor_sweep.printable_ratio(bytes(range(128, 256))), 0.0)
        self.assertEqual(xor_sweep.printable_ratio(b""), 0.0)

    def test_padding_key_guess(self):
        # 0x00 padding XOR'd with the key becomes a run of the key byte, so the
        # most common byte recovers it. Emulate the sweep's guess step.
        from collections import Counter
        plain = b"\x00" * 900 + b"BOOT" * 25
        blob = bytes(b ^ 0x5A for b in plain)
        self.assertEqual(Counter(blob).most_common(1)[0][0], 0x5A)


class TestEntropy(unittest.TestCase):
    def test_uniform_is_max_entropy(self):
        self.assertAlmostEqual(entropy.entropy(bytes(range(256))), 8.0, places=6)

    def test_constant_is_zero_entropy(self):
        self.assertEqual(entropy.entropy(b"\x00" * 1024), 0.0)

    def test_empty(self):
        self.assertEqual(entropy.entropy(b""), 0.0)


class TestCryptoIndicators(unittest.TestCase):
    def _hits(self, text):
        return [s for _, s in
                crypto_indicators.iter_strings(text.encode(), minlen=3)
                if crypto_indicators._PAT.search(s)]

    def test_short_tokens_need_word_boundaries(self):
        # These used to false-positive on substrings; they must not now.
        self.assertEqual(self._hits("conversation adoption relationship"), [])

    def test_whole_word_tokens_match(self):
        self.assertTrue(self._hits("uses aes and rsa here"))
        self.assertTrue(self._hits("hisilicon hi35 soc"))

    def test_iter_strings_respects_minlen(self):
        data = b"\x00ab\x00hello\x00"
        found = [s for _, s in crypto_indicators.iter_strings(data, minlen=4)]
        self.assertEqual(found, ["hello"])


if __name__ == "__main__":
    unittest.main()
