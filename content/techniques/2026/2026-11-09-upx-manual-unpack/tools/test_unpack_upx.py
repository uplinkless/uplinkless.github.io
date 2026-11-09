"""Unit tests for unpack_upx.py pure functions. Run: python -m unittest test_unpack_upx -v"""
import struct
import unittest

import unpack_upx as u


def rel32(src_rva: int, dst_rva: int) -> bytes:
    return struct.pack("<i", dst_rva - (src_rva + 5))


class FindTailJump(unittest.TestCase):
    def test_prefers_sub_rsp_pattern_and_skips_out_of_range_jumps(self):
        stub_rva = 0x9000
        code = bytearray(b"\x90" * 0x40)
        code[0x10:0x15] = b"\xe9" + rel32(stub_rva + 0x10, 0x9800)  # stays in stub: ignored
        code[0x20:0x24] = b"\x48\x83\xec\x80"
        code[0x24:0x29] = b"\xe9" + rel32(stub_rva + 0x24, 0x1234)
        tj = u.find_tail_jump(bytes(code), stub_rva, stub_rva, 0x1000, 0x8000)
        self.assertEqual((tj.rva, tj.target_rva, tj.pattern), (stub_rva + 0x24, 0x1234, True))

    def test_falls_back_without_pattern(self):
        code = b"\x90" * 8 + b"\xe9" + rel32(0x9008, 0x2000) + b"\x90" * 4
        tj = u.find_tail_jump(code, 0x9000, 0x9000, 0x1000, 0x8000)
        self.assertEqual((tj.rva, tj.target_rva, tj.pattern), (0x9008, 0x2000, False))

    def test_starts_at_entry_point(self):
        code = b"\xe9" + rel32(0x9000, 0x2000) + b"\x90" * 8
        with self.assertRaises(u.UnpackError):
            u.find_tail_jump(code, 0x9000, 0x9005, 0x1000, 0x8000)


class IatRegion(unittest.TestCase):
    def setUp(self):
        k = [u.Candidate("kernel32.dll", "A", False)]
        fwd = [u.Candidate("kernel32.dll", "B", True), u.Candidate("ntdll.dll", "RtlB", False)]
        usr = [u.Candidate("user32.dll", "C", False)]
        stray = [u.Candidate("kernel32.dll", "A", False)]
        self.index = {0x7FF0_0000_1000: k, 0x7FF0_0000_2000: fwd, 0x7FF0_0000_3000: usr, 0x7FF0_0000_4000: stray}

    def image(self):
        img = bytearray(0x3000)
        struct.pack_into("<QQQQ", img, 0x2000, 0x7FF0_0000_1000, 0x7FF0_0000_2000, 0, 0x7FF0_0000_3000)
        struct.pack_into("<Q", img, 0x2800, 0x7FF0_0000_4000)  # lone pointer elsewhere
        return bytes(img)

    def test_picks_largest_region_and_splits_on_zero(self):
        raw = u.find_iat_region(self.image(), self.index)
        self.assertEqual([(b.iat_rva, len(b.entries)) for b in raw], [(0x2000, 2), (0x2018, 1)])

    def test_choose_blocks_prefers_forwarding_dll(self):
        blocks = u.choose_blocks(u.find_iat_region(self.image(), self.index))
        self.assertEqual([(b.dll, b.iat_rva, b.names) for b in blocks],
                         [("kernel32.dll", 0x2000, ["A", "B"]), ("user32.dll", 0x2018, ["C"])])

    def test_choose_blocks_rejects_mixed_block(self):
        raw = [u.RawBlock(0x2000, [[u.Candidate("a.dll", "x", False)], [u.Candidate("b.dll", "y", False)]])]
        with self.assertRaises(u.UnpackError):
            u.choose_blocks(raw)


class ImportSection(unittest.TestCase):
    def test_layout_round_trips(self):
        blocks = [u.IatBlock("kernel32.dll", 0x2000, ["A", "B"]), u.IatBlock("user32.dll", 0x2018, ["C"])]
        sec = u.build_import_section(blocks, 0x5000)
        self.assertEqual((sec.dir_rva, sec.dir_size), (0x5000, 3 * 20))
        d = sec.data

        def cstr(rva):
            off = rva - 0x5000
            return d[off:d.index(b"\0", off)].decode()

        names = []
        for i in range(2):
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", d, i * 20)
            funcs = []
            off = oft - 0x5000
            while True:
                (thunk,) = struct.unpack_from("<Q", d, off)
                if thunk == 0:
                    break
                funcs.append(cstr(thunk + 2))
                off += 8
            names.append((cstr(name_rva), ft, funcs))
        self.assertEqual(names, [("kernel32.dll", 0x2000, ["A", "B"]), ("user32.dll", 0x2018, ["C"])])
        self.assertEqual(struct.unpack_from("<IIIII", d, 40), (0, 0, 0, 0, 0))
        self.assertEqual([p[0] for p in sec.iat_patches], [0x2000, 0x2008, 0x2018])


def tiny_pe64(size_of_image=0x3000):
    """Headers of a mapped PE32+ image with two sections; enough for rebuild_pe."""
    img = bytearray(size_of_image)
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x80)
    img[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", img, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0x22)
    opt = 0x98
    struct.pack_into("<H", img, opt, 0x20B)
    struct.pack_into("<I", img, opt + 16, 0x2100)
    struct.pack_into("<Q", img, opt + 24, 0x140000000)
    struct.pack_into("<II", img, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", img, opt + 56, size_of_image, 0x400)
    struct.pack_into("<H", img, opt + 70, 0x8160)
    struct.pack_into("<I", img, opt + 108, 16)
    struct.pack_into("<II", img, opt + 112 + 8 * 5, 0x2F00, 0x10)
    sec = opt + 0xF0
    struct.pack_into("<8sIIIIIIHHI", img, sec, b"UPX0", 0x1000, 0x1000, 0, 0x400, 0, 0, 0, 0, 0xE0000080)
    struct.pack_into("<8sIIIIIIHHI", img, sec + 40, b"UPX1", 0x1000, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0x60000040)
    return bytes(img)


class RebuildPe(unittest.TestCase):
    def test_headers_describe_the_dump(self):
        blocks = [u.IatBlock("user32.dll", 0x1800, ["CharUpperA"])]
        out = u.rebuild_pe(tiny_pe64(), 0x7FF600000000, 0x1234, blocks)
        opt, sec = 0x98, 0x98 + 0xF0
        self.assertEqual(struct.unpack_from("<H", out, 0x86)[0], 3)
        self.assertEqual(struct.unpack_from("<I", out, opt + 16)[0], 0x1234)
        self.assertEqual(struct.unpack_from("<Q", out, opt + 24)[0], 0x7FF600000000)
        self.assertEqual(struct.unpack_from("<H", out, opt + 70)[0] & 0x60, 0)
        self.assertEqual(struct.unpack_from("<II", out, opt + 112 + 8 * 5), (0, 0))
        self.assertEqual(struct.unpack_from("<II", out, opt + 112 + 8)[0], 0x3000)
        for i in range(2):
            name, vsize, va, raw_size, raw_ptr = struct.unpack_from("<8sIIII", out, sec + 40 * i)
            chars = struct.unpack_from("<I", out, sec + 40 * i + 36)[0]
            self.assertEqual((raw_ptr, raw_size), (va, 0x1000), name)
            self.assertEqual(chars & 0xE0000000, 0xE0000000, name)
        self.assertEqual(struct.unpack_from("<8s", out, sec + 80)[0], b".idata2\0")
        self.assertEqual(len(out), struct.unpack_from("<I", out, opt + 56)[0])


if __name__ == "__main__":
    unittest.main()
