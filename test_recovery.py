import pathlib
import struct
import sys
import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from extract_macro_source import KEY, ROOT, TypePackReader, xor_stream
from decode_macro_actions import FIELD_KEYS

sys.path.insert(0, str(ROOT / '.analysis_deps'))
import unicorn
from unicorn import x86_const


class RecoveryChecks(unittest.TestCase):
    def test_xor_matches_native_loop(self):
        text = (ROOT / 'emulation_analysis/section_00_rva_00001000.bin').read_bytes()
        start = 0x1400EF729
        end = 0x1400EF751
        code = text[start - 0x140001000:end - 0x140001000]
        for length in (1, 15, 16, 31, 256, 4096):
            with self.subTest(length=length):
                source = bytes(index % 256 for index in range(length))
                machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
                machine.mem_map(start & ~4095, 4096)
                machine.mem_write(start, code)
                machine.mem_map(0x100000, 8192)
                machine.mem_write(0x100000, source)
                machine.reg_write(x86_const.UC_X86_REG_R14, 0x100000)
                machine.reg_write(x86_const.UC_X86_REG_RBX, length)
                machine.reg_write(x86_const.UC_X86_REG_R8, 0)
                machine.emu_start(start, end, count=100000)
                self.assertEqual(machine.reg_read(x86_const.UC_X86_REG_RIP), end)
                self.assertEqual(bytes(machine.mem_read(0x100000, length)), xor_stream(source))

    def test_outer_exact_hash_and_size(self):
        import hashlib
        encrypted = (ROOT / 'recovered_assets/resource_00.emacro').read_bytes()
        plain = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(xor_stream(encrypted)), 16)
        self.assertEqual(len(plain), 335611)
        self.assertEqual(hashlib.sha256(plain).hexdigest(), '3b09603397b010572f4f489c82c1e2d2e08a77589dff184ab722ac8ad00ce9e4')
        reader = TypePackReader(plain)
        macro = reader.read()
        self.assertEqual(reader.offset, len(plain))
        self.assertTrue(macro['qiml'].startswith('<qiml>'))
        self.assertEqual(len(macro['actions']), 31)
        self.assertEqual(len(macro['actionsEnding']), 7)

    def test_known_inner_plaintexts(self):
        pairs = [('2c73f7ff', '7b56960098c45e754ddcde55b101e239', b'jiyfpzgs7'),
                 ('4e3698ae', '58bbc12a953f1ed1baa0a1f8f7ac2e6381cf1bc60dfec69ece59b786bd26b347', '提前打开逻辑'.encode())]
        for field, encrypted, expected in pairs:
            self.assertEqual(unpad(AES.new(FIELD_KEYS[field], AES.MODE_ECB).decrypt(bytes.fromhex(encrypted)), 16), expected)

    def test_typepack_scalars(self):
        for data, expected in [(b'\0', False), (b'\1', True), (b'\4\xff', -1),
                               (b'\5\xff', 255), (b'G\x03\0abc', 'abc'),
                               (b'\x86' + struct.pack('<f', 1.5), 1.5),
                               (b'\xc6' + struct.pack('<d', 1.25), 1.25)]:
            self.assertEqual(TypePackReader(data).read(), expected)

    def test_every_decoded_field_roundtrips(self):
        import json
        from decode_macro_actions import FIELD_NAMES
        original = json.loads((ROOT / 'recovered_source/macro.full.json').read_text(encoding='utf-8'))
        readable = json.loads((ROOT / 'recovered_source/macro.readable.json').read_text(encoding='utf-8'))
        count = 0

        def verify(first, second):
            nonlocal count
            if isinstance(first, list):
                self.assertEqual(len(first), len(second))
                for raw, decoded in zip(first, second):
                    verify(raw, decoded)
            elif isinstance(first, dict):
                action = '2c73f7ff' in first
                self.assertEqual(len(second), len(first) + int(action))
                for key, raw in first.items():
                    decoded = second[FIELD_NAMES.get(key, key) if action else key]
                    if key in FIELD_KEYS:
                        from Crypto.Util.Padding import pad
                        cipher = bytes.fromhex(raw)
                        plain = unpad(AES.new(FIELD_KEYS[key], AES.MODE_ECB).decrypt(cipher), 16)
                        rebuilt = plain[:8] + str(decoded).encode() if key == '2c73f7ff' else decoded.encode()
                        self.assertEqual(AES.new(FIELD_KEYS[key], AES.MODE_ECB).encrypt(pad(rebuilt, 16)), cipher)
                        count += 1
                    else:
                        verify(raw, decoded)
            else:
                self.assertEqual(first, second)

        verify(original, readable)
        self.assertEqual(count, 4106)

    def test_typepack_rejects_bad_inputs(self):
        for data in (b'', b'\x09', b'\x07\x10a', b'\x03\xff', b'\x46\0\0'):
            with self.assertRaises(ValueError):
                TypePackReader(data).read()


if __name__ == '__main__':
    unittest.main(verbosity=2)

