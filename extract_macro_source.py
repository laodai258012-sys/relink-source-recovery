import hashlib
import json
import pathlib
import struct
import zipfile

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

ROOT = pathlib.Path(__file__).resolve().parent
KEY = b'ON7X6bhaTQVcO5oUBNlwmKqCJHzWIrDK'
SEED = 0x4AB145F8


def xor_stream(data):
    result = bytearray(data)
    state = SEED
    for index in range(len(result)):
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        result[index] ^= state & 255
    return bytes(result)


class TypePackReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0
        self.nodes = 0
        self.binary_fields = []
        self.string_fields = []

    def take(self, size):
        if size < 0 or self.offset + size > len(self.data):
            raise ValueError(f'Truncated TypePack at {self.offset}, requested {size}')
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def read(self, path='$', depth=0):
        if depth > 200:
            raise ValueError('TypePack nesting exceeds safety limit')
        start = self.offset
        tag = self.take(1)[0]
        self.nodes += 1
        kind = tag & 63
        width = 1 << (tag >> 6)
        if tag in (0, 1):
            return bool(tag)
        if kind not in (2, 3, 4, 5, 6, 7, 8):
            raise ValueError(f'Unknown TypePack tag {tag:02x} at {start}')
        raw = self.take(width)
        if kind == 6:
            if width not in (4, 8):
                raise ValueError('Reserved float tag')
            return struct.unpack('<f' if width == 4 else '<d', raw)[0]
        value = int.from_bytes(raw, 'little', signed=kind == 4)
        if kind in (4, 5):
            return value
        if kind in (7, 8):
            content = self.take(value)
            if kind == 8:
                filename = f'blobs/{len(self.binary_fields):04d}.bin'
                record = dict(path=path, file=filename, size=value, sha256=hashlib.sha256(content).hexdigest())
                self.binary_fields.append((record, content))
                return {'$binary': filename, 'size': value, 'sha256': record['sha256']}
            text = content.decode('utf-8', errors='strict')
            self.string_fields.append(dict(path=path, value=text, offset=start, bytes=value))
            return text
        if value > len(self.data) - self.offset:
            raise ValueError('Impossible collection size')
        if kind == 3:
            return [self.read(f'{path}[{index}]', depth + 1) for index in range(value)]
        result = {}
        for index in range(value):
            key = self.read(f'{path}.$key[{index}]', depth + 1)
            if not isinstance(key, str) or key in result:
                raise ValueError(f'Invalid or duplicate object key at {self.offset}')
            result[key] = self.read(f'{path}.{key}', depth + 1)
        return result


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')


def main():
    output = ROOT / 'recovered_source'
    output.mkdir(exist_ok=True)
    ciphertext = (ROOT / 'recovered_assets/resource_00.emacro').read_bytes()
    plain = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(xor_stream(ciphertext)), 16)
    rebuilt = xor_stream(AES.new(KEY, AES.MODE_ECB).encrypt(pad(plain, 16)))
    if rebuilt != ciphertext:
        raise ValueError('Encryption round-trip mismatch')
    reader = TypePackReader(plain)
    macro = reader.read()
    if reader.offset != len(plain):
        raise ValueError(f'Unparsed tail: {len(plain) - reader.offset}')
    (output / 'macro.decrypted.qim').write_bytes(plain)
    write_json(output / 'macro.full.json', macro)
    write_json(output / 'strings.full.json', reader.string_fields)
    scripts = []
    for field in reader.string_fields:
        if '.$key[' in field['path']:
            continue
        if field['value'] and (field['path'].endswith('.script') or field['path'].endswith('.qiml')):
            suffix = '.qiml' if field['path'].endswith('.qiml') else '.txt'
            filename = f'scripts/{len(scripts):04d}{suffix}'
            target = output / filename
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(field['value'].encode('utf-8'))
            scripts.append(dict(path=field['path'], file=filename, bytes=field['bytes']))
    for record, content in reader.binary_fields:
        target = output / record['file']
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(content)
    write_json(output / 'script_manifest.json', scripts)
    write_json(output / 'binary_manifest.json', [record for record, content in reader.binary_fields])
    manifest = dict(input='recovered_assets/resource_00.emacro', ciphertext_bytes=len(ciphertext),
                    plaintext_bytes=len(plain), plaintext_sha256=hashlib.sha256(plain).hexdigest(),
                    cipher='AES-256-ECB with PKCS#7, then XOR xorshift32 (13,17,5)',
                    key_ascii=KEY.decode(), seed=hex(SEED), loader_va='0x1400ef410',
                    xor_loop_va='0x1400ef730', aes_call_va='0x1400ef796',
                    encryption_roundtrip_equal=True, parsed_bytes=reader.offset,
                    total_nodes=reader.nodes, binary_fields=len(reader.binary_fields),
                    script_fields=len(scripts), root_keys=list(macro), native_execution=False)
    write_json(output / 'extraction_manifest.json', manifest)
    print(json.dumps(manifest, ensure_ascii=True, indent=2))
    print('Root summary:', [(key, type(value).__name__, len(value) if isinstance(value, (str, list, dict)) else value) for key, value in macro.items()])


if __name__ == '__main__':
    main()

