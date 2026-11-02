import gzip
import hashlib
import json
import pathlib
import struct
import zipfile


ROOT = pathlib.Path(__file__).parent
SOURCE = ROOT / 'emulation_analysis'
OUTPUT = ROOT / 'recovered_assets'
OUTPUT.mkdir(exist_ok=True)
sections = json.loads((ROOT / 'static_extracted/inspection.json').read_text(encoding='utf-8'))['sections']
blobs = {}
for index, section in enumerate(sections):
    path = SOURCE / f'section_{index:02d}_rva_{section["address"]:08x}.bin'
    if path.exists():
        blobs[index] = path.read_bytes()


def read_rva(address, length):
    for index, raw in blobs.items():
        start = sections[index]['address']
        if start <= address and address + length <= start + len(raw):
            return raw[address-start:address-start+length]
    raise ValueError(f'Unmapped resource data: {address:x}')


raw = blobs[6]
resources = []
visited = set()


def walk(relative=0, path=()):
    if relative in visited or len(path) > 8:
        raise ValueError('Invalid resource directory')
    visited.add(relative)
    named, numbered = struct.unpack_from('<HH', raw, relative + 12)
    if named + numbered > 10000:
        raise ValueError('Too many resource entries')
    for index in range(named + numbered):
        name, target = struct.unpack_from('<II', raw, relative + 16 + index * 8)
        if name & 0x80000000:
            offset = name & 0x7fffffff
            length = struct.unpack_from('<H', raw, offset)[0]
            name = raw[offset+2:offset+2+length*2].decode('utf-16le')
        current = path + (name,)
        if target & 0x80000000:
            walk(target & 0x7fffffff, current)
        else:
            address, length, codepage, reserved = struct.unpack_from('<IIII', raw, target)
            payload = read_rva(address, length)
            extension = '.bin'
            if payload.startswith(b'MZ'):
                extension = '.pe.bin'
            elif payload.startswith(b'\x89PNG\r\n\x1a\n'):
                extension = '.png'
            elif payload.startswith(b'RIFF') and payload[8:12] == b'WAVE':
                extension = '.wav'
            elif current[0] == 'TEXT' and current[1] == 'CONFIG':
                json.loads(payload)
                extension = '.json'
            elif current[0] == 'EMACRO':
                extension = '.emacro'
            elif current[0] == 'OCR' and current[1] == 'OCR_KEY':
                payload.decode('utf-8')
                extension = '.txt'
            elif current[0] == 24:
                extension = '.manifest'
            filename = f'resource_{len(resources):02d}' + extension
            (OUTPUT / filename).write_bytes(payload)
            resources.append(dict(path=current, rva=hex(address), size=length, filename=filename,
                                  sha256=hashlib.sha256(payload).hexdigest()))


walk()
(OUTPUT / 'resource_manifest.json').write_text(json.dumps(resources, indent=2, ensure_ascii=False), encoding='utf-8')
(OUTPUT / 'decompressed_mime_database.xml').write_bytes(gzip.decompress(blobs[4]))
(OUTPUT / 'README.md').write_text(
    '# 主程序还原后的内嵌资源\n\n'
    '这些是从还原后的原程序资源区提取的数据，并不等同于原始 C++ 工程。\n'
    'resource_manifest.json 记录每项原资源类型、名称、RVA、大小和校验值。\n'
    '包含 EMACRO 宏数据、内嵌资源程序、OCR 数据、配置 JSON、图片、音频和清单。\n'
    '尚未把 EMACRO 数据证明为可读脚本；内嵌 PE 以 .pe.bin 保存，未运行。\n'
    'decompressed_mime_database.xml 是 gzip 节中的 MIME 数据库，不是业务源码。\n', encoding='utf-8')
with zipfile.ZipFile(ROOT / 'recovered_assets.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(OUTPUT.iterdir()):
        archive.write(path, path.name)
print('Extracted',len(resources),'original resources')
for entry in resources:
    print(entry['path'],entry['size'],entry['filename'])

