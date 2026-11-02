import hashlib
import json
import pathlib
import struct
import zipfile

source = next(pathlib.Path(__file__).parent.glob('*.exe'))
data = source.read_bytes()
output = source.parent / 'static_extracted'
output.mkdir(exist_ok=True)
pe = struct.unpack_from('<I', data, 60)[0]
count = struct.unpack_from('<H', data, pe + 6)[0]
optional_size = struct.unpack_from('<H', data, pe + 20)[0]
sections = []
for index in range(count):
    name, virtual_size, address, size, offset = struct.unpack_from('<8sIIII', data, pe + 24 + optional_size + index * 40)
    sections.append(dict(name=name.rstrip(b'\0').decode('ascii'), virtual_size=virtual_size, address=address, size=size, offset=offset))

def file_offset(address):
    for section in sections:
        if section['address'] <= address < section['address'] + section['size']:
            return section['offset'] + address - section['address']
    raise ValueError(f'Unmapped RVA: {address:#x}')

root = file_offset(struct.unpack_from('<I', data, pe + 24 + 112 + 16)[0])
resources = {}

def walk(relative=0, path=()):
    position = root + relative
    named, numbered = struct.unpack_from('<HH', data, position + 12)
    for index in range(named + numbered):
        name, target = struct.unpack_from('<II', data, position + 16 + index * 8)
        if name & 0x80000000:
            location = root + (name & 0x7fffffff)
            length = struct.unpack_from('<H', data, location)[0]
            name = data[location + 2:location + 2 + length * 2].decode('utf-16le')
        current = path + (name,)
        if target & 0x80000000:
            walk(target & 0x7fffffff, current)
        else:
            address, length = struct.unpack_from('<II', data, root + target)
            start = file_offset(address)
            resources[current] = data[start:start + length]

walk()
manifest = []
for path, payload in resources.items():
    extension = '.manifest' if path[0] == 24 else '.bin'
    if payload.startswith(b'\x89PNG\r\n\x1a\n'):
        extension = '.png'
    filename = 'resource_' + '_'.join(map(str, path)) + extension
    (output / filename).write_bytes(payload)
    manifest.append(dict(path=path, size=len(payload), file=filename))
    if path[0] == 14:
        count = struct.unpack_from('<H', payload, 4)[0]
        header = bytearray(payload[:6])
        images = bytearray()
        for index in range(count):
            entry = payload[6 + index * 14:20 + index * 14]
            image_id = struct.unpack_from('<H', entry, 12)[0]
            image = resources[(3, image_id, path[2])]
            header.extend(entry[:8] + struct.pack('<II', len(image), 6 + count * 16 + len(images)))
            images.extend(image)
        (output / 'application.ico').write_bytes(header + images)
report = dict(source=source.name, size=len(data), sha256=hashlib.sha256(data).hexdigest(), sections=sections, resources=manifest, source_code_recovered=False)
(output / 'inspection.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
(output / 'README.txt').write_text('静态提取结果（未执行原程序）\n\n没有恢复出源码。图标、PNG 和程序清单均为资源，不是源码。\n文件是 Windows x64 PE，含 .winlice 和 .boot 节，存在加壳迹象。\n多数主要节呈高熵，支持压缩或加密判断；未确认保护器版本和开发语言。\n未发现明文 PyInstaller 标记及常见 ZIP/7z 文件头；CLR 目录为空。\n不能排除被加密隐藏的脚本或程序集。已导出 9 项资源并重建图标。\ninspection.json 包含文件哈希和结构。进一步恢复逻辑需要脱壳和逆向分析，或取得未加壳文件/原始工程。\n本脚本仅针对本次样本结构。\n', encoding='utf-8')
with zipfile.ZipFile(source.parent / 'static_extracted.zip', 'w', zipfile.ZIP_DEFLATED) as bundle:
    for extracted in sorted(output.iterdir()):
        bundle.write(extracted, extracted.name)
print('Extracted', len(resources), 'resources. Source code recovered: False')
