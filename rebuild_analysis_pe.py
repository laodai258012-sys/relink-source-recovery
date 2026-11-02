import collections
import hashlib
import json
import pathlib
import struct
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
BASE = 0x140000000


def align(value, boundary):
    return (value + boundary - 1) & -boundary


def main():
    output = ROOT / 'native_recovered'
    output.mkdir(exist_ok=True)
    report = json.loads((ROOT / 'static_extracted/inspection.json').read_text(encoding='utf-8'))
    status = json.loads((ROOT / 'emulation_analysis/emulation.json').read_text(encoding='utf-8'))
    with zipfile.ZipFile(ROOT / 'emulation_analysis/checkpoint.zip') as archive:
        state = json.loads(archive.read('state.json'))
    api_names = {int(address): tuple(value) for address, value in state['api_addresses'].items()}
    sections = []
    names = ['.text', '.rdata', '.data', '.pdata', '.mime', '.tlsdata', '.rsrc', '.extra']
    flags = [0x60000020, 0x40000040, 0xC0000040, 0x40000040, 0x40000040, 0xC0000040, 0x40000040, 0x40000040]
    for index, item in enumerate(report['sections'][:8]):
        data = bytearray((ROOT / f'emulation_analysis/section_{index:02d}_rva_{item["address"]:08x}.bin').read_bytes())
        sections.append(dict(name=names[index], rva=item['address'], data=data, flags=flags[index]))
    imports = []
    for section in sections:
        if section['name'] not in ('.rdata', '.data'):
            continue
        data = section['data']
        for offset in range(0, len(data) - 7, 8):
            value = struct.unpack_from('<Q', data, offset)[0]
            if value in api_names:
                library, symbol = api_names[value]
                imports.append(dict(rva=section['rva'] + offset, library=library, symbol=symbol))
    groups = []
    for item in imports:
        if groups and groups[-1][-1]['rva'] + 8 == item['rva'] and groups[-1][-1]['library'] == item['library']:
            groups[-1].append(item)
        else:
            groups.append([item])
    import_rva = align(sections[-1]['rva'] + len(sections[-1]['data']), 4096)
    import_data = bytearray(20 * (len(groups) + 1))

    def append(content, boundary=1):
        import_data.extend(bytes(align(len(import_data), boundary) - len(import_data)))
        address = import_rva + len(import_data)
        import_data.extend(content)
        return address

    for group_index, group in enumerate(groups):
        library_rva = append(group[0]['library'].encode('ascii') + b'\0')
        thunks = []
        for item in group:
            symbol = item['symbol']
            thunk = (1 << 63) | symbol if isinstance(symbol, int) else append(b'\0\0' + symbol.encode('ascii') + b'\0', 2)
            thunks.append(thunk)
            for section in sections:
                if section['rva'] <= item['rva'] < section['rva'] + len(section['data']):
                    struct.pack_into('<Q', section['data'], item['rva'] - section['rva'], thunk)
                    break
        table_rva = append(struct.pack('<' + 'Q' * (len(thunks) + 1), *thunks, 0), 8)
        struct.pack_into('<IIIII', import_data, group_index * 20, table_rva, 0, 0, library_rva, group[0]['rva'])
    sections.append(dict(name='.reimp', rva=import_rva, data=import_data, flags=0x40000040))
    original = next(ROOT.glob('*.exe')).read_bytes()
    pe = struct.unpack_from('<I', original, 60)[0]
    optional = pe + 24
    optional_size = struct.unpack_from('<H', original, pe + 20)[0]
    section_table = optional + optional_size
    header_size = align(section_table + 40 * len(sections), 512)
    header = bytearray(original[:header_size])
    struct.pack_into('<H', header, pe + 6, len(sections))
    struct.pack_into('<I', header, optional + 16, 0)
    struct.pack_into('<II', header, optional + 56, align(import_rva + len(import_data), 4096), header_size)
    struct.pack_into('<I', header, optional + 64, 0)
    header[optional + 112:optional + 240] = bytes(128)
    struct.pack_into('<II', header, optional + 112 + 8, import_rva, 20 * (len(groups) + 1))
    struct.pack_into('<II', header, optional + 112 + 16, sections[6]['rva'], len(sections[6]['data']))
    struct.pack_into('<II', header, optional + 112 + 24, sections[3]['rva'], len(sections[3]['data']))
    raw_offset = header_size
    for index, section in enumerate(sections):
        section['raw_offset'] = raw_offset
        size = align(len(section['data']), 512)
        struct.pack_into('<8sIIIIIIHHI', header, section_table + index * 40,
                         section['name'].encode(), len(section['data']), section['rva'], size, raw_offset,
                         0, 0, 0, 0, section['flags'])
        raw_offset += size
    target = output / 'reconstructed.analysis.pe'
    with target.open('wb') as stream:
        stream.write(header)
        for section in sections:
            stream.write(section['data'])
            stream.write(bytes(align(len(section['data']), 512) - len(section['data'])))
    functions = list(struct.iter_unpack('<III', sections[3]['data']))
    with (output / 'function_index.csv').open('w', encoding='ascii', newline='') as stream:
        stream.write('start_rva,end_rva,unwind_rva\n')
        for start, end, unwind in functions:
            stream.write(f'{start:x},{end:x},{unwind:x}\n')
    (output / 'imports.json').write_text(json.dumps(imports, indent=2), encoding='utf-8')
    manifest = dict(analysis_only=True, entry_point=0, note='Not a runnable unpacked application. TLS/protector entry not executed. Import names resolved from modeled export metadata; aliases may differ from original.',
                    functions=len(functions), recovered_import_slots=len(imports), import_groups=len(groups),
                    pe_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                    original_sha256=report['sha256'], last_stop=status['events'][-1],
                    sections=[dict(name=item['name'], rva=hex(item['rva']), size=len(item['data'])) for item in sections])
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()

