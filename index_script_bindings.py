import bisect
import json
import pathlib
import re
import struct

ROOT = pathlib.Path(__file__).resolve().parent


def main():
    output = ROOT / 'native_recovered'
    fields = json.loads((ROOT / 'recovered_source/inner_fields.json').read_text(encoding='utf-8'))
    macro = json.loads((ROOT / 'recovered_source/macro.readable.json').read_text(encoding='utf-8'))
    texts = [item['plaintext'] for item in fields if item['name'] in ('script', 'condition')] + [macro['script']]
    names = sorted({name for text in texts for name in re.findall(r'\b([A-Za-z_][A-Za-z_0-9]*)\s*\(', text)})
    rdata = (ROOT / 'emulation_analysis/section_01_rva_01ebb000.bin').read_bytes()
    text = (ROOT / 'emulation_analysis/section_00_rva_00001000.bin').read_bytes()
    functions = list(struct.iter_unpack('<III', (ROOT / 'emulation_analysis/section_03_rva_02d8f000.bin').read_bytes()))
    starts = [record[0] for record in functions]
    targets = {}
    result = {name: dict(literal_addresses=[], references=[]) for name in names}
    for name in names:
        for encoding in ('ascii', 'utf-16le'):
            needle = name.encode(encoding) + (b'\0' if encoding == 'ascii' else b'\0\0')
            position = rdata.find(needle)
            while position >= 0:
                address = 0x141EBB000 + position
                targets[address] = name
                result[name]['literal_addresses'].append(dict(address=hex(address), encoding=encoding))
                position = rdata.find(needle, position + 1)
    for match in re.finditer(rb'[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        offset = match.start()
        if offset + 7 > len(text):
            continue
        target = 0x140001000 + offset + 7 + struct.unpack_from('<i', text, offset + 3)[0]
        if target not in targets:
            continue
        index = bisect.bisect_right(starts, offset + 0x1000) - 1
        function = functions[index] if index >= 0 else None
        if function and not function[0] <= offset + 0x1000 < function[1]:
            function = None
        result[targets[target]]['references'].append(dict(instruction=hex(0x140001000 + offset),
                function_rva=hex(function[0]) if function else None,
                decompiled_file=f'decompiled/{function[0]:x}.c' if function else None))
    (output / 'script_api_references.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Script API names:', len(names), 'References:', sum(len(item['references']) for item in result.values()))


if __name__ == '__main__':
    main()

