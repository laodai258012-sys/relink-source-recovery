import bisect
import collections
import io
import json
import pathlib
import re
import struct
import zipfile

import capstone

ROOT = pathlib.Path(__file__).resolve().parent


def main():
    native = ROOT / 'native_recovered'
    records = list(struct.iter_unpack('<III', (ROOT / 'emulation_analysis/section_03_rva_02d8f000.bin').read_bytes()))
    starts = [record[0] for record in records]
    text = (ROOT / 'emulation_analysis/section_00_rva_00001000.bin').read_bytes()
    end_text = 0x1000 + len(text)
    candidates = collections.defaultdict(set)

    def add(address, reason):
        rva = address - 0x140000000
        if not 0x1000 <= rva < end_text:
            return
        index = bisect.bisect_right(starts, rva) - 1
        if index >= 0 and rva < records[index][1]:
            return
        if text[rva-0x1000] in (0, 0xcc):
            return
        candidates[rva].add(reason)

    with zipfile.ZipFile(native / 'all_functions_assembly.zip') as archive:
        with archive.open('all_functions.asm') as binary:
            for line in io.TextIOWrapper(binary, encoding='utf-8'):
                match = re.search(r'  (call|jmp) 0x([0-9a-f]+)$', line.rstrip())
                if match:
                    add(int(match.group(2), 16), 'direct_' + match.group(1))
    for name in ('section_01_rva_01ebb000.bin', 'section_02_rva_02c8d000.bin', 'section_07_rva_041e9000.bin'):
        data = (ROOT / 'emulation_analysis' / name).read_bytes()
        for offset in range(0, len(data)-7, 8):
            value = struct.unpack_from('<Q', data, offset)[0]
            if 0x140001000 <= value < 0x140000000 + end_text:
                add(value, 'aligned_code_pointer')
    sorted_candidates = sorted(candidates)
    result = []
    for index, rva in enumerate(sorted_candidates):
        next_known = bisect.bisect_right(starts, rva)
        limit = records[next_known][0] if next_known < len(records) else end_text
        if index + 1 < len(sorted_candidates):
            limit = min(limit, sorted_candidates[index+1])
        if limit > rva:
            result.append(dict(rva=f'{rva:x}', end_rva=f'{limit:x}', reasons=sorted(candidates[rva])))
    (native / 'leaf_candidates.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    with (native / 'leaf_candidate_index.csv').open('w', encoding='ascii') as stream:
        stream.write('start_rva,end_rva,unwind_rva\n')
        for record in result:
            stream.write(f'{record["rva"]},{record["end_rva"]},0\n')
    print('Additional leaf/thunk candidates:', len(result))
    print('Candidate bytes:', sum(int(record['end_rva'],16)-int(record['rva'],16) for record in result))
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.skipdata = True
    with zipfile.ZipFile(native / 'leaf_candidates_assembly.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        with archive.open('leaf_candidates.asm', 'w') as binary:
            with io.TextIOWrapper(binary, encoding='utf-8', newline='\n') as stream:
                for record in result:
                    start = int(record['rva'], 16)
                    end = int(record['end_rva'], 16)
                    stream.write(f'\ncandidate_{start:x}:\n')
                    for address, size, mnemonic, operands in decoder.disasm_lite(text[start-0x1000:end-0x1000], 0x140000000 + start):
                        stream.write(f'{address:016x}  {mnemonic} {operands}\n')
        archive.write(native / 'leaf_candidates.json', 'leaf_candidates.json')
    intervals = [(begin, end) for begin, end, unwind in records]
    intervals += [(int(record['rva'], 16), int(record['end_rva'], 16)) for record in result]
    gaps = []
    cursor = 0x1000
    for begin, end in sorted(intervals):
        if begin > cursor:
            gaps.append((cursor, begin))
        cursor = max(cursor, end)
    if cursor < end_text:
        gaps.append((cursor, end_text))
    coverage = dict(text_bytes=len(text), exception_range_bytes=sum(end-begin for begin,end,unwind in records),
                    candidate_range_bytes=sum(int(record['end_rva'],16)-int(record['rva'],16) for record in result),
                    other_range_bytes=sum(end-begin for begin,end in gaps), other_range_count=len(gaps),
                    note='Other ranges may contain alignment padding, tables, prologues or unidentified code; no complete original source claim is made.')
    (native / 'text_range_coverage.json').write_text(json.dumps(coverage, indent=2), encoding='utf-8')
    with zipfile.ZipFile(native / 'unclassified_text.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        with archive.open('text_gaps.hex', 'w') as binary:
            with io.TextIOWrapper(binary, encoding='ascii', newline='\n') as stream:
                for begin, end in gaps:
                    stream.write(f'\nrange {begin:x}..{end:x}\n')
                    for offset in range(begin, end, 16):
                        stream.write(f'{0x140000000+offset:016x} {text[offset-0x1000:min(offset+16,end)-0x1000].hex()}\n')
        archive.write(native / 'text_range_coverage.json', 'coverage.json')


if __name__ == '__main__':
    main()

