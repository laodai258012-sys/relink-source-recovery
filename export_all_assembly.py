import io
import pathlib
import struct
import zipfile

import capstone

ROOT = pathlib.Path(__file__).resolve().parent


def main():
    text = (ROOT / 'emulation_analysis/section_00_rva_00001000.bin').read_bytes()
    pdata = (ROOT / 'emulation_analysis/section_03_rva_02d8f000.bin').read_bytes()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.skipdata = True
    instruction_count = 0
    function_count = 0
    target = ROOT / 'native_recovered/all_functions_assembly.zip'
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED, compresslevel=5) as archive:
        with archive.open('all_functions.asm', 'w', force_zip64=True) as binary_stream:
            with io.TextIOWrapper(binary_stream, encoding='utf-8', newline='\n') as stream:
                for start, end, unwind in struct.iter_unpack('<III', pdata):
                    if not 0x1000 <= start < end <= 0x1000 + len(text):
                        raise ValueError(f'Invalid function range {start:x}..{end:x}')
                    function_count += 1
                    stream.write(f'\nrecovered_{start:x}:\n')
                    covered = 0
                    for address, size, mnemonic, operands in decoder.disasm_lite(text[start-0x1000:end-0x1000], 0x140000000 + start):
                        stream.write(f'{address:016x}  {mnemonic} {operands}\n')
                        instruction_count += 1
                        covered += size
                    if covered != end-start:
                        raise ValueError(f'Unconsumed bytes in function {start:x}')
                    if function_count % 20000 == 0:
                        print('Functions disassembled:', function_count, flush=True)
        archive.write(ROOT / 'native_recovered/function_index.csv', 'function_index.csv')
        archive.writestr('README.txt', f'{function_count} exception-table function ranges disassembled. {instruction_count} decoded instructions/data directives.\nThis is assembly, not original C++ source. Data gaps outside the ranges remain in reconstructed.analysis.pe.\n')
    print('Completed:', function_count, instruction_count, target.stat().st_size)


if __name__ == '__main__':
    main()

