import hashlib
import json
import pathlib
import re
import struct
import zipfile

import capstone


root = pathlib.Path(__file__).parent
output = root / 'deep_analysis'
original = next(root.glob('*.exe')).read_bytes()
layer = (output / 'winlice_layer1.bin').read_bytes()
metadata = json.loads((output / 'layer1.json').read_text(encoding='utf-8'))
sections = json.loads((root / 'static_extracted/inspection.json').read_text(encoding='utf-8'))['sections']


def original_offset(address):
    for section in sections:
        if section['address'] <= address < section['address'] + section['size']:
            return section['offset'] + address - section['address']
    raise ValueError('Unmapped address')


def read_string(position):
    return original[position:original.index(b'\0', position)].decode('ascii', errors='replace')


pe_offset = struct.unpack_from('<I', original, 60)[0]
import_rva = struct.unpack_from('<I', original, pe_offset + 24 + 112 + 8)[0]
imports = []
position = original_offset(import_rva)
while True:
    lookup, timestamp, forwarder, name, table = struct.unpack_from('<IIIII', original, position)
    if not any((lookup, timestamp, forwarder, name, table)):
        break
    symbols = []
    pointer = original_offset(lookup or table)
    while True:
        value = struct.unpack_from('<Q', original, pointer)[0]
        if not value:
            break
        symbols.append('#' + str(value & 65535) if value >> 63 else read_string(original_offset(value) + 2))
        pointer += 8
    imports.append(dict(library=read_string(original_offset(name)), symbols=symbols))
    position += 20
(output / 'imports.json').write_text(json.dumps(imports, indent=2), encoding='utf-8')
engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
engine.detail = True
loader_lines = [f'{instruction.address:016x}: {instruction.mnemonic} {instruction.op_str}'
                for instruction in engine.disasm(original[40734208+0x58:40734208+0x248], 0x146244058)]
(output / 'outer_loader.asm').write_text('\n'.join(loader_lines) + '\n', encoding='utf-8')
base = 0x14423c000
address = base + 0x342f65
trace = []
visited = set()
for index in range(400):
    if address in visited:
        trace.append('STOP: previously visited address')
        break
    visited.add(address)
    offset = address - base
    if not 0 <= offset < len(layer):
        trace.append('STOP: outside the restored layer')
        break
    instruction = next(engine.disasm(layer[offset:offset+16], address), None)
    if instruction is None:
        trace.append('STOP: invalid instruction')
        break
    trace.append(f'{address:016x}: {instruction.mnemonic} {instruction.op_str}')
    if instruction.mnemonic in ('jmp', 'call') and instruction.op_str.startswith('0x'):
        if instruction.mnemonic == 'call':
            trace.append('; Static descent into call target; no code is executed.')
        address = int(instruction.op_str, 16)
    elif instruction.group(capstone.CS_GRP_JUMP) or instruction.group(capstone.CS_GRP_RET):
        trace.append('STOP: branch/return requires runtime state; this is not a full execution path.')
        break
    else:
        address += instruction.size
(output / 'protected_entry_trace.asm').write_text('\n'.join(trace) + '\n', encoding='utf-8')
helper = layer[0x2c44e:0x2c44e+0xe00]
(output / 'embedded_helper.pe.bin').write_bytes(helper)
helper_engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
helper_lines = [f'{instruction.address:08x}: {instruction.mnemonic} {instruction.op_str}'
                for instruction in helper_engine.disasm(helper[0x400:0x620], 0x401000)]
(output / 'embedded_helper_text.asm').write_text('\n'.join(helper_lines) + '\n', encoding='utf-8')
evidence = []
for match in re.finditer(rb'[\x20-\x7e]{6,}', layer):
    text = match.group().decode('ascii')
    if re.search(r'(?i)winlicense|kernel32|\.pdb$', text):
        evidence.append(dict(offset=hex(match.start()), value=text))
(output / 'string_evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
assert len(layer) == 33587200
assert sum(chunk['decompressed_size'] for chunk in metadata['chunks']) == len(layer)
assert metadata['decompressed_sha256'] == hashlib.sha256(layer).hexdigest()
assert metadata['compressed_end'] <= 40734208 + 23131648
for before, after in zip(metadata['chunks'], metadata['chunks'][1:]):
    assert before['source_offset'] + before['compressed_size'] == after['source_offset']
    assert before['destination_offset'] + before['decompressed_size'] == after['destination_offset']
report = f'''# 深入静态分析结果

## 结论

已离线解开外层压缩，恢复 **{len(layer):,} 字节（约 32 MiB）的保护层数据**。
这不是业务源码，也不是已完成脱壳的可运行 EXE。
恢复的数据中出现多处 Software\\WinLicense、WinLicenseVersion、WinLicenseDriverVersion 字符串，结合原文件 .winlice 节，强烈支持 WinLicense 保护判断；未确认具体版本。
整个过程没有启动原始 EXE 或内嵌程序，没有修改原文件，也没有将样本上传到外部服务。

## 已完成的恢复

1. 反汇编原始入口 RVA 0x6244058，还原其位流解压逻辑。
2. 从原文件偏移 0x{metadata['compressed_start']:x} 开始解码 **20 个连续数据块**，每块输出 **1,679,360 字节**。
3. 输出大小与 .winlice 节虚拟大小 **33,587,200 字节**完全一致。
4. 还原数据映射到 RVA 0x423c000，后续入口为 RVA 0x457ef65。
5. 从还原数据偏移 0x2c44e 提取一个 **3,584 字节的 x86 PE**，以 .pe.bin 保存，避免被误当成可直接启动的交付程序。该文件可见 CreateProcessA、TerminateProcess 等导入，不能据此把它认定为业务主体。
6. 导出原文件 **{len(imports)} 个导入库**和反汇编记录。每个库仅有一个可见导入项，不能据此判断程序完整功能。

## 交付文件

- offline_unpack.py：按此样本入口逻辑重建的离线解压脚本，是本次编写的分析代码，**不是作者原始源码**。仅使用 Python 标准库，并检查输入文件 SHA-256。
- analyze_unpacked.py：生成导入信息、证据和反汇编的辅助脚本，需要本机已有的 capstone，以及前次提取的 static_extracted/inspection.json。
- winlice_layer1.bin：恢复的保护层原始数据，不能作为独立 EXE 运行。
- layer1.json：数据块位置、尺寸、SHA-256 和后续入口信息。
- outer_loader.asm：外层解压入口反汇编。
- protected_entry_trace.asm：后续入口的有限静态跟踪；遇到依赖运行时状态的分支即停止。
- embedded_helper.pe.bin、embedded_helper_text.asm：小型内嵌 PE 及其代码段的线性反汇编。
- imports.json、string_evidence.json：导入表及保护层字符串证据。

## 验证结果

- 位流解码器通过固定输入的已知输出测试。
- 20 块输入位置连续、输出位置连续；解压结果大小精确匹配目标节。
- 解压数据 SHA-256：{metadata['decompressed_sha256']}。
- 原样本 SHA-256：{metadata['source_sha256']}。
- 所有核验均为静态数据处理，不等同于原程序运行测试。

## 尚未恢复的内容与下一步

业务函数、原始工程、变量名称和源码文件尚未恢复。后续入口仍有大量跳转、间接控制流和混淆代码；现有静态跟踪不足以还原其运行时状态。
继续恢复需要进一步分析保护层的解密/调度逻辑，或者在**无敏感数据、可回滚的隔离虚拟机**里进行受控动态分析，再定位原始入口并修复导入表。
当前没有执行该动态步骤。即使完成脱壳，也不能承诺得到逐字一致的原始源码；应区分反汇编、反编译伪代码与原始工程。
'''
(output / 'REPORT.md').write_text(report, encoding='utf-8')
with zipfile.ZipFile(root / 'deep_analysis.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(output.iterdir()):
        archive.write(path, path.name)
    archive.write(root / 'offline_unpack.py', 'offline_unpack.py')
    archive.write(root / 'analyze_unpacked.py', 'analyze_unpacked.py')
    archive.write(root / 'static_extracted/inspection.json', 'static_extracted/inspection.json')
print('Verified restored layer and exported', len(imports), 'import libraries')
print('Archive:', root / 'deep_analysis.zip')

