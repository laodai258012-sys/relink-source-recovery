import collections
import csv
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent


def rows(path):
    with path.open(encoding='utf-8', newline='') as stream:
        return list(csv.DictReader(stream, delimiter='\t'))


def main():
    native = ROOT / 'native_recovered'
    original_digest = hashlib.sha256(next(ROOT.glob('*.exe')).read_bytes()).hexdigest()
    if original_digest != '15405f1cd736f38ee315469e0b3eeddb87fd179103dc642acadd9440ccc6e696':
        raise ValueError('Original EXE hash changed')
    tested = subprocess.run([sys.executable, '-m', 'unittest', 'test_recovery', '-v'], cwd=ROOT, capture_output=True, text=True, timeout=60)
    (native / 'test_report.txt').write_text(tested.stdout + tested.stderr, encoding='utf-8')
    if tested.returncode:
        raise ValueError('Recovery validation tests failed')
    with (native / 'function_index.csv').open() as stream:
        expected = {record['start_rva'] for record in csv.DictReader(stream)}
    effective = {}
    for name in ('decompile_status_1000.tsv', 'remaining_status.tsv', 'retry_status.tsv'):
        for record in rows(native / name):
            effective[record['rva']] = record
    if set(effective) != expected:
        raise ValueError(f'Native coverage incomplete: {len(expected - set(effective))} missing, {len(set(effective)-expected)} unexpected')
    successful = {address for address, record in effective.items() if record['status'] == 'ok'}
    failures = [record for record in effective.values() if record['status'] != 'ok']
    helper_rows = rows(ROOT / 'native_resource_helper/decompile_status_1000.tsv')
    leaf_rows = rows(native / 'leaf_status.tsv')
    leaf_candidates = json.loads((native / 'leaf_candidates.json').read_text(encoding='utf-8'))
    if {record['rva'] for record in leaf_rows} != {record['rva'] for record in leaf_candidates}:
        raise ValueError('Leaf candidate coverage incomplete')
    leaf_successful = {record['rva'] for record in leaf_rows if record['status'] == 'ok'}
    leaf_failures = [record for record in leaf_rows if record['status'] != 'ok']
    macro = json.loads((ROOT / 'recovered_source/inner_verification.json').read_text(encoding='utf-8'))
    coverage = json.loads((native / 'text_range_coverage.json').read_text(encoding='utf-8'))
    if coverage['text_bytes'] != coverage['exception_range_bytes'] + coverage['candidate_range_bytes'] + coverage['other_range_bytes']:
        raise ValueError('Text range accounting mismatch')
    summary = dict(original_sha256='15405f1cd736f38ee315469e0b3eeddb87fd179103dc642acadd9440ccc6e696',
                   date='2026-11-02', macro=macro, native_functions_attempted=len(effective),
                   native_pseudocode_success=len(successful), native_pseudocode_failed=len(failures),
                   native_assembly_functions=len(expected), resource_editor_functions=len(helper_rows),
                   additional_leaf_candidates=len(leaf_rows), additional_leaf_success=len(leaf_successful),
                   additional_leaf_failed=len(leaf_failures),
                   text_range_coverage=coverage,
                   resource_editor_success=sum(record['status'] == 'ok' for record in helper_rows),
                   original_cpp_project_recovered=False, native_sample_executed=False,
                   sample_server_contacted=False, limitations=['C pseudocode is not original C++ and is not guaranteed compilable.',
                    'Exception table ranges may be fragments rather than whole source functions; leaf functions without unwind records can exist outside this list.',
                    'No PDB, original variable names, original comments, build project, or server source is recovered.'])
    (native / 'final_verification.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    all_failures = [dict(origin='exception_table', **record) for record in failures]
    all_failures += [dict(origin='leaf_candidate', **record) for record in leaf_failures]
    (native / 'decompile_failures.json').write_text(json.dumps(all_failures, ensure_ascii=False, indent=2), encoding='utf-8')
    target = native / 'all_native_pseudocode.zip'
    written = set()
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED, compresslevel=3) as archive:
        for name in ('retry_decompiled.zip', 'remaining_decompiled.zip'):
            with zipfile.ZipFile(native / name) as source:
                for entry in source.infolist():
                    address = pathlib.PurePosixPath(entry.filename).stem
                    if address in successful and address not in written:
                        archive.writestr('main/' + address + '.c', source.read(entry))
                        written.add(address)
        for path in (native / 'decompiled').glob('*.c'):
            if path.stem in successful and path.stem not in written:
                archive.write(path, 'main/' + path.name)
                written.add(path.stem)
        if written != successful:
            raise ValueError('Missing C output despite successful status')
        with zipfile.ZipFile(native / 'leaf_decompiled.zip') as source:
            leaf_written = set()
            for entry in source.infolist():
                address = pathlib.PurePosixPath(entry.filename).stem
                if address in leaf_successful:
                    archive.writestr('leaf_candidates/' + address + '.c', source.read(entry))
                    leaf_written.add(address)
            if leaf_written != leaf_successful:
                raise ValueError('Missing leaf candidate output')
        for path in (ROOT / 'native_resource_helper/decompiled').glob('*.c'):
            archive.write(path, 'resource_editor/' + path.name)
        archive.write(native / 'decompile_failures.json', 'decompile_failures.json')
        archive.write(native / 'final_verification.json', 'verification.json')
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None:
            raise ValueError('Pseudocode archive CRC failure')
    readme = f'''# Relink 源码提取总包

## 结果与边界

- 嵌入宏：完整恢复 2,281 个动作、808 处脚本、585 处条件、432 个备注、界面定义及初始化脚本。
- 外层 335,611 字节完整解析；所有 4,106 个内层字段重新加密后均与输入一致。
- 原生程序：异常表列出的 {len(effective):,} 个地址范围全部完成反编译尝试，其中 {len(successful):,} 个成功生成 C 风格伪代码，{len(failures)} 个未成功，失败清单逐项列出。
- 全部 {len(expected):,} 个异常表范围均另有反汇编，无论 C 伪代码是否成功。
- 另外通过直接调用/跳转和静态代码指针找到 {len(leaf_rows):,} 个不在异常表内的叶函数/跳板候选，已全部尝试，其中 {len(leaf_successful):,} 个生成伪代码；候选身份不保证等于独立源函数。
- 资源编辑器：430 个异常表函数全部生成伪代码。
- 另有重建的 x86 重启助手 C 文件、22 项程序资源及公开上游参考源码。

这些结果不是原作者可直接重新编译的完整 C++ 工程。函数名、类型、变量名和控制流可能是反编译器推断；注释、原始源文件划分、项目配置及服务端源码无法从本 EXE 自动恢复。
异常表记录也可能是函数片段，并不等于原始源函数数量；无展开记录的叶函数不一定在该列表中。完整 .text 字节保留在 analysis.pe 中。

## 目录

- recovered_source/：首先查看 README.md、macro.readable.json、actions.readable.txt，以及 scripts/、action_scripts/。
- native_recovered/all_native_pseudocode.zip：全部成功导出的主程序和资源编辑器 C 伪代码，文件名为 RVA。
- native_recovered/all_functions_assembly.zip：全部异常表记录对应的反汇编和地址索引。
- native_recovered/leaf_candidates_assembly.zip：额外候选范围的反汇编；unclassified_text.zip 另保留其余代码区字节（可能是填充、数据表或未识别代码），没有把它们隐藏或算作已恢复源码。
- native_recovered/reconstructed.analysis.pe：仅供静态分析的重建 PE；入口点刻意设为零，不能当成脱壳可运行程序。
- native_recovered/decompile_failures.json：C 伪代码失败记录，对应机器码仍在反汇编/PE 中。
- recovered_assets.zip：模型、字典、配置、图片、音频和原始加密宏等资源。
- recovered_helper/：重建的小型 x86 助手 C 源码与说明。
- upstream_reference/：固定提交的 Quickinput 上游，只用于参考，不冒充本 EXE 私有分支源码。
- tools/：提取、解密、核验及反编译脚本；运行完整链路需要原 EXE、对应依赖和原工作目录结构。

## 安全与复现

未启动原 EXE，也未执行宏；保护层通过受限 CPU 模拟恢复，系统 API 由内存模型替代。未连接程序内置服务器。
不分发包含宿主系统 DLL 内存的模拟检查点。分析 PE 的导入表采用模型导出名重建，可能与原别名不同。
工具脚本是本次重建的分析代码，不是原程序作者源码。依赖版本见 tools/requirements-recovery.txt，Ghidra 使用 11.0.3 / JDK 17。
测试包含 TypePack 边界条件、已知明文、完整宏校验及 XOR 算法与原生机器码的独立交叉校验。
原文件 SHA256：{summary['original_sha256']}。
'''
    (ROOT / 'RECOVERY_REPORT.md').write_text(readme, encoding='utf-8')
    bundle = ROOT / 'source_recovery_bundle.zip'
    with zipfile.ZipFile(bundle, 'w', zipfile.ZIP_DEFLATED, compresslevel=3) as archive:
        archive.write(ROOT / 'RECOVERY_REPORT.md', 'README.md')
        for directory in ('recovered_source', 'recovered_helper'):
            for path in (ROOT / directory).rglob('*'):
                if path.is_file():
                    archive.write(path, path.relative_to(ROOT).as_posix())
        for name in ('all_native_pseudocode.zip', 'all_functions_assembly.zip', 'leaf_candidates_assembly.zip', 'unclassified_text.zip'):
            archive.write(native / name, 'native_recovered/' + name, compress_type=zipfile.ZIP_STORED)
        for name in ('reconstructed.analysis.pe', 'function_index.csv', 'imports.json', 'manifest.json',
                     'script_api_references.json', 'decompile_failures.json', 'final_verification.json',
                     'decompile_status_1000.tsv', 'remaining_status.tsv', 'retry_status.tsv',
                     'leaf_status.tsv', 'leaf_candidates.json', 'leaf_candidate_index.csv', 'text_range_coverage.json'):
            archive.write(native / name, 'native_recovered/' + name)
        archive.write(native / 'test_report.txt', 'evidence/test_report.txt')
        archive.write(ROOT / 'recovered_assets.zip', 'recovered_assets.zip', compress_type=zipfile.ZIP_STORED)
        archive.write(ROOT / 'upstream_quickinput_reference.zip', 'upstream_reference/upstream_quickinput_reference.zip', compress_type=zipfile.ZIP_STORED)
        archive.write(ROOT / 'upstream_provenance.md', 'upstream_reference/README.md')
        for path in ROOT.glob('*.py'):
            archive.write(path, 'tools/' + path.name)
        archive.write(ROOT / 'requirements-recovery.txt', 'tools/requirements-recovery.txt')
        for path in (ROOT / 'ghidra_scripts').glob('*.java'):
            archive.write(path, 'tools/ghidra_scripts/' + path.name)
        for name in ('crypto_ef410.asm', 'crypto_860d0.asm', 'action_af0b0.asm', 'helper_function_checks.json'):
            archive.write(ROOT / 'emulation_analysis' / name, 'evidence/' + name)
    with zipfile.ZipFile(bundle) as archive:
        if archive.testzip() is not None:
            raise ValueError('Final archive CRC failure')
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print('Bundle bytes:', bundle.stat().st_size)
    print('Bundle SHA256:', hashlib.sha256(bundle.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()

