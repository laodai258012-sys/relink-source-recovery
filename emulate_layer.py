import collections
import hashlib
import json
import pathlib
import pickle
import struct
import sys
import zipfile

ROOT = pathlib.Path(__file__).parent
sys.path.insert(0, str(ROOT / '.analysis_deps'))
import unicorn
from unicorn import x86_const
import capstone
from emulator_windows import WindowsModel


BASE = 0x140000000
STACK = 0x10000000
STACK_SIZE = 0x200000
TEB = 0x7ff00000
PEB = 0x7fe00000
LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 1000000
TIME_LIMIT = int(next((argument.split('=', 1)[1] for argument in sys.argv if argument.startswith('--seconds=')), '120'))
if not 1 <= TIME_LIMIT <= 1200:
    raise ValueError('Runtime limit must be between 1 and 1200 seconds')
OUTPUT = ROOT / 'emulation_analysis'
OUTPUT.mkdir(exist_ok=True)
original = next(ROOT.glob('*.exe')).read_bytes()
report = json.loads((ROOT / 'static_extracted/inspection.json').read_text(encoding='utf-8'))
if hashlib.sha256(original).hexdigest() != report['sha256']:
    raise ValueError('Unexpected input sample')
pe = struct.unpack_from('<I', original, 60)[0]
image_size = struct.unpack_from('<I', original, pe + 24 + 56)[0]
machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
machine.mem_map(BASE, (image_size + 4095) & ~4095)
machine.mem_write(BASE, original[:1536])
for section in report['sections']:
    if section['size']:
        machine.mem_write(BASE + section['address'], original[section['offset']:section['offset']+section['size']])
machine.mem_write(BASE + 0x423c000, (ROOT / 'deep_analysis/winlice_layer1.bin').read_bytes())
machine.mem_map(STACK, STACK_SIZE)
machine.mem_map(TEB, 0x10000)
machine.mem_map(PEB, 0x10000)


def write_pointer(address, value):
    machine.mem_write(address, struct.pack('<Q', value))


write_pointer(TEB + 8, STACK + STACK_SIZE)
write_pointer(TEB + 16, STACK)
write_pointer(TEB + 0x30, TEB)
write_pointer(TEB + 0x40, 1000)
write_pointer(TEB + 0x48, 1001)
write_pointer(TEB + 0x60, PEB)
write_pointer(PEB + 0x10, BASE)
write_pointer(PEB + 0x30, 0x7fe09000)
machine.reg_write(x86_const.UC_X86_REG_GS_BASE, TEB)
machine.reg_write(x86_const.UC_X86_REG_RSP, STACK + STACK_SIZE - 0x1008)
write_pointer(STACK + STACK_SIZE - 0x1008, 0xdead0000)
machine.reg_write(x86_const.UC_X86_REG_EFLAGS, 0x202)
trace = collections.deque(maxlen=120)
events = []
write_pages = collections.Counter()
changed_section_indices = set()
executed = 0
imports = json.loads((ROOT / 'deep_analysis/imports.json').read_text())
windows = WindowsModel(machine, BASE, imports, events)
windows.image_bytes = original


def original_offset(address):
    for section in report['sections']:
        if section['address'] <= address < section['address'] + section['size']:
            return section['offset'] + address - section['address']
    raise ValueError('Unmapped input address')


import_rva = struct.unpack_from('<I', original, pe + 24 + 112 + 8)[0]
descriptor = original_offset(import_rva)
for library in imports:
    table = struct.unpack_from('<I', original, descriptor + 16)[0]
    for index, symbol in enumerate(library['symbols']):
        write_pointer(BASE + table + index * 8, windows.stub(library['library'], symbol))
    descriptor += 20
loader = PEB + 0x1000
write_pointer(PEB + 0x18, loader)
machine.mem_write(loader, struct.pack('<II', 0x58, 1))
module_list = [dict(name=next(ROOT.glob('*.exe')).name, base=BASE, size=image_size)] + list(windows.modules.values())
nodes = [PEB + 0x2000 + index * 0x100 for index in range(len(module_list))]
for index, module in enumerate(module_list):
    node = nodes[index]
    write_pointer(node + 0x30, module['base'])
    machine.mem_write(node + 0x40, struct.pack('<I', module['size']))
    encoded = module['name'].encode('utf-16le')
    name_address = PEB + 0x6000 + index * 0x200
    machine.mem_write(name_address, encoded + b'\0\0')
    for relative in (0x48, 0x58):
        machine.mem_write(node + relative, struct.pack('<HHIQ', len(encoded), len(encoded) + 2, 0, name_address))
for link_index in range(3):
    head = loader + 0x10 + link_index * 16
    links = [node + link_index * 16 for node in nodes]
    chain = [head] + links
    for index, pointer in enumerate(chain):
        write_pointer(pointer, chain[(index + 1) % len(chain)])
        write_pointer(pointer + 8, chain[(index - 1) % len(chain)])


def on_code(engine, address, size, user_data):
    trace.append((address, size))
    if address in windows.api_addresses:
        try:
            windows.dispatch(address)
        except Exception as error:
            events.append(dict(type='api_model_stopped', error=str(error)))
            engine.emu_stop()
    elif not BASE <= address < BASE + image_size:
        events.append(dict(type='external_code_blocked', address=hex(address)))
        engine.emu_stop()


def on_block(engine, address, size, user_data):
    global executed
    executed += 1
    trace.append((address, min(size, 4096)))
    if not BASE <= address < BASE + image_size and address not in windows.api_addresses:
        events.append(dict(type='external_code_blocked', address=hex(address)))
        engine.emu_stop()


def on_invalid_memory(engine, access, address, size, value, user_data):
    events.append(dict(type='unmapped_memory', access=access, address=hex(address), size=size,
                       instruction=hex(engine.reg_read(x86_const.UC_X86_REG_RIP))))
    return False


def on_write(engine, access, address, size, value, user_data):
    write_pages[address & ~4095] += 1


def on_interrupt(engine, number, user_data):
    events.append(dict(type='interrupt', number=number, instruction=hex(engine.reg_read(x86_const.UC_X86_REG_RIP))))
    engine.emu_stop()


def on_syscall(engine, user_data):
    events.append(dict(type='syscall_blocked', instruction=hex(engine.reg_read(x86_const.UC_X86_REG_RIP))))
    engine.emu_stop()


def on_original_code(engine, address, size, user_data):
    events.append(dict(type='candidate_original_code_entry', address=hex(address),
                       rva=hex(address-BASE), note='Stopped before interpreting this instruction'))
    engine.emu_stop()


if '--fast' in sys.argv:
    machine.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=1, end=BASE-1)
    machine.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=BASE+image_size, end=0xffffffffffffffff)
else:
    machine.hook_add(unicorn.UC_HOOK_BLOCK, on_block)
    machine.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=0x70000000, end=0x7000ffff)
    machine.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=0x180000000, end=0x2ffffffff)
machine.hook_add(unicorn.UC_HOOK_MEM_INVALID, on_invalid_memory)
if '--turbo' not in sys.argv:
    machine.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write, begin=BASE, end=BASE+0x423bfff)
machine.hook_add(unicorn.UC_HOOK_INTR, on_interrupt)
machine.hook_add(unicorn.UC_HOOK_INSN, on_syscall, None, 1, 0, x86_const.UC_X86_INS_SYSCALL)
machine.hook_add(unicorn.UC_HOOK_CODE, on_original_code, begin=BASE+report['sections'][0]['address'],
                 end=BASE+report['sections'][0]['address']+report['sections'][0]['virtual_size']-1)
entry = BASE + 0x457ef65
checkpoint = OUTPUT / 'checkpoint.zip'
if '--resume' in sys.argv:
    with zipfile.ZipFile(checkpoint) as saved:
        state = json.loads(saved.read('state.json'))
        if state['source_sha256'] != report['sha256']:
            raise ValueError('Checkpoint belongs to another sample')
        windows.modules = state['modules']
        for module in windows.modules.values():
            module['exports'] = {int(key) if key.isdecimal() else key: value for key, value in module['exports'].items()}
        windows.api_addresses = {int(key): tuple(value) for key, value in state['api_addresses'].items()}
        windows.allocations = {int(key): value for key, value in state['allocations'].items()}
        windows.allocation_sizes = {int(key): value for key, value in state.get('allocation_sizes', {}).items()}
        windows.next_allocation = state['next_allocation']
        windows.next_stub = state['next_stub']
        windows.calls = state['calls']
        windows.last_error = state.get('last_error', 0)
        windows.current_directory = state.get('current_directory', windows.current_directory)
        windows.file_handles = {int(key): value for key, value in state.get('file_handles', {}).items()}
        windows.file_mappings = {int(key): value for key, value in state.get('file_mappings', {}).items()}
        windows.registry = state.get('registry', {})
        windows.registry_handles = {int(key): value for key, value in state.get('registry_handles', {}).items()}
        windows.next_handle = state.get('next_handle', windows.next_handle)
        windows.environment = state.get('environment', windows.environment)
        windows.vectored_handlers = state.get('vectored_handlers', [])
        windows.unhandled_filter = state.get('unhandled_filter', 0)
        windows.exception_frames = state.get('exception_frames', [])
        for start, end, permissions in state['regions']:
            cursor = start
            for existing_start, existing_end, existing_permissions in sorted(machine.mem_regions()):
                if existing_end < cursor or existing_start > end:
                    continue
                if existing_start > cursor:
                    machine.mem_map(cursor, existing_start - cursor, permissions)
                cursor = max(cursor, existing_end + 1)
            if cursor <= end:
                machine.mem_map(cursor, end + 1 - cursor, permissions)
            machine.mem_write(start, saved.read(f'memory_{start:x}.bin'))
        machine.context_restore(pickle.loads(saved.read('cpu.context')))
        entry = machine.reg_read(x86_const.UC_X86_REG_RIP)
        if entry not in windows.api_addresses:
            raise ValueError('This checkpoint stopped inside protected code, not at an API boundary; restart continuously without --resume')
        events[:] = state['events']
        executed = state['basic_blocks']
        write_pages.update({int(key): value for key, value in state['write_pages'].items()})
        changed_section_indices.update(state.get('changed_section_indices', []))
previous_blocks = executed
windows.api_addresses[0x7000fff0] = ('virtual_dispatch', 'exception_return')
machine.mem_write(0x7000fff0, b'\xc3')
file_reads = dict(count=0, minimum=None, maximum=None)
reported_file_progress = [0]


def on_file_read(engine, access, address, size, value, user_data):
    file_reads['count'] += 1
    relative = address - user_data
    file_reads['minimum'] = relative if file_reads['minimum'] is None else min(file_reads['minimum'], relative)
    file_reads['maximum'] = relative + size if file_reads['maximum'] is None else max(file_reads['maximum'], relative + size)
    if '--progress' in sys.argv and file_reads['maximum'] - reported_file_progress[0] >= 4194304:
        reported_file_progress[0] = file_reads['maximum']
        print('Virtual sample read position:', file_reads['maximum'], '/', len(original), flush=True)


for address, size in windows.allocation_sizes.items():
    if size == len(original) and ('--turbo' not in sys.argv or '--progress' in sys.argv):
        machine.hook_add(unicorn.UC_HOOK_MEM_READ, on_file_read, address, begin=address, end=address+size-1)
if '--progress' in sys.argv:
    windows.file_view_observer = lambda address, size: machine.hook_add(unicorn.UC_HOOK_MEM_READ, on_file_read, address, begin=address, end=address+size-1)
initial_section_hashes = {}
for index, section in enumerate(report['sections']):
    if section['address'] < 0x423c000:
        initial_section_hashes[index] = hashlib.sha256(machine.mem_read(BASE + section['address'], section['virtual_size'])).digest()
try:
    machine.emu_start(entry, 0, timeout=TIME_LIMIT * 1000000, count=0 if '--turbo' in sys.argv else LIMIT)
except unicorn.UcError as error:
    events.append(dict(type='emulator_error', error=str(error)))
registers = {}
for name in ['RIP','RSP','RAX','RBX','RCX','RDX','RSI','RDI','RBP','R8','R9','R10','R11','R12','R13','R14','R15','EFLAGS']:
    registers[name] = hex(machine.reg_read(getattr(x86_const, 'UC_X86_REG_' + name)))
result = dict(basic_blocks=executed, basic_blocks_this_run=executed-previous_blocks, instruction_limit=LIMIT, timeout_reached=bool(machine.query(unicorn.UC_QUERY_TIMEOUT)), events=events,
              block_counting_enabled='--fast' not in sys.argv,
              instruction_counting_enabled='--turbo' not in sys.argv, runtime_limit_seconds=TIME_LIMIT,
              file_read_counting_enabled='--turbo' not in sys.argv or '--progress' in sys.argv,
              file_reads_this_run=file_reads,
              original_section_written_pages={hex(address): count for address, count in write_pages.items()},
              registers=registers, native_execution=False, host_api_calls=False)
result['safe_to_resume_at_api_boundary'] = machine.reg_read(x86_const.UC_X86_REG_RIP) in windows.api_addresses
(OUTPUT / 'runtime_layer.bin').write_bytes(machine.mem_read(BASE + 0x423c000, 33587200))
modified_sections = []
for index, section in enumerate(report['sections']):
    start = BASE + section['address']
    size = section['virtual_size']
    if section['address'] >= 0x423c000:
        continue
    current_hash = hashlib.sha256(machine.mem_read(start, size)).digest()
    if current_hash != initial_section_hashes[index]:
        changed_section_indices.add(index)
    if index in changed_section_indices or any(start <= page < start + size for page in write_pages):
        filename = f'section_{index:02d}_rva_{section["address"]:08x}.bin'
        content = bytes(machine.mem_read(start, size))
        (OUTPUT / filename).write_bytes(content)
        modified_sections.append(dict(index=index, rva=hex(section['address']), file=filename,
                                      size=size, sha256=hashlib.sha256(content).hexdigest()))
result['modified_sections'] = modified_sections
result['changed_section_indices'] = sorted(changed_section_indices)
(OUTPUT / 'emulation.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
lines = []
for address, size in trace:
    raw = bytes(machine.mem_read(address, size))
    instructions = list(disassembler.disasm(raw, address))
    lines.extend(f'{instruction.address:016x}: {instruction.mnemonic} {instruction.op_str}' for instruction in instructions)
(OUTPUT / 'last_instructions.asm').write_text('\n'.join(lines) + '\n', encoding='utf-8')
state = dict(source_sha256=report['sha256'], modules=windows.modules, api_addresses=windows.api_addresses,
             allocations=windows.allocations, allocation_sizes=windows.allocation_sizes, next_allocation=windows.next_allocation,
             next_stub=windows.next_stub, calls=windows.calls, last_error=windows.last_error, events=events,
             current_directory=windows.current_directory, file_handles=windows.file_handles, next_handle=windows.next_handle,
             file_mappings=windows.file_mappings,
             registry=windows.registry, registry_handles=windows.registry_handles,
             environment=windows.environment,
             vectored_handlers=windows.vectored_handlers, unhandled_filter=windows.unhandled_filter,
             exception_frames=windows.exception_frames,
             regions=list(machine.mem_regions()), basic_blocks=executed, write_pages=dict(write_pages))
state['changed_section_indices'] = sorted(changed_section_indices)
with zipfile.ZipFile(OUTPUT / 'checkpoint.next.zip', 'w', zipfile.ZIP_DEFLATED, compresslevel=1) as saved:
    saved.writestr('state.json', json.dumps(state))
    saved.writestr('cpu.context', pickle.dumps(machine.context_save()))
    for start, end, permissions in state['regions']:
        saved.writestr(f'memory_{start:x}.bin', machine.mem_read(start, end + 1 - start))
(OUTPUT / 'checkpoint.next.zip').replace(checkpoint)
print(json.dumps({**result, 'events': events[-5:]}, indent=2))

