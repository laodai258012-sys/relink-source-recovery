import pathlib
import ntpath
import datetime
import re
import struct

from unicorn import x86_const


class WindowsModel:
    def __init__(self, machine, image_base, imports, events):
        self.machine = machine
        self.image_base = image_base
        self.events = events
        self.modules = {}
        self.api_sets = self.read_api_sets()
        self.api_addresses = {}
        self.allocations = {}
        self.allocation_sizes = {}
        self.next_allocation = 0x30000000
        self.calls = 0
        self.last_error = 0
        self.current_directory = 'C:\\sample'
        self.image_bytes = b''
        self.file_handles = {}
        self.file_mappings = {}
        self.file_view_observer = None
        self.next_handle = 0x2000
        self.registry = {}
        self.registry_handles = {}
        self.environment = {'windir': 'C:\\Windows', 'systemroot': 'C:\\Windows', 'temp': 'C:\\sample\\tmp', 'tmp': 'C:\\sample\\tmp'}
        self.vectored_handlers = []
        self.unhandled_filter = 0
        self.exception_frames = []
        self.allowed = {item['library'].lower() for item in imports} | {'ntdll.dll', 'kernelbase.dll', 'kernel32.dll', 'cfgmgr32.dll'}
        self.allowed.update(self.api_sets.values())
        self.allowed.update({'icu.dll', 'sspicli.dll', 'srvcli.dll', 'netutils.dll', 'cryptbase.dll'})
        self.stub_base = 0x70000000
        machine.mem_map(self.stub_base, 0x10000)
        self.next_stub = self.stub_base
        for name in ('ntdll.dll', 'kernelbase.dll', 'kernel32.dll'):
            self.map_module(name)

    def read_api_sets(self):
        data = pathlib.Path('C:/Windows/System32/apisetschema.dll').read_bytes()
        pe = struct.unpack_from('<I', data, 60)[0]
        count = struct.unpack_from('<H', data, pe + 6)[0]
        optional_size = struct.unpack_from('<H', data, pe + 20)[0]
        mapping = {}
        for index in range(count):
            section = pe + 24 + optional_size + index * 40
            if data[section:section+8].rstrip(b'\0') != b'.apiset':
                continue
            size, offset = struct.unpack_from('<II', data, section + 16)
            namespace = data[offset:offset+size]
            version, total, flags, count, entries = struct.unpack_from('<IIIII', namespace)
            if version != 6:
                raise ValueError('Unsupported API-set schema')
            for entry_index in range(count):
                flags, name, name_length, hashed, values, value_count = struct.unpack_from('<IIIIII', namespace, entries + entry_index * 24)
                contract = namespace[name:name+name_length].decode('utf-16le').lower()
                for value_index in range(value_count):
                    flags, alias, alias_length, target, target_length = struct.unpack_from('<IIIII', namespace, values + value_index * 20)
                    if alias_length == 0 and target_length:
                        mapping[contract] = namespace[target:target+target_length].decode('utf-16le').lower()
                        mapping[contract[:hashed // 2]] = mapping[contract]
        return mapping

    def pointer(self, address):
        return struct.unpack('<Q', self.machine.mem_read(address, 8))[0]

    def registry_path(self, handle, subkey):
        root = self.registry_handles.get(handle, hex(handle & 0xffffffff))
        return root + ('\\' + subkey.lower() if subkey else '')

    def allocate(self, size):
        rounded = (max(size, 1) + 4095) & ~4095
        if rounded > 0x10000000 or self.next_allocation + rounded >= self.stub_base:
            raise ValueError('Emulated allocation exceeds limit')
        address = self.next_allocation
        self.next_allocation += rounded + 0x10000
        self.machine.mem_map(address, rounded)
        self.allocations[address] = rounded
        self.allocation_sizes[address] = size
        return address

    def write_string(self, address, text, capacity, wide):
        width = 2 if wide else 1
        if capacity <= len(text):
            self.last_error = 122
            return len(text) + 1
        encoded = text.encode('utf-16le' if wide else 'ascii') + bytes(width)
        self.machine.mem_write(address, encoded)
        return len(text)

    def exception_registers(self):
        names = ('RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'RIP')
        return {name: 0x78 + index * 8 for index, name in enumerate(names)}

    def begin_exception(self, code, flags, count, parameters):
        if not self.vectored_handlers or count > 15 or len(self.exception_frames) >= 8:
            raise ValueError('Unsupported exception dispatch')
        stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
        continuation = self.pointer(stack)
        memory = self.allocate(4096)
        context = memory + 0x100
        pointers = memory + 0x800
        record = struct.pack('<IIQQII', code & 0xffffffff, flags & 0xffffffff, 0, continuation, count, 0)
        if count:
            record += bytes(self.machine.mem_read(parameters, count * 8))
        self.machine.mem_write(memory, record)
        self.machine.mem_write(pointers, struct.pack('<QQ', memory, context))
        self.machine.mem_write(context + 0x30, struct.pack('<II', 0x10003f, self.machine.reg_read(x86_const.UC_X86_REG_MXCSR)))
        self.machine.mem_write(context + 0x38, struct.pack('<6H', 0x33, 0x2b, 0x2b, 0x53, 0x2b, 0x2b))
        self.machine.mem_write(context + 0x44, struct.pack('<I', self.machine.reg_read(x86_const.UC_X86_REG_EFLAGS)))
        for name, offset in self.exception_registers().items():
            value = self.machine.reg_read(getattr(x86_const, 'UC_X86_REG_' + name))
            if name == 'RIP':
                value = continuation
            elif name == 'RSP':
                value = stack + 8
            self.machine.mem_write(context + offset, struct.pack('<Q', value))
        for index in range(16):
            value = self.machine.reg_read(getattr(x86_const, 'UC_X86_REG_XMM' + str(index)))
            self.machine.mem_write(context + 0x1a0 + index * 16, value.to_bytes(16, 'little'))
        frame = dict(context=context, pointers=pointers, stack=(stack - 0x200) & ~15,
                     handlers=list(self.vectored_handlers), index=0, code=code)
        self.exception_frames.append(frame)
        self.events.append(dict(type='virtual_exception_dispatch', code=hex(code), handlers=[hex(item) for item in frame['handlers']]))
        self.invoke_exception_handler(frame)

    def invoke_exception_handler(self, frame):
        stack = frame['stack'] - 8
        self.machine.mem_write(stack, struct.pack('<Q', 0x7000fff0))
        self.machine.reg_write(x86_const.UC_X86_REG_RCX, frame['pointers'])
        self.machine.reg_write(x86_const.UC_X86_REG_RSP, stack)
        self.machine.reg_write(x86_const.UC_X86_REG_RIP, frame['handlers'][frame['index']])

    def finish_exception(self):
        if not self.exception_frames:
            raise ValueError('Unexpected exception return')
        frame = self.exception_frames[-1]
        disposition = self.machine.reg_read(x86_const.UC_X86_REG_RAX) & 0xffffffff
        if disposition == 0xffffffff:
            context = frame['context']
            for name, offset in self.exception_registers().items():
                self.machine.reg_write(getattr(x86_const, 'UC_X86_REG_' + name), self.pointer(context + offset))
            flags = struct.unpack('<I', self.machine.mem_read(context + 0x44, 4))[0]
            self.machine.reg_write(x86_const.UC_X86_REG_EFLAGS, flags)
            for index in range(16):
                value = int.from_bytes(self.machine.mem_read(context + 0x1a0 + index * 16, 16), 'little')
                self.machine.reg_write(getattr(x86_const, 'UC_X86_REG_XMM' + str(index)), value)
            self.exception_frames.pop()
            self.events.append(dict(type='virtual_exception_continued', instruction=hex(self.machine.reg_read(x86_const.UC_X86_REG_RIP))))
        elif disposition == 0 and frame['index'] + 1 < len(frame['handlers']):
            frame['index'] += 1
            self.invoke_exception_handler(frame)
        else:
            raise ValueError('Virtual exception was not handled')

    def string(self, address, wide=False):
        if not address:
            return None
        width = 2 if wide else 1
        raw = bytearray()
        for index in range(4096):
            part = bytes(self.machine.mem_read(address + index * width, width))
            if part == bytes(width):
                return raw.decode('utf-16le' if wide else 'ascii', errors='replace')
            raw.extend(part)
        raise ValueError('String exceeds limit')

    def map_module(self, name):
        name = name.lower()
        if '.' not in name:
            name += '.dll'
        contract = name.removesuffix('.dll')
        name = self.api_sets.get(contract, self.api_sets.get(contract.rsplit('-', 1)[0], name))
        if name in self.modules:
            return self.modules[name]
        if not re.fullmatch(r'[a-z0-9_.-]+', name) or name not in self.allowed:
            raise ValueError('DLL read outside allowlist: ' + name)
        data = (pathlib.Path('C:/Windows/System32') / name).read_bytes()
        pe = struct.unpack_from('<I', data, 60)[0]
        count = struct.unpack_from('<H', data, pe + 6)[0]
        optional_size = struct.unpack_from('<H', data, pe + 20)[0]
        optional = pe + 24
        if struct.unpack_from('<H', data, optional)[0] != 0x20b:
            raise ValueError('Only x64 system DLL data is supported')
        size, header_size = struct.unpack_from('<II', data, optional + 56)
        base = 0x180000000 + len(self.modules) * 0x1000000
        self.machine.mem_map(base, (size + 4095) & ~4095)
        self.machine.mem_write(base, data[:header_size])
        for index in range(count):
            address, raw_size, offset = struct.unpack_from('<III', data, optional + optional_size + index * 40 + 12)
            if raw_size:
                self.machine.mem_write(base + address, data[offset:offset+raw_size])
        module = dict(name=name, base=base, size=size, exports={})
        self.modules[name] = module
        export_rva, export_size = struct.unpack_from('<II', data, optional + 112)
        if export_rva:
            directory = bytes(self.machine.mem_read(base + export_rva, 40))
            ordinal_base, function_count, name_count, functions, names, ordinals = struct.unpack_from('<IIIIII', directory, 16)
            exports_by_index = []
            for index in range(function_count):
                address = struct.unpack('<I', self.machine.mem_read(base + functions + index * 4, 4))[0]
                value = self.string(base + address) if export_rva <= address < export_rva + export_size else base + address
                exports_by_index.append(value)
                module['exports'][ordinal_base + index] = value
            for index in range(name_count):
                address = struct.unpack('<I', self.machine.mem_read(base + names + index * 4, 4))[0]
                ordinal = struct.unpack('<H', self.machine.mem_read(base + ordinals + index * 2, 2))[0]
                symbol = self.string(base + address)
                value = exports_by_index[ordinal]
                module['exports'][symbol] = value
                if isinstance(value, int):
                    self.api_addresses[value] = (name, symbol)
        return module

    def resolve(self, handle, symbol, depth=0):
        if depth > 8:
            raise ValueError('Export forwarding cycle')
        module = next((item for item in self.modules.values() if item['base'] == handle), None)
        if module is None:
            return 0
        value = module['exports'].get(symbol, 0)
        if isinstance(value, str):
            name, forwarded = value.rsplit('.', 1)
            target = self.map_module(name)
            symbol = int(forwarded[1:]) if forwarded.startswith('#') else forwarded
            if target['base'] == handle and name.startswith(('api-ms-', 'ext-ms-')):
                candidate = self.modules['kernelbase.dll']
                if isinstance(candidate['exports'].get(symbol), int):
                    self.events.append(dict(type='api_set_fallback', contract=name, symbol=symbol, target='kernelbase.dll'))
                    target = candidate
            return self.resolve(target['base'], symbol, depth + 1)
        return value

    def stub(self, library, symbol):
        address = self.next_stub
        self.next_stub += 16
        if self.next_stub >= self.stub_base + 0x10000:
            raise ValueError('Import stub space exhausted')
        self.machine.mem_write(address, b'\xc3')
        self.api_addresses[address] = (library, symbol)
        return address

    def dispatch(self, address):
        if address == 0x7000fff0:
            self.finish_exception()
            return
        library, symbol = self.api_addresses[address]
        self.calls += 1
        arguments = [self.machine.reg_read(register) for register in (
            x86_const.UC_X86_REG_RCX, x86_const.UC_X86_REG_RDX,
            x86_const.UC_X86_REG_R8, x86_const.UC_X86_REG_R9)]
        record = dict(type='modeled_api', library=library, symbol=symbol,
                      arguments=[hex(value) for value in arguments])
        self.events.append(record)
        if self.calls > 10000:
            raise ValueError('API call limit exceeded')
        first, second, third, fourth = arguments
        if symbol == 'RaiseException':
            self.begin_exception(first, second, third, fourth)
            return
        elif symbol in ('GetModuleHandleA', 'GetModuleHandleW'):
            name = self.string(first, symbol.endswith('W'))
            record['name'] = name
            result = self.image_base if name is None else self.modules.get(name.lower(), {}).get('base', 0)
        elif symbol in ('LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW'):
            name = self.string(first, symbol.endswith('W'))
            record['name'] = name
            result = self.map_module(name)['base']
        elif symbol == 'GetProcAddress':
            name = second if second <= 65535 else self.string(second)
            record['name'] = name
            result = self.resolve(first, name)
        elif symbol in ('RtlInitializeCriticalSection', 'InitializeCriticalSection', 'InitializeCriticalSectionAndSpinCount', 'RtlInitializeCriticalSectionAndSpinCount'):
            self.machine.mem_write(first, struct.pack('<QiiQQQ', 0, -1, 0, 0, 0, second if 'SpinCount' in symbol else 0))
            result = 0 if symbol.startswith('Rtl') else 1
        elif symbol in ('RtlEnterCriticalSection', 'EnterCriticalSection'):
            recursion = struct.unpack('<i', self.machine.mem_read(first + 12, 4))[0] + 1
            self.machine.mem_write(first + 8, struct.pack('<iiQ', recursion - 1, recursion, 1001))
            result = 0
        elif symbol in ('RtlLeaveCriticalSection', 'LeaveCriticalSection'):
            recursion = struct.unpack('<i', self.machine.mem_read(first + 12, 4))[0] - 1
            if recursion < 0:
                raise ValueError('Unbalanced critical section')
            self.machine.mem_write(first + 8, struct.pack('<iiQ', recursion - 1, recursion, 1001 if recursion else 0))
            result = 0
        elif symbol in ('RtlDeleteCriticalSection', 'DeleteCriticalSection'):
            self.machine.mem_write(first, bytes(40))
            result = 0
        elif symbol in ('IsBadWritePtr', 'IsBadReadPtr', 'IsBadCodePtr'):
            length = 1 if symbol == 'IsBadCodePtr' else second
            result = 0 if any(start <= first and first + length <= end + 1 for start, end, permissions in self.machine.mem_regions()) else 1
        elif symbol == 'VirtualProtect':
            self.machine.mem_write(fourth, struct.pack('<I', 0x40))
            result = 1
        elif symbol in ('NtProtectVirtualMemory', 'ZwProtectVirtualMemory'):
            stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
            old_protection = self.pointer(stack + 0x28)
            self.machine.mem_write(old_protection, struct.pack('<I', 0x40))
            result = 0
        elif symbol == 'GetProcessHeap':
            result = 0x7fe09000
        elif symbol == 'AllocateAndInitializeSid':
            if second > 8:
                raise ValueError('SID subauthority count exceeds limit')
            stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
            authority = bytes(self.machine.mem_read(first, 6))
            subauthorities = [third, fourth] + [self.pointer(stack + 0x28 + index * 8) for index in range(6)]
            identifier = bytes([1, second]) + authority + b''.join(struct.pack('<I', value & 0xffffffff) for value in subauthorities[:second])
            allocated = self.allocate(len(identifier))
            self.machine.mem_write(allocated, identifier)
            self.machine.mem_write(self.pointer(stack + 0x58), struct.pack('<Q', allocated))
            result = 1
        elif symbol == 'GetLengthSid':
            result = 8 + 4 * self.machine.mem_read(first + 1, 1)[0]
        elif symbol == 'FreeSid':
            if first in self.allocations:
                self.machine.mem_unmap(first, self.allocations.pop(first))
                self.allocation_sizes.pop(first, None)
            result = 0
        elif symbol == 'InitializeSecurityDescriptor':
            self.machine.mem_write(first, bytes([second & 255]) + bytes(39))
            result = 1
        elif symbol == 'InitializeAcl':
            self.machine.mem_write(first, struct.pack('<BBHHH', third & 255, 0, second & 65535, 0, 0))
            result = 1
        elif symbol == 'AddAccessAllowedAce':
            size = 8 + 4 * self.machine.mem_read(fourth + 1, 1)[0]
            identifier = bytes(self.machine.mem_read(fourth, size))
            acl_size, count = struct.unpack('<HH', self.machine.mem_read(first + 2, 4))
            cursor = first + 8
            for index in range(count):
                cursor += struct.unpack('<H', self.machine.mem_read(cursor + 2, 2))[0]
            entry = struct.pack('<BBHI', 0, 0, 8 + size, third & 0xffffffff) + identifier
            if cursor + len(entry) > first + acl_size:
                raise ValueError('ACL capacity exceeded')
            self.machine.mem_write(cursor, entry)
            self.machine.mem_write(first + 4, struct.pack('<H', count + 1))
            result = 1
        elif symbol == 'SetSecurityDescriptorDacl':
            control = struct.unpack('<H', self.machine.mem_read(first + 2, 2))[0]
            control = (control & ~12) | (4 if second else 0) | (8 if fourth else 0)
            self.machine.mem_write(first + 2, struct.pack('<H', control))
            self.machine.mem_write(first + 32, struct.pack('<Q', third))
            result = 1
        elif symbol in ('SetEntriesInAclA', 'SetEntriesInAclW'):
            if third or first > 32:
                raise ValueError('Only a new bounded ACL is modeled')
            entries = []
            for index in range(first):
                entry = second + index * 48
                permissions, mode, inheritance = struct.unpack('<III', self.machine.mem_read(entry, 12))
                form = struct.unpack('<I', self.machine.mem_read(entry + 28, 4))[0]
                if form != 0 or mode not in (1, 2, 3):
                    raise ValueError('Unsupported trustee or access mode')
                identifier_address = self.pointer(entry + 40)
                size = 8 + 4 * self.machine.mem_read(identifier_address + 1, 1)[0]
                identifier = bytes(self.machine.mem_read(identifier_address, size))
                entries.append(struct.pack('<BBHI', 1 if mode == 3 else 0, inheritance & 255, 8 + size, permissions) + identifier)
            data = b''.join(entries)
            acl = struct.pack('<BBHHH', 2, 0, 8 + len(data), len(entries), 0) + data
            allocated = self.allocate(len(acl))
            self.machine.mem_write(allocated, acl)
            self.machine.mem_write(fourth, struct.pack('<Q', allocated))
            result = 0
        elif symbol == 'SetSecurityInfo':
            if first not in (0x1000, 0x1001):
                raise ValueError('Unknown synthetic security handle')
            result = 0
        elif symbol in ('LocalAlloc', 'GlobalAlloc'):
            if first & 2:
                raise ValueError('Movable local/global handles are not modeled')
            result = self.allocate(second)
        elif symbol == 'LocalFree':
            if first in self.allocations:
                self.machine.mem_unmap(first, self.allocations.pop(first))
                self.allocation_sizes.pop(first, None)
            result = 0
        elif symbol == 'SetKernelObjectSecurity':
            if first not in (0x1000, 0x1001):
                raise ValueError('Unknown synthetic kernel handle')
            result = 1
        elif symbol in ('HeapAlloc', 'RtlAllocateHeap'):
            result = self.allocate(third)
        elif symbol in ('HeapFree', 'RtlFreeHeap'):
            if third in self.allocations:
                self.machine.mem_unmap(third, self.allocations.pop(third))
                self.allocation_sizes.pop(third, None)
            result = 1
        elif symbol in ('HeapSize', 'RtlSizeHeap'):
            result = self.allocation_sizes.get(third, 0xffffffffffffffff)
        elif symbol in ('HeapReAlloc', 'RtlReAllocateHeap'):
            if third not in self.allocations:
                raise ValueError('Unknown heap allocation')
            result = self.allocate(fourth)
            self.machine.mem_write(result, bytes(self.machine.mem_read(third, min(fourth, self.allocation_sizes[third]))))
            self.machine.mem_unmap(third, self.allocations.pop(third))
            self.allocation_sizes.pop(third, None)
        elif symbol == 'VirtualAlloc':
            size = (second + 4095) & ~4095
            if first or size <= 0 or size > 0x10000000:
                raise ValueError('Unsupported VirtualAlloc parameters')
            result = self.allocate(size)
        elif symbol == 'VirtualFree':
            if first not in self.allocations:
                raise ValueError('Unknown virtual allocation')
            if third == 0x8000:
                self.machine.mem_unmap(first, self.allocations.pop(first))
                self.allocation_sizes.pop(first, None)
            elif third == 0x4000:
                self.machine.mem_write(first, bytes(min(second, self.allocations[first])))
            else:
                raise ValueError('Unsupported virtual free mode')
            result = 1
        elif symbol in ('GetThreadContext', 'NtGetContextThread', 'ZwGetContextThread'):
            flags = struct.unpack('<I', self.machine.mem_read(second + 0x30, 4))[0]
            if flags != 0x100010:
                raise ValueError('Only a debug-register context is modeled')
            self.machine.mem_write(second + 0x48, bytes(48))
            result = 1 if symbol == 'GetThreadContext' else 0
        elif symbol in ('NtQueryInformationProcess', 'ZwQueryInformationProcess'):
            result = 0
            if second in (7, 26):
                data = bytes(8)
            elif second == 31:
                data = struct.pack('<I', 1)
            elif second == 30:
                data = bytes(8)
                result = 0xc0000353
            elif second == 0:
                data = struct.pack('<IIQQIIQQ', 0, 0, 0x7fe00000, 15, 8, 0, 1000, 500)
            else:
                raise ValueError('Unsupported process information class: ' + str(second))
            if fourth < len(data):
                raise ValueError('Process information buffer too small')
            self.machine.mem_write(third, data)
            stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
            returned_size = self.pointer(stack + 0x28)
            if returned_size:
                self.machine.mem_write(returned_size, struct.pack('<I', len(data)))
        elif symbol in ('NtQuerySystemInformation', 'ZwQuerySystemInformation'):
            if first == 11:
                data = bytes(8)
                record['system_model'] = 'no kernel modules are simulated'
            elif first == 35:
                data = bytes([0, 1])
            else:
                raise ValueError('Unsupported system information class: ' + str(first))
            if third < len(data):
                raise ValueError('System information buffer too small')
            self.machine.mem_write(second, data)
            if fourth:
                self.machine.mem_write(fourth, struct.pack('<I', len(data)))
            result = 0
        elif symbol == 'IsDebuggerPresent':
            result = 0
        elif symbol in ('GetSystemFirmwareTable', 'EnumSystemFirmwareTables'):
            record['hardware_model'] = 'firmware unavailable; no host hardware query'
            self.last_error = 50
            result = 0
        elif symbol == 'GetAdaptersInfo':
            self.machine.mem_write(second, bytes(4))
            record['network_model'] = 'no adapters; no host network access'
            result = 232
        elif symbol == 'FreeLibrary':
            result = 1 if any(module['base'] == first for module in self.modules.values()) else 0
        elif symbol in ('GetVolumeInformationA', 'GetVolumeInformationW'):
            record['root'] = self.string(first, symbol.endswith('W'))
            record['hardware_model'] = 'synthetic volume, serial 0x12345678'
            stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
            maximum = self.pointer(stack + 0x28)
            flags = self.pointer(stack + 0x30)
            filesystem = self.pointer(stack + 0x38)
            filesystem_size = self.pointer(stack + 0x40)
            if second:
                self.write_string(second, 'EMULATED', third, symbol.endswith('W'))
            if fourth:
                self.machine.mem_write(fourth, struct.pack('<I', 0x12345678))
            if maximum:
                self.machine.mem_write(maximum, struct.pack('<I', 255))
            if flags:
                self.machine.mem_write(flags, struct.pack('<I', 3))
            if filesystem:
                self.write_string(filesystem, 'NTFS', filesystem_size, symbol.endswith('W'))
            result = 1
        elif symbol in ('FindWindowA', 'FindWindowW'):
            record['class_name'] = self.string(first, symbol.endswith('W')) if first > 65535 else first
            record['window_name'] = self.string(second, symbol.endswith('W'))
            record['desktop_model'] = 'empty; no host GUI access'
            result = 0
        elif symbol == 'EnumWindows':
            record['desktop_model'] = 'empty; callback not invoked'
            result = 1
        elif symbol in ('NtSetInformationThread', 'ZwSetInformationThread'):
            if first not in (0xfffffffffffffffe, 0x1001) or second != 17 or third or fourth:
                raise ValueError('Unsupported thread-information update')
            record['scope'] = 'synthetic thread only; no native call'
            result = 0
        elif symbol == 'CheckRemoteDebuggerPresent':
            self.machine.mem_write(second, bytes(4))
            result = 1
        elif symbol == 'GetCurrentProcess':
            result = 0xffffffffffffffff
        elif symbol == 'GetCurrentProcessId':
            result = 1000
        elif symbol == 'GetCurrentThreadId':
            result = 1001
        elif symbol in ('GetCurrentDirectoryA', 'GetCurrentDirectoryW'):
            result = self.write_string(second, self.current_directory, first, symbol.endswith('W'))
        elif symbol in ('SHGetSpecialFolderPathA', 'SHGetSpecialFolderPathW'):
            paths = {0x23: 'C:\\ProgramData', 0x1a: 'C:\\Users\\analyst\\AppData\\Roaming',
                     0x1c: 'C:\\Users\\analyst\\AppData\\Local', 0x24: 'C:\\Windows', 0x25: 'C:\\Windows\\System32'}
            if third not in paths:
                raise ValueError('Unsupported special folder: ' + hex(third))
            self.write_string(second, paths[third], 260, symbol.endswith('W'))
            result = 1
        elif symbol in ('RtlAddVectoredExceptionHandler', 'AddVectoredExceptionHandler'):
            if first:
                self.vectored_handlers.insert(0, second)
            else:
                self.vectored_handlers.append(second)
            result = second
        elif symbol in ('RtlRemoveVectoredExceptionHandler', 'RemoveVectoredExceptionHandler'):
            if first in self.vectored_handlers:
                self.vectored_handlers.remove(first)
                result = 1
            else:
                result = 0
        elif symbol == 'SetUnhandledExceptionFilter':
            result = self.unhandled_filter
            self.unhandled_filter = first
        elif symbol in ('SetEnvironmentVariableA', 'SetEnvironmentVariableW'):
            name = self.string(first, symbol.endswith('W'))
            value = self.string(second, symbol.endswith('W'))
            record['name'] = name
            record['value'] = value
            if value is None:
                self.environment.pop(name.lower(), None)
            else:
                self.environment[name.lower()] = value
            result = 1
        elif symbol in ('GetEnvironmentVariableA', 'GetEnvironmentVariableW'):
            name = self.string(first, symbol.endswith('W'))
            record['name'] = name
            value = self.environment.get(name.lower())
            if value is None:
                self.last_error = 203
                result = 0
            else:
                result = self.write_string(second, value, third, symbol.endswith('W'))
        elif symbol in ('SetCurrentDirectoryA', 'SetCurrentDirectoryW'):
            name = self.string(first, symbol.endswith('W'))
            record['path'] = name
            self.current_directory = ntpath.normpath(ntpath.join(self.current_directory, name))
            result = 1
        elif symbol in ('DeleteFileA', 'DeleteFileW'):
            record['path'] = self.string(first, symbol.endswith('W'))
            record['filesystem_model'] = 'empty virtual filesystem; no host deletion'
            self.last_error = 2
            result = 0
        elif symbol in ('CreateFileA', 'CreateFileW', 'GetFileAttributesA', 'GetFileAttributesW'):
            name = ntpath.normpath(ntpath.join(self.current_directory, self.string(first, symbol.endswith('W')))).lower()
            record['path'] = name
            if name == 'c:\\sample\\protected.exe':
                if symbol.startswith('GetFileAttributes'):
                    result = 0x20
                elif second & 0x40000000:
                    raise ValueError('Write access to the immutable sample is not modeled')
                else:
                    result = self.next_handle
                    self.next_handle += 1
                    self.file_handles[result] = dict(position=0)
            elif symbol.startswith('GetFileAttributes') and name in ('c:\\sample', 'c:\\windows', 'c:\\windows\\system32'):
                result = 0x10
            else:
                self.last_error = 2
                result = 0xffffffff if symbol.startswith('GetFileAttributes') else 0xffffffffffffffff
        elif symbol in ('CreateFileMappingA', 'CreateFileMappingW'):
            if first not in self.file_handles or third != 2:
                raise ValueError('Only read-only sample mappings are modeled')
            result = self.next_handle
            self.next_handle += 1
            self.file_mappings[result] = dict(file=first)
        elif symbol in ('MapViewOfFile', 'MapViewOfFileEx'):
            if first not in self.file_mappings:
                raise ValueError('Unknown virtual file mapping')
            stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
            offset = (third << 32) | fourth
            length = self.pointer(stack + 0x28) or len(self.image_bytes) - offset
            if offset + length > len(self.image_bytes) or length <= 0:
                raise ValueError('Invalid virtual mapping bounds')
            result = self.allocate(length)
            self.machine.mem_write(result, self.image_bytes[offset:offset+length])
            if self.file_view_observer:
                self.file_view_observer(result, length)
        elif symbol == 'UnmapViewOfFile':
            if first not in self.allocations:
                raise ValueError('Unknown virtual mapping view')
            self.machine.mem_unmap(first, self.allocations.pop(first))
            self.allocation_sizes.pop(first, None)
            result = 1
        elif symbol == 'ReadFile':
            stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
            if first not in self.file_handles or self.pointer(stack + 0x28):
                raise ValueError('Unsupported virtual file read')
            position = self.file_handles[first]['position']
            data = self.image_bytes[position:position+third]
            self.machine.mem_write(second, data)
            if fourth:
                self.machine.mem_write(fourth, struct.pack('<I', len(data)))
            self.file_handles[first]['position'] += len(data)
            result = 1
        elif symbol in ('GetFileSize', 'GetFileSizeEx'):
            if first not in self.file_handles:
                raise ValueError('Unknown virtual file handle')
            if symbol.endswith('Ex'):
                self.machine.mem_write(second, struct.pack('<Q', len(self.image_bytes)))
                result = 1
            else:
                if second:
                    self.machine.mem_write(second, struct.pack('<I', len(self.image_bytes) >> 32))
                result = len(self.image_bytes) & 0xffffffff
        elif symbol == 'SetFilePointer':
            if first not in self.file_handles or fourth not in (0, 1, 2):
                raise ValueError('Unsupported virtual file seek')
            distance = struct.unpack('<i', struct.pack('<I', second & 0xffffffff))[0]
            if third:
                high = struct.unpack('<i', self.machine.mem_read(third, 4))[0]
                distance = (high << 32) | (second & 0xffffffff)
            position = (0, self.file_handles[first]['position'], len(self.image_bytes))[fourth] + distance
            if position < 0:
                raise ValueError('Negative virtual file position')
            self.file_handles[first]['position'] = position
            if third:
                self.machine.mem_write(third, struct.pack('<I', position >> 32))
            result = position & 0xffffffff
        elif symbol in ('GetModuleFileNameA', 'GetModuleFileNameW'):
            if first in (0, self.image_base):
                name = 'C:\\sample\\protected.exe'
            else:
                module = next((item for item in self.modules.values() if item['base'] == first), None)
                if module is None:
                    raise ValueError('Unknown module handle')
                name = 'C:\\Windows\\System32\\' + module['name']
            result = self.write_string(second, name, third, symbol.endswith('W'))
        elif symbol in ('GetWindowsDirectoryA', 'GetWindowsDirectoryW', 'GetSystemDirectoryA', 'GetSystemDirectoryW'):
            name = 'C:\\Windows\\System32' if 'System' in symbol else 'C:\\Windows'
            result = self.write_string(first, name, second, symbol.endswith('W'))
        elif symbol in ('GetCommandLineA', 'GetCommandLineW'):
            text = '"C:\\sample\\protected.exe"'
            result = self.allocate((len(text) + 1) * 2)
            self.write_string(result, text, len(text) + 1, symbol.endswith('W'))
        elif symbol == 'GetCurrentThread':
            result = 0xfffffffffffffffe
        elif symbol == 'OpenThread':
            result = 0x1001 if third == 1001 else 0
        elif symbol == 'OpenThreadToken':
            self.last_error = 1008
            result = 0
        elif symbol == 'OpenProcessToken':
            self.machine.mem_write(third, struct.pack('<Q', 0x1002))
            result = 1
        elif symbol == 'IsUserAnAdmin':
            result = 1
        elif symbol in ('RegOpenKeyA', 'RegOpenKeyW', 'RegOpenKeyExA', 'RegOpenKeyExW'):
            record['subkey'] = self.string(second, symbol.endswith('W'))
            record['registry_model'] = 'in-memory only; no host registry access'
            if 'Ex' in symbol:
                stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
                output = self.pointer(stack + 0x28)
            else:
                output = third
            path = self.registry_path(first, record['subkey'])
            handle = 0
            if path in self.registry:
                handle = self.next_handle
                self.next_handle += 1
                self.registry_handles[handle] = path
            if output:
                self.machine.mem_write(output, struct.pack('<Q', handle))
            result = 0 if handle else 2
        elif symbol in ('RegCreateKeyA', 'RegCreateKeyW', 'RegCreateKeyExA', 'RegCreateKeyExW'):
            name = self.string(second, symbol.endswith('W'))
            record['subkey'] = name
            record['registry_model'] = 'in-memory only; no host registry changes'
            path = self.registry_path(first, name)
            existed = path in self.registry
            self.registry.setdefault(path, {})
            handle = self.next_handle
            self.next_handle += 1
            self.registry_handles[handle] = path
            output = third
            if 'Ex' in symbol:
                stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
                output = self.pointer(stack + 0x40)
                disposition = self.pointer(stack + 0x48)
                if disposition:
                    self.machine.mem_write(disposition, struct.pack('<I', 2 if existed else 1))
            self.machine.mem_write(output, struct.pack('<Q', handle))
            result = 0
        elif symbol in ('RegQueryValueExA', 'RegQueryValueExW', 'RegSetValueExA', 'RegSetValueExW'):
            if first not in self.registry_handles:
                raise ValueError('Unknown virtual registry handle')
            name = (self.string(second, symbol.endswith('W')) or '').lower()
            record['value_name'] = name
            values = self.registry[self.registry_handles[first]]
            stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
            data_pointer = self.pointer(stack + 0x28)
            size_parameter = self.pointer(stack + 0x30)
            if symbol.startswith('RegSet'):
                if size_parameter > 1048576:
                    raise ValueError('Virtual registry value exceeds limit')
                values[name] = dict(type=fourth, data=bytes(self.machine.mem_read(data_pointer, size_parameter)).hex())
                result = 0
            elif name not in values:
                result = 2
            else:
                value = values[name]
                data = bytes.fromhex(value['data'])
                capacity = struct.unpack('<I', self.machine.mem_read(size_parameter, 4))[0]
                self.machine.mem_write(size_parameter, struct.pack('<I', len(data)))
                if fourth:
                    self.machine.mem_write(fourth, struct.pack('<I', value['type']))
                if not data_pointer:
                    result = 0
                elif capacity < len(data):
                    result = 234
                else:
                    self.machine.mem_write(data_pointer, data)
                    result = 0
        elif symbol == 'RegCloseKey':
            self.registry_handles.pop(first, None)
            result = 0
        elif symbol == 'GetTokenInformation':
            if second != 2:
                raise ValueError('Unsupported token information class: ' + str(second))
            identifiers = [bytes([1, 1, 0, 0, 0, 0, 0, 1]) + struct.pack('<I', 0),
                           bytes([1, 2, 0, 0, 0, 0, 0, 5]) + struct.pack('<II', 32, 545),
                           bytes([1, 2, 0, 0, 0, 0, 0, 5]) + struct.pack('<II', 32, 544)]
            offset = 8 + 16 * len(identifiers)
            entries = []
            for identifier in identifiers:
                entries.append(struct.pack('<QII', third + offset, 7, 0))
                offset += len(identifier)
            data = struct.pack('<II', len(entries), 0) + b''.join(entries) + b''.join(identifiers)
            stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
            self.machine.mem_write(self.pointer(stack + 0x28), struct.pack('<I', len(data)))
            if not third or fourth < len(data):
                self.last_error = 122
                result = 0
            else:
                self.machine.mem_write(third, data)
                result = 1
        elif symbol in ('EqualSid', 'RtlEqualSid'):
            first_size = 8 + 4 * self.machine.mem_read(first + 1, 1)[0]
            second_size = 8 + 4 * self.machine.mem_read(second + 1, 1)[0]
            result = int(first_size == second_size and self.machine.mem_read(first, first_size) == self.machine.mem_read(second, second_size))
        elif symbol == 'OpenProcess':
            result = 0x1000 if third == 1000 else 0
        elif symbol in ('CloseHandle', 'NtClose', 'ZwClose'):
            self.file_handles.pop(first, None)
            self.file_mappings.pop(first, None)
            result = 1 if symbol == 'CloseHandle' else 0
        elif symbol in ('GetUserDefaultUILanguage', 'GetSystemDefaultUILanguage', 'GetUserDefaultLangID', 'GetSystemDefaultLangID', 'GetUserDefaultLCID', 'GetSystemDefaultLCID'):
            result = 0x409
        elif symbol in ('GetACP', 'GetOEMCP'):
            result = 1252 if symbol == 'GetACP' else 437
        elif symbol == 'GetVersion':
            result = (19045 << 16) | 10
        elif symbol in ('GetVersionExA', 'GetVersionExW', 'RtlGetVersion'):
            size = struct.unpack('<I', self.machine.mem_read(first, 4))[0]
            if size not in (148, 156, 276, 284):
                raise ValueError('Unexpected version structure size')
            self.machine.mem_write(first, struct.pack('<IIIII', size, 10, 0, 19045, 2) + bytes(size - 20))
            if size in (156, 284):
                self.machine.mem_write(first + size - 2, b'\x01')
            result = 0 if symbol == 'RtlGetVersion' else 1
        elif symbol == 'IsWow64Process':
            self.machine.mem_write(second, struct.pack('<I', 0))
            result = 1
        elif symbol == 'IsWow64Process2':
            self.machine.mem_write(second, struct.pack('<H', 0))
            self.machine.mem_write(third, struct.pack('<H', 0x8664))
            result = 1
        elif symbol in ('QueryPerformanceCounter', 'QueryPerformanceFrequency'):
            value = 10000000 if symbol.endswith('Frequency') else 600000000 + self.calls * 10000
            self.machine.mem_write(first, struct.pack('<Q', value))
            result = 1
        elif symbol in ('GetTickCount', 'GetTickCount64'):
            result = 60000 + self.calls
        elif symbol in ('GetLocalTime', 'GetSystemTime'):
            hour = 17 if symbol == 'GetLocalTime' else 9
            self.machine.mem_write(first, struct.pack('<8H', 2026, 11, 1, 2, hour, 0, 0, 0))
            record['time_model'] = 'fixed 2026-11-02; local offset UTC+8'
            result = 0
        elif symbol in ('GetSystemTimeAsFileTime', 'GetSystemTimePreciseAsFileTime'):
            moment = datetime.datetime(2026, 11, 2, 9)
            ticks = int((moment - datetime.datetime(1601, 1, 1)).total_seconds()) * 10000000
            self.machine.mem_write(first, struct.pack('<Q', ticks))
            result = 0
        elif symbol == 'SystemTimeToFileTime':
            year, month, weekday, day, hour, minute, second_value, millisecond = struct.unpack('<8H', self.machine.mem_read(first, 16))
            moment = datetime.datetime(year, month, day, hour, minute, second_value, millisecond * 1000)
            ticks = int((moment - datetime.datetime(1601, 1, 1)).total_seconds() * 10000000)
            self.machine.mem_write(second, struct.pack('<Q', ticks))
            result = 1
        elif symbol == 'FileTimeToSystemTime':
            ticks = self.pointer(first)
            moment = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ticks // 10)
            self.machine.mem_write(second, struct.pack('<8H', moment.year, moment.month, (moment.weekday()+1) % 7,
                                                      moment.day, moment.hour, moment.minute, moment.second, moment.microsecond // 1000))
            result = 1
        elif symbol in ('FileTimeToLocalFileTime', 'LocalFileTimeToFileTime'):
            delta = 8 * 3600 * 10000000
            ticks = self.pointer(first) + (delta if symbol.startswith('FileTime') else -delta)
            self.machine.mem_write(second, struct.pack('<Q', ticks))
            result = 1
        elif symbol == 'GetLastError':
            result = self.last_error
        elif symbol == 'SetLastError':
            self.last_error = first & 0xffffffff
            result = 0
        else:
            record['type'] = 'unsupported_api_blocked'
            self.machine.emu_stop()
            return
        record['result'] = hex(result)
        stack = self.machine.reg_read(x86_const.UC_X86_REG_RSP)
        destination = self.pointer(stack)
        self.machine.reg_write(x86_const.UC_X86_REG_RAX, result)
        self.machine.reg_write(x86_const.UC_X86_REG_RSP, stack + 8)
        self.machine.reg_write(x86_const.UC_X86_REG_RIP, destination)

