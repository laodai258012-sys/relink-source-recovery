import hashlib
import json
import pathlib
import struct


class BitStream:
    def __init__(self, data, position):
        self.data = data
        self.position = position
        self.remaining = 0
        self.tag = 0

    def byte(self):
        value = self.data[self.position]
        self.position += 1
        return value

    def bit(self):
        if self.remaining == 0:
            self.tag = self.byte()
            self.remaining = 8
        self.remaining -= 1
        return (self.tag >> self.remaining) & 1

    def gamma(self):
        value = 1
        for iteration in range(32):
            value = value * 2 + self.bit()
            if not self.bit():
                return value
        raise ValueError('Invalid gamma value')


def decode_chunk(data, position, maximum):
    stream = BitStream(data, position)
    result = bytearray([stream.byte()])
    state = 2
    previous_distance = None

    def copy(distance, length):
        if distance is None or not 0 < distance <= len(result):
            raise ValueError('Invalid match distance')
        if len(result) + length > maximum:
            raise ValueError('Output exceeds destination section')
        if distance >= length:
            start = len(result) - distance
            result.extend(result[start:start + length])
        else:
            pattern = bytes(result[-distance:])
            result.extend((pattern * ((length + distance - 1) // distance))[:length])

    while len(result) <= maximum:
        if not stream.bit():
            result.append(stream.byte())
            state = 2
        elif not stream.bit():
            distance = stream.gamma() - state
            state = 1
            if distance == 0:
                copy(previous_distance, stream.gamma())
            else:
                distance = (distance - 1) * 256 + stream.byte()
                length = stream.gamma()
                if distance >= 32000 or distance <= 127:
                    length += 2
                elif distance >= 1280:
                    length += 1
                copy(distance, length)
                previous_distance = distance
        elif not stream.bit():
            encoded = stream.byte()
            distance = encoded >> 1
            if distance == 0:
                return bytes(result), stream.position
            copy(distance, 2 + (encoded & 1))
            previous_distance = distance
            state = 1
        else:
            distance = 0
            for index in range(4):
                distance = distance * 2 + stream.bit()
            if distance:
                copy(distance, 1)
            else:
                result.append(0)
            state = 2
    raise ValueError('Output exceeds destination section')


def main():
    source = next(pathlib.Path(__file__).parent.glob('*.exe'))
    data = source.read_bytes()
    expected_hash = '15405f1cd736f38ee315469e0b3eeddb87fd179103dc642acadd9440ccc6e696'
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError('This script only supports the inspected sample')
    output = source.parent / 'deep_analysis'
    output.mkdir(exist_ok=True)
    boot_offset = 40734208
    position = boot_offset + 0x248
    count = data[position]
    position += 1
    restored = bytearray()
    chunks = []
    for index in range(count):
        start = position
        chunk, position = decode_chunk(data, position, 33587200 - len(restored))
        chunks.append(dict(index=index, source_offset=start, compressed_size=position-start,
                           destination_offset=len(restored), decompressed_size=len(chunk)))
        restored.extend(chunk)
        print(f'Chunk {index + 1}/{count}: {position-start} -> {len(chunk)} bytes', flush=True)
    (output / 'winlice_layer1.bin').write_bytes(restored)
    metadata = dict(source_sha256=expected_hash, destination_rva='0x423c000',
                    next_entry_rva='0x457ef65', compressed_start=boot_offset + 0x249,
                    compressed_end=position, decompressed_size=len(restored),
                    decompressed_sha256=hashlib.sha256(restored).hexdigest(), chunks=chunks,
                    original_program_executed=False, source_code_recovered=False)
    (output / 'layer1.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    print('Restored bytes:',len(restored),'into',output / 'winlice_layer1.bin')


if __name__ == '__main__':
    main()

