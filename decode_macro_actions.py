import collections
import json
import pathlib
import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from extract_macro_source import ROOT, write_json

FIELD_KEYS = {
    '2c73f7ff': b'cf849460143f9176',
    '4e3698ae': b'a71ebf091617c23a',
    '2e73f7ff': b'8ac774fc1afe55bb',
    '2e73f7fe': b'78f281c0bdee68f5',
}
FIELD_NAMES = {
    '2c73f7ff': 'type', '7049459c': 'disabled', '4e3698ae': 'mark',
    'aae3083b': 'min', '74a66447': 'max', 'cdd0c122': 'next', 'bb58b051': 'next2',
    '2e73f7ff': 'script', '2e73f7fe': 'condition', '8a22cc15': 'key',
    '1238cd81': 'block', 'a70ba7d6': 'key_state', 'fd1f0a60': 'x', 'ba20d839': 'y',
    '8ae748e5': 'text', 'cbffe59e': 'time', '5b33880e': 'rgbe', '69ca7cca': 'rect',
    'c5fc0bc0': 'level', '4d208281': 'option', 'fe7f1ef2': 'id', '4578d94a': 'sync',
    'c3e16116': 'variable', 'sp': 'speed', '5d258b03': 'random_extent',
    '620d9da4': 'track', '_aae3083b': 'min_expression', '_74a66447': 'max_expression',
    '0e82f4bb': 'row', '53853f41': 'match', 'c7d298c2': 'url',
}
TYPE_NAMES = 'none end delay key mouse copyText color loop loopEnd keyState resetPos image popText savePos timer jump jumpPoint dialog block blockExec quickInput keyBlock clock ocr varOperator varCondition mouseTrack open textPad editDialog volume soundPlay msgView range'.split()


def main():
    output = ROOT / 'recovered_source'
    macro = json.loads((output / 'macro.full.json').read_text(encoding='utf-8'))
    counts = collections.Counter()
    decrypted_fields = []
    actions = []
    unknown = set()

    def transform(value, path='$'):
        if isinstance(value, list):
            return [transform(item, f'{path}[{index}]') for index, item in enumerate(value)]
        if not isinstance(value, dict):
            return value
        is_action = '2c73f7ff' in value
        result = {}
        for key, item in value.items():
            field_path = f'{path}.{key}'
            name = FIELD_NAMES.get(key, key) if is_action else key
            if is_action and key not in FIELD_NAMES:
                unknown.add(key)
            if key in FIELD_KEYS:
                ciphertext = bytes.fromhex(item)
                plaintext = unpad(AES.new(FIELD_KEYS[key], AES.MODE_ECB).decrypt(ciphertext), 16)
                if AES.new(FIELD_KEYS[key], AES.MODE_ECB).encrypt(pad(plaintext, 16)) != ciphertext:
                    raise ValueError('Inner field round-trip mismatch')
                text = plaintext.decode('utf-8', errors='strict')
                if key == '2c73f7ff':
                    if not re.fullmatch(r'[a-z0-9]{8}[0-9]+', text):
                        raise ValueError(f'Unexpected action type plaintext at {field_path}')
                    item = int(text[8:])
                    result['type_name'] = TYPE_NAMES[item]
                    counts[TYPE_NAMES[item]] += 1
                else:
                    item = text
                decrypted_fields.append(dict(path=field_path, name=name, plaintext=text,
                                             sha256=__import__('hashlib').sha256(plaintext).hexdigest()))
            result[name] = transform(item, field_path)
        if is_action:
            actions.append(dict(path=path, action=result))
        return result

    readable = transform(macro)
    write_json(output / 'macro.readable.json', readable)
    write_json(output / 'inner_fields.json', decrypted_fields)
    write_json(output / 'field_map.json', dict(aliases=FIELD_NAMES, aes_keys={key: value.decode() for key, value in FIELD_KEYS.items()},
               notes='Aliases are analysis labels based on native field access and the upstream Action schema; original keys remain in macro.full.json.'))
    script_output = output / 'action_scripts'
    script_output.mkdir(exist_ok=True)
    unique_scripts = {}
    manifest = []
    for record in decrypted_fields:
        if record['name'] not in ('script', 'condition'):
            continue
        text = record['plaintext']
        identity = (record['name'], text)
        if identity not in unique_scripts:
            filename = f'action_scripts/{len(unique_scripts):04d}_{record["name"]}.txt'
            (output / filename).write_bytes(text.encode('utf-8'))
            unique_scripts[identity] = filename
        manifest.append(dict(path=record['path'], kind=record['name'], file=unique_scripts[identity]))
    write_json(output / 'action_script_manifest.json', manifest)
    lines = ['Recovered macro action tree. Inspection only; not executable code.',
             'Includes disabled actions and both branches. All expressions retain their original text.', '']

    def render(sequence, depth=0):
        for action in sequence:
            params = {key: value for key, value in action.items() if key not in ('next', 'next2', 'type_name')}
            lines.append('  ' * depth + action['type_name'] + ' ' + json.dumps(params, ensure_ascii=False))
            for branch in ('next', 'next2'):
                if action.get(branch):
                    lines.append('  ' * (depth + 1) + branch + ':')
                    render(action[branch], depth + 2)

    for section in ('actionsEntry', 'actions', 'actionsEnding'):
        lines.append(section + ':')
        render(readable[section], 1)
    (output / 'actions.readable.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    summary = dict(actions=sum(counts.values()), types=dict(counts), decrypted_fields=len(decrypted_fields),
                   script_occurrences=len(manifest), unique_script_or_condition_files=len(unique_scripts),
                   unknown_action_keys=sorted(unknown), all_inner_roundtrips_equal=True,
                   prefix_removal='Only action type has an eight-character random prefix; other text is unchanged.')
    write_json(output / 'inner_verification.json', summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()

