"""Run fixtures and stateful regressions on an installed, running Wazuh manager.

Install the repository XML first. No files or services are modified by this runner.
Each subprocess starts an isolated logtest session.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--logtest', default='/var/ossec/bin/wazuh-logtest')
args = parser.parse_args()
if not Path(args.logtest).is_file():
    parser.error('wazuh-logtest is missing; run on a Wazuh manager')
fixtures = json.loads(Path(__file__).with_name('fixtures.json').read_text())


def replay(lines, criteria=None):
    command = [args.logtest, '-v']
    if criteria:
        command += ['-U', criteria]
    result = subprocess.run(command, input='\n'.join(lines)+'\n', text=True,
                            capture_output=True, timeout=60)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    if re.search(r'\b(?:ERROR|CRITICAL)\b', result.stdout + result.stderr):
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout


for case in fixtures:
    text = replay([case['line']], f"{case['rule_id']}:{case['level']}:{case['decoder']}")
    for key, value in case['fields'].items():
        if f"{key}: '{value}'" not in text:
            raise AssertionError(f"{case['name']}: missing {key}={value}\n{text}")
    print('PASS', case['name'])


def check_sequence(name, lines, target, should_fire):
    text = replay(lines)
    ids = re.findall(r"\*\*Phase 3:.*?\bid: '(\d+)'", text, re.S)
    if len(ids) != len(lines):
        raise AssertionError(f'{name}: not every event was classified\n{text}')
    if (str(target) in ids) != should_fire:
        raise AssertionError(f'{name}: rule {target}, observed {ids}\n{text}')
    print('PASS', name)


block = next(case['line'] for case in fixtures if case['name']=='current-cef-block')
check_sequence('repeated-cef-blocks-same-ip', [block]*10, 100154, True)
check_sequence('cef-blocks-different-ips',
               [block.replace('src=192.0.2.42', f'src=192.0.2.{i}') for i in range(1,11)],
               100154, False)
wifi = fixtures[0]['line']
check_sequence('same-mac-changing-alias',
               [wifi.replace('Test Watch', f'Client {i}') for i in range(8)], 100153, True)
check_sequence('same-alias-different-macs',
               [wifi.replace('02:00:00:00:00:42', f'02:00:00:00:00:{i:02x}') for i in range(8)],
               100153, False)
radius = next(case['line'] for case in fixtures if case['name']=='radius-failed')
check_sequence('repeated-radius-failures', [radius]*5, 100210, True)
print(f'{len(fixtures)} fixtures and 5 correlation sequences passed')
