import re


def parse_contract(contract):
    return contract.split('\n')


def detect_looped_calls_vulnerability(file_path):
    with open(file_path, 'r') as file:
        contract_code = file.read()
    pattern = re.compile(r'^.*\[.*\]\.?.*\.(transfer|send|call)\(.*\)')

    lines = contract_code.split('\n')
    vulnerable_lines = []

    for line_number, line in enumerate(lines, start=1):
        if pattern.match(line):
            vulnerable_lines.append(line_number)

    return vulnerable_lines


def fix_looped_calls_vulnerability(file_path):
    with open(file_path, 'r') as file:
        contract_code = file.read()
    pattern = re.compile(r'^.*\[.*\]\.?.*\.(transfer|send|call)\(.*\)')

    safer_withdrawal = r'withdraw(msg.sender);'

    lines = contract_code.split('\n')
    fixed_lines = []

    for line in lines:
        if pattern.match(line):
            fixed_line = re.sub(pattern, safer_withdrawal, line)
            fixed_lines.append(fixed_line)
        else:
            fixed_lines.append(line)

    fixed_contract_code = '\n'.join(fixed_lines)
    fixed_file_path = file_path.replace('.sol', '_fixed.sol')
    with open(fixed_file_path, 'w') as file:
        file.write(fixed_contract_code)

    return fixed_file_path