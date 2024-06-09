import re

def detect_short_address_attack(file_path):
    with open(file_path, 'r') as solidity_file:
        contract_code = solidity_file.read()

    short_address_attack_pattern = re.compile(r'\.call\(.*\.gas\)$')

    vulnerable_lines = []
    lines = contract_code.split('\n')
    for line_number, line in enumerate(lines, start=1):
        if short_address_attack_pattern.search(line):
            vulnerable_lines.append(line_number)

    return vulnerable_lines