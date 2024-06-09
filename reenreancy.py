import re

def detect_reentrancy_vulnerabilities(file_path):
    with open(file_path, 'r') as file:
        solidity_code = file.read()

    pattern = r'call\.value\((.*?)\)'

    vulnerable_lines = []
    for line_number, line in enumerate(solidity_code.split('\n'), start=1):
        if re.search(pattern, line):
            vulnerable_lines.append(line_number)

    return vulnerable_lines

def fix_reentrancy_vulnerabilities(file_path):
    with open(file_path, 'r') as file:
        solidity_code = file.read()

    pattern = r'call\.value\((.*?)\)'

    fixed_code = re.sub(pattern, r'call.gas(2300).value(\1)', solidity_code)

    fixed_file_path = file_path.replace('.sol', '_fixed.sol')
    with open(fixed_file_path, 'w') as file:
        file.write(fixed_code)

    return fixed_file_path

