import re

def detect_unchecked_external(file_path):
    with open(file_path, 'r') as solidity_file:
        contract_code = solidity_file.read()

    pattern = re.compile(r'^.*\.send\(.*\).*')
    lines = contract_code.split('\n')
    matching_lines = [line for line in lines if pattern.match(line)]
    return matching_lines


def detect_and_fix_unchecked_external_call(file_path):
    with open(file_path, 'r') as solidity_file:
        contract_code = solidity_file.read()

    unchecked_external_call_pattern = re.compile(r'^.*\.send\(.*\).*')

    vulnerable_lines = []
    lines = contract_code.split('\n')
    for line_number, line in enumerate(lines, start=1):
        if unchecked_external_call_pattern.match(line):
            vulnerable_lines.append(line_number)

    fixed_code = []
    for line_number, line in enumerate(lines, start=1):
        if line_number in vulnerable_lines:
            fixed_line = re.sub(unchecked_external_call_pattern, '', line)
            fixed_line += f'require(!target.call{{value: msg.value}}(""), "External call failed");'
            fixed_code.append(fixed_line)
        else:
            fixed_code.append(line)

   
    with open(file_path, 'w') as fixed_solidity_file:
        fixed_solidity_file.write('\n'.join(fixed_code))
    
    return file_path