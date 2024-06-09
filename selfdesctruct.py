import re

def detect_self_destruct(file_path):
    with open(file_path, 'r') as solidity_file:
        contract_code = solidity_file.read()
    pattern = re.compile(r'^.*selfdestruct\(.*\).*|^.*suicide\(.*\).*')

    lines = contract_code.split('\n')

    matching_lines = [(i + 1, line) for i, line in enumerate(lines) if pattern.match(line)]

    return matching_lines