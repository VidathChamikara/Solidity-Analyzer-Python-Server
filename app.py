from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
from reenreancy import detect_reentrancy_vulnerabilities, fix_reentrancy_vulnerabilities
from delegatecall import detect_delegate_call_vulnerabilities, fix_delegate_call_vulnerabilities
from integer import detect_integer_overflow_underflow
from insecurerandom import detect_insecure_randomness, fix_insecure_randomness
from loopedcall import detect_looped_calls_vulnerability, fix_looped_calls_vulnerability
from selfdesctruct import detect_self_destruct
from short_address import detect_short_address_attack
from throw import throw_vulnerability_detection
from uncheckedexternal import detect_unchecked_external, detect_and_fix_unchecked_external_call

app = Flask(__name__,static_folder='upload')
CORS(app)



UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'sol'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/uploads/<filename>')
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/process', methods=['POST'])
def process_solidity_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        fixed_file_path = file_path
        
        re_entrancy_vulnerabilities = detect_reentrancy_vulnerabilities(file_path)
        if re_entrancy_vulnerabilities:
            fixed_file_path = fix_reentrancy_vulnerabilities(file_path)

        delegate_vulnerabilities = detect_delegate_call_vulnerabilities(fixed_file_path)
        if delegate_vulnerabilities:
            fixed_file_path = fix_delegate_call_vulnerabilities(fixed_file_path)       
        
        insecure_rand_vulnerabilities = detect_insecure_randomness(fixed_file_path)
        if insecure_rand_vulnerabilities:
            fixed_file_path = fix_insecure_randomness(fixed_file_path)
        
        looped_call_vulnerabilities = detect_looped_calls_vulnerability(fixed_file_path)
        if looped_call_vulnerabilities:
            fixed_file_path = fix_looped_calls_vulnerability(fixed_file_path)

        unchecked_ext_vulnerabilities = detect_unchecked_external(fixed_file_path)
        if unchecked_ext_vulnerabilities:
            fixed_file_path = detect_and_fix_unchecked_external_call(fixed_file_path)
        
        self_destruct_vul = detect_self_destruct(fixed_file_path)

        shot_addr_vul = detect_short_address_attack(fixed_file_path)

        integer_vulnerabilities = detect_integer_overflow_underflow(fixed_file_path)

        throw_vul = throw_vulnerability_detection(fixed_file_path)
        
        return jsonify({
            "success":"Completed!",
            "file_path": fixed_file_path,
            "message": "Success",
            "reentrancy_amount": len(re_entrancy_vulnerabilities),
            "reenteancy_lines": re_entrancy_vulnerabilities,
            "delegate_amount": len(delegate_vulnerabilities),
            "delegate_lines": delegate_vulnerabilities,
            "integer_amount": len(integer_vulnerabilities),
            "integer_lines": integer_vulnerabilities,
            "insecure_lines": insecure_rand_vulnerabilities,
            "insecure_amt": len(insecure_rand_vulnerabilities),
            "looped_amt": len(looped_call_vulnerabilities),
            "looped_lines": looped_call_vulnerabilities,
            "unchecked_amt": len(unchecked_ext_vulnerabilities),
            "unchecked_lines": unchecked_ext_vulnerabilities,
            "self_des_lines": self_destruct_vul,
            "self_des_amt": len(self_destruct_vul),
            "short_a_lines": shot_addr_vul,
            "short_a_amt": len(shot_addr_vul),
            "throw_lines": throw_vul,
            "throw_amt": len(throw_vul),
        })
    else:
        return jsonify({'error': 'Invalid file format'})



