from flask import Blueprint, request, jsonify
import os
from app.services.parser import parse_requirements_txt
from app.services.osv_client import query_osv

upload_bp = Blueprint('upload', __name__)

@upload_bp.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename != 'requirements.txt':
        return jsonify({'error': 'Only requirements.txt supported'}), 400

    os.makedirs('uploads', exist_ok=True)
    save_path = os.path.join('uploads', file.filename)
    file.save(save_path)

    deps = parse_requirements_txt(save_path)

    results = []

    for dep in deps:
        vulns = []
        # 只处理精确版本
        if dep['specifier'].startswith('=='):
            version = dep['specifier'].replace('==', '')
            vulns = query_osv(dep['name'], version)

        results.append({
            'name': dep['name'],
            'version': dep['specifier'],
            'vulnerabilities': [
                {
                    'id': v.get('id'),
                    'summary': v.get('summary')
                } for v in vulns
            ]
        })

    return jsonify({'scan_result': results})
