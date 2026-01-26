from flask import Blueprint, request, render_template, redirect, url_for
import os
from app.services.parser import parse_requirements_txt
from app.services.osv_client import query_osv
from flask import Blueprint, render_template

import os

# 找到当前文件的绝对路径
current_dir = os.path.dirname(os.path.abspath(__file__))
template_path = os.path.join(current_dir, '../templates')

upload_bp = Blueprint(
    'upload',
    __name__,
    template_folder=template_path
)

@upload_bp.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template("upload.html", error="未上传文件")
        file = request.files['file']
        if file.filename != 'requirements.txt':
            return render_template("upload.html", error="只支持 requirements.txt")

        os.makedirs('uploads', exist_ok=True)
        save_path = os.path.join('uploads', file.filename)
        file.save(save_path)

        deps = parse_requirements_txt(save_path)
        results = []

        for dep in deps:
            vulns = []
            if dep['specifier'].startswith('=='):
                version = dep['specifier'].replace('==','')
                vulns = query_osv(dep['name'], version)

            # 精简返回
            simplified_vulns = [
                {
                    'id': v.get('id'),
                    'summary': v.get('summary'),
                    'severity': v.get('severity')[0]['score'] if v.get('severity') else None
                }
                for v in vulns
            ]

            results.append({
                'name': dep['name'],
                'version': dep['specifier'],
                'vulnerabilities': simplified_vulns
            })

        return render_template("result.html", scan_result=results)

    return render_template("upload.html")
