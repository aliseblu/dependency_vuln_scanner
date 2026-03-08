from app.models import Vulnerability
import json
from packaging.version import parse as parse_version, InvalidVersion


def check_version_in_range(target_version, affected_ranges):
    """
    语义化版本比对核心逻辑
    target_version: 提取到的版本，如 '2.2'
    affected_ranges: [{"introduced": "0", "fixed": "2.2.1"}]
    """
    if not target_version: return True  # 如果没指定版本，默认提示风险
    target_version = target_version.replace('==', '').replace('>=', '').replace('<=', '').strip()

    try:
        t_ver = parse_version(target_version)
    except InvalidVersion:
        return False

    for r in affected_ranges:
        introduced = r.get('introduced', '0')
        fixed = r.get('fixed')
        try:
            intro_ver = parse_version(introduced)
            if fixed:
                fixed_ver = parse_version(fixed)
                if intro_ver <= t_ver < fixed_ver:
                    return True
            else:
                if intro_ver <= t_ver:
                    return True
        except InvalidVersion:
            continue
    return False


def match_vulnerabilities(dependencies):
    results = []
    for dep in dependencies:
        name = dep['name']
        version_spec = dep['specifier']

        # 查询本地 MySQL 库
        db_vulns = Vulnerability.query.filter(Vulnerability.package_name.ilike(name)).all()
        hit_vulns = []

        for vuln in db_vulns:
            try:
                ranges = json.loads(vuln.affected_versions)
            except:
                ranges = []

            if check_version_in_range(version_spec, ranges):
                hit_vulns.append({
                    'id': vuln.id,
                    'summary': vuln.summary,
                    'severity': vuln.severity
                })

        results.append({
            'name': name,
            'version': version_spec,
            'vulnerabilities': hit_vulns
        })
    return results