from packaging.requirements import Requirement

def parse_requirements_txt(file_path):
    dependencies = []

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                req = Requirement(line)
                dependencies.append({
                    'name': req.name,
                    'specifier': str(req.specifier)
                })
            except Exception:
                continue

    return dependencies
