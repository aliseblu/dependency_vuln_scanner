import ast
import toml
from packaging.requirements import Requirement

def parse_requirements_txt(file_path):
    deps = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            try:
                req = Requirement(line)
                deps.append({'name': req.name, 'specifier': str(req.specifier)})
            except:
                pass
    return deps

def parse_setup_py(file_path):
    deps = []
    with open(file_path, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read(), filename=file_path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'setup':
            for kw in node.keywords:
                if kw.arg == 'install_requires' and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant):
                            try:
                                req = Requirement(elt.value)
                                deps.append({'name': req.name, 'specifier': str(req.specifier)})
                            except:
                                pass
    return deps

def parse_pipfile(file_path):
    deps = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = toml.load(f)
        packages = data.get('packages', {})
        for name, version in packages.items():
            spec = version if isinstance(version, str) and version != "*" else ""
            deps.append({'name': name, 'specifier': spec})
    except:
        pass
    return deps

def parse_dependency_file(file_path, filename):
    if filename == 'requirements.txt': return parse_requirements_txt(file_path)
    elif filename == 'setup.py': return parse_setup_py(file_path)
    elif filename.lower() == 'pipfile': return parse_pipfile(file_path)
    return []