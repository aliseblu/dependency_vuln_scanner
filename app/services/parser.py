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
        if isinstance(node, ast.Call):
            # 1. 匹配直接调用 setup() 的情况
            is_setup = isinstance(node.func, ast.Name) and node.func.id == 'setup'
            # 2. 匹配通过 setuptools.setup() 调用的情况 (修复 edge02 的 Bug)
            is_setuptools_setup = isinstance(node.func, ast.Attribute) and node.func.attr == 'setup'

            if is_setup or is_setuptools_setup:
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
    fn = filename.lower()
    # 增加 or fn.endswith('.txt')
    if 'requirements' in fn or 'req' in fn or fn.endswith('.txt'):
        return parse_requirements_txt(file_path)
    elif 'setup.py' in fn:
        return parse_setup_py(file_path)
    elif 'pipfile' in fn:
        return parse_pipfile(file_path)
    return []