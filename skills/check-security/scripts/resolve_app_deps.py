import argparse
import ast
from pathlib import Path


def iter_imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, 0
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            yield node.module, node.level


def module_to_path(root, module):
    parts = module.split('.')
    # Try package __init__.py
    pkg_path = root.joinpath(*parts, '__init__.py')
    if pkg_path.exists():
        return pkg_path
    # Try module file
    mod_path = root.joinpath(*parts).with_suffix('.py')
    if mod_path.exists():
        return mod_path
    return None


def resolve_module(root, current_file, module, level):
    if level == 0:
        return module_to_path(root, module)
    # relative import
    base = current_file.parent
    for _ in range(level - 1):
        base = base.parent
    rel_parts = module.split('.') if module else []
    target = base.joinpath(*rel_parts)
    if (target / '__init__.py').exists():
        return target / '__init__.py'
    if target.with_suffix('.py').exists():
        return target.with_suffix('.py')
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--root', default='.')
    parser.add_argument('-e', '--entry', default='app.py')
    args = parser.parse_args()

    root = Path(args.root).resolve()
    entry = root / args.entry
    if not entry.exists():
        raise SystemExit(f'Entry not found: {entry}')

    seen = set()
    stack = [entry]

    while stack:
        path = stack.pop()
        if path in seen:
            continue
        seen.add(path)

        try:
            tree = ast.parse(path.read_text(encoding='utf-8'))
        except Exception:
            continue

        for mod, level in iter_imports(tree):
            target = resolve_module(root, path, mod, level)
            if target and target.exists():
                stack.append(target)

    for p in sorted(seen):
        print(str(p))


if __name__ == '__main__':
    main()
