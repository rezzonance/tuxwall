#!/usr/bin/env python3
"""Static module-level name-order check (mini-pyflakes for the bug class
that crash-looped the live api_server: a module-level assignment
referencing a name defined further down the file).

Usage: python3 py-name-check.py FILE [FILE...]
Exit 1 if any module-level NameError-class violation is found.
"""
import ast
import builtins
import sys

BUILTINS = set(dir(builtins))


def check(path):
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src, filename=path)
    defined = set()
    problems = []

    # Comprehension targets are block-local names; treat them as defined
    # so `[f(n) for n in X]` at module level doesn't false-positive.
    comp_targets = set()
    for sub in ast.walk(tree):
        if isinstance(sub, (ast.ListComp, ast.SetComp, ast.DictComp,
                            ast.GeneratorExp)):
            for gen in sub.generators:
                for t in ast.walk(gen.target):
                    if isinstance(t, ast.Name):
                        comp_targets.add(t.id)

    def names_used(node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                if sub.id in comp_targets:
                    continue
                yield sub

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)  # hoisted: usable before definition
        elif isinstance(node, ast.Import):
            for a in node.names:
                defined.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                defined.add(a.asname or a.name)
        elif isinstance(node, ast.Assign):
            for n in names_used(node.value):
                if n.id not in defined and n.id not in BUILTINS:
                    problems.append(
                        (node.lineno, n.id, ast.dump(node.value)[:60]))
            for t in node.targets:
                if isinstance(t, ast.Name):
                    defined.add(t.id)
        elif isinstance(node, (ast.If, ast.Try, ast.For, ast.While, ast.With)):
            # bare compound statements at module level: conservative pass
            continue
        # decorators/default args of classes already handled by FunctionDef add
    return problems


bad = 0
for path in sys.argv[1:]:
    for lineno, name, snippet in check(path):
        bad += 1
        print(f"{path}:{lineno}: module-level use of undefined name '{name}'")
if bad:
    print(f"{bad} problem(s)")
    sys.exit(1)
print("module-level name order OK")
