"""Static route discovery for www/includes/api_server.py (AST, no import).

Entry points are the do_<METHOD> methods of every BaseHTTPRequestHandler
subclass. Inside them (and, transitively, inside every helper that is
handed the request path as an argument - interfaces_get(path, ...),
self._backup_post(path, ...), _agent_ro_identity(self, path), ...) these
patterns on the path variable become routes:

    path == "/api/x"                      exact
    path in ("/api/a", "/api/b")          exact (literal tuple/list/set)
    path in SOME_CONSTANT                 exact (module-level str collection)
    path.startswith("/api/x/")            prefix   (also tuples / constants)
    re.match(r"^/api/x/(a|b)$", path)     regex    (expanded to sample paths)
    TABLE.get(path) / TABLE[path]         exact    (module-level dict keys)

The method of a route is the do_<METHOD> it was reached from. Prefixes
that come from the gate lists (GATE_LISTS) and the bare "/api/" are gates,
not routes; they are returned separately so the checker can probe them.

    python3 tools/route_discovery.py [api_server.py]   # print the route list
"""
import ast
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "www", "includes", "api_server.py")
# module-level collections the handlers use as role/token gates
GATE_LISTS = ("ADMIN_GET_PREFIXES", "VIEWER_POST_PATHS", "AGENT_API_READ_PATHS")
ROUTE_LITERAL_RE = re.compile(r"^/api(/[A-Za-z0-9._~/-]*)?$")


class Route:
    __slots__ = ("method", "kind", "value", "line", "via", "samples")

    def __init__(self, method, kind, value, line, via, samples=()):
        self.method, self.kind, self.value, self.line, self.via = method, kind, value, line, via
        self.samples = tuple(samples)

    @property
    def key(self):
        if self.kind == "prefix":
            return "%s %s*" % (self.method, self.value)
        return "%s %s" % (self.method, self.value)

    def paths(self):
        """Concrete request paths that exercise this route."""
        if self.kind == "exact":
            return [self.value]
        if self.kind == "prefix":
            base = self.value
            deep = base + ("" if base.endswith("/") else "/") + "probe/deep"
            return [base, deep] if not base.endswith("/") else [base + "probe", deep]
        return list(self.samples)

    def matches(self, literal):
        if self.kind == "exact":
            return literal == self.value
        if self.kind == "prefix":
            return literal.startswith(self.value)
        return re.match(self.value, literal) is not None

    def __repr__(self):
        return "<%s %s %s:%d via %s>" % (self.method, self.kind, self.value, self.line, self.via)


def _str_collection(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
            node.func.id in ("frozenset", "set", "tuple", "list") and node.args:
        node = node.args[0]
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)) and node.elts and \
            all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts):
        return [e.value for e in node.elts]
    if isinstance(node, ast.Dict) and node.keys and \
            all(isinstance(k, ast.Constant) and isinstance(k.value, str) for k in node.keys):
        return [k.value for k in node.keys]
    return None


def _regex_samples(pattern):
    """All alternation expansions of a route regex, one sample value per
    character class/repeat. Returns [] for constructs it does not model."""
    try:
        import re._parser as sre_parse
        import re._constants as sre_c
    except ImportError:            # Python < 3.11
        import sre_parse
        import sre_constants as sre_c

    def gen(items):
        outs = [""]
        for op, av in items:
            if op is sre_c.LITERAL:
                parts = [chr(av)]
            elif op is sre_c.AT:
                parts = [""]
            elif op is sre_c.SUBPATTERN:
                parts = gen(av[-1])
            elif op is sre_c.BRANCH:
                parts = [s for b in av[1] for s in gen(b)]
            elif op is sre_c.IN:
                ch = None
                for cop, cav in av:
                    if cop is sre_c.LITERAL:
                        ch = chr(cav)
                    elif cop is sre_c.RANGE:
                        ch = chr(cav[0])
                    if ch:
                        break
                if ch is None:
                    return []
                parts = [ch]
            elif op in (sre_c.MAX_REPEAT, sre_c.MIN_REPEAT):
                lo, _hi, sub = av
                one = gen(sub)
                if not one:
                    return []
                parts = [one[0] * max(lo, 1)] if len(one) == 1 else [o * max(lo, 1) for o in one]
            else:
                return []
            outs = [o + p for o in outs for p in parts]
            if len(outs) > 64:
                return outs
        return outs
    try:
        return gen(sre_parse.parse(pattern))
    except Exception:
        return []


class Discovery:
    def __init__(self, source):
        self.tree = ast.parse(source)
        self.source = source
        self.consts = {}
        for n in self.tree.body:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                vals = _str_collection(n.value)
                if vals is not None:
                    self.consts[n.targets[0].id] = vals
        self.funcs = {}
        self.handlers = []        # (class, method, FunctionDef)
        for n in self.tree.body:
            if isinstance(n, ast.FunctionDef):
                self.funcs[n.name] = n
            elif isinstance(n, ast.ClassDef):
                for m in n.body:
                    if isinstance(m, ast.FunctionDef):
                        self.funcs["%s.%s" % (n.name, m.name)] = m
                        if m.name.startswith("do_") and m.name[3:].isupper():
                            self.handlers.append((n.name, m.name[3:], m))
        self.routes = {}          # key -> Route
        self.gates = {}           # (method, prefix) -> source
        self.notes = []
        for cls, method, fn in self.handlers:
            self._walk(fn, cls, method, self._path_vars(fn), set(), fn.name)

    @staticmethod
    def _path_vars(fn):
        """Variables holding the request path: `path = self.path...`."""
        names = set()
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                src = ast.unparse(n.value)
                if src.startswith("self.path") or src.startswith("urllib.parse.urlsplit(self.path).path"):
                    names.add(n.targets[0].id)
        return names or {"path"}

    def _add(self, method, kind, value, line, via, gate=False, samples=()):
        if gate or value == "/api/" or value == "/api":
            self.gates.setdefault((method, value), via)
            return
        r = Route(method, kind, value, line, via, samples)
        self.routes.setdefault(r.key, r)

    def _values(self, node):
        """(values, from_gate_list) for a comparator node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value], False
        if isinstance(node, ast.Name) and node.id in self.consts:
            return self.consts[node.id], node.id in GATE_LISTS
        vals = _str_collection(node)
        return (vals or []), False

    def _resolve(self, call, cls):
        f = call.func
        if isinstance(f, ast.Name) and f.id in self.funcs:
            return self.funcs[f.id], 0
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "self":
            fn = self.funcs.get("%s.%s" % (cls, f.attr))
            if fn is None:   # inherited / mixin: any class defining it
                fn = next((v for k, v in self.funcs.items() if k.endswith("." + f.attr)), None)
            if fn is not None:
                return fn, 1
        return None, 0

    def _walk(self, fn, cls, method, pvars, seen, via):
        if (fn.name, method, frozenset(pvars)) in seen:
            return
        seen.add((fn.name, method, frozenset(pvars)))
        for n in ast.walk(fn):
            if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name) and n.left.id in pvars:
                for op, comp in zip(n.ops, n.comparators):
                    if isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)):
                        vals, gate = self._values(comp)
                        for v in vals:
                            if v.startswith("/"):
                                self._add(method, "exact", v, n.lineno, via, gate)
            elif isinstance(n, ast.Call):
                f = n.func
                if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in pvars \
                        and f.attr == "startswith" and n.args:
                    vals, gate = self._values(n.args[0])
                    for v in vals:
                        if v.startswith("/"):
                            self._add(method, "prefix", v, n.lineno, via, gate)
                elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "re" \
                        and f.attr in ("match", "fullmatch", "search") and len(n.args) >= 2 \
                        and isinstance(n.args[1], ast.Name) and n.args[1].id in pvars \
                        and isinstance(n.args[0], ast.Constant):
                    pat = n.args[0].value
                    samples = _regex_samples(pat)
                    if not samples:
                        self.notes.append("regex at line %d not expanded: %s" % (n.lineno, pat))
                    self._add(method, "regex", pat, n.lineno, via, samples=samples)
                elif isinstance(f, ast.Attribute) and f.attr == "get" and isinstance(f.value, ast.Name) \
                        and f.value.id in self.consts and n.args and isinstance(n.args[0], ast.Name) \
                        and n.args[0].id in pvars:
                    for v in self.consts[f.value.id]:
                        if v.startswith("/"):
                            self._add(method, "exact", v, n.lineno, via)
                else:
                    callee, skip = self._resolve(n, cls)
                    if callee is None:
                        continue
                    params = [a.arg for a in callee.args.args][skip:]
                    sub = set()
                    for i, a in enumerate(n.args):
                        if isinstance(a, ast.Name) and a.id in pvars and i < len(params):
                            sub.add(params[i])
                    for kw in n.keywords:
                        if isinstance(kw.value, ast.Name) and kw.value.id in pvars and kw.arg:
                            sub.add(kw.arg)
                    if sub:
                        self._walk(callee, cls, method, sub, seen, "%s>%s" % (via, callee.name))
            elif isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id in self.consts \
                    and isinstance(n.slice, ast.Name) and n.slice.id in pvars:
                for v in self.consts[n.value.id]:
                    if v.startswith("/"):
                        self._add(method, "exact", v, n.lineno, via)

    def methods(self):
        return sorted({m for _c, m, _f in self.handlers})

    def literals(self):
        """The crude grep: every "/api..." string literal in the file."""
        out = {}
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and ROUTE_LITERAL_RE.match(n.value):
                out.setdefault(n.value, n.lineno)
        return out

    def coverage(self):
        """(covered literals, uncovered {literal: line})."""
        routes = list(self.routes.values())
        lits = self.literals()
        covered, uncovered = {}, {}
        for lit, line in sorted(lits.items()):
            hit = next((r for r in routes if r.matches(lit)), None)
            if hit is None and any(lit == g or lit.rstrip("/") == g.rstrip("/") for _m, g in self.gates):
                hit = "gate"
            (covered if hit else uncovered)[lit] = line
        return covered, uncovered


def discover(path=TARGET):
    with open(path, encoding="utf-8") as f:
        return Discovery(f.read())


if __name__ == "__main__":
    d = discover(sys.argv[1] if len(sys.argv) > 1 else TARGET)
    for key in sorted(d.routes, key=lambda k: (k.split()[1], k)):
        r = d.routes[key]
        print("%-6s %-7s %-60s line %-6d via %s" % (r.method, r.kind, r.value, r.line, r.via))
    for (m, g), via in sorted(d.gates.items()):
        print("gate   %-6s %-60s via %s" % (m, g, via))
    cov, unc = d.coverage()
    print("routes: %d  (%s)" % (len(d.routes), ", ".join(
        "%s %d" % (m, sum(1 for r in d.routes.values() if r.method == m)) for m in d.methods())))
    print("literal coverage: %d/%d" % (len(cov), len(cov) + len(unc)))
    for lit, line in unc.items():
        print("  not a route: %s (line %d)" % (lit, line))
    for n in d.notes:
        print("note:", n)
