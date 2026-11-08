"""Local source-consistency checks for the V2 reference's repository closure.

Names, imports, code and defaults are checked against parsed source, including
modules that V1's historical guard only inspected by a function's self-reported
``__module__``.  Nothing here authenticates a remote interpreter, an operating
system or a native owner.  The checker and installed runtime are trusted; an
attacker with arbitrary same-process writes can also replace the checker itself.

Standard-library/extension internals remain runtime dependencies.  In
particular, checking the imported ``time`` module's identity does not read or
pin ``time.time_ns``; historical replay has no present-clock dependency.
"""
from __future__ import annotations

import ast
import builtins
import dataclasses
import dis
import functools
import gc
import hashlib
import operator
from pathlib import Path
import sys
import types

_CACHE = {}
_MISSING = object()


def _require(value, code):
    if not value:
        raise ValueError(code)


def _same_value(left, right):
    if type(left) is not type(right):
        return False
    if type(right) in (tuple, list):
        return len(left) == len(right) and all(_same_value(a, b) for a, b in zip(left, right))
    if type(right) is dict:
        return left.keys() == right.keys() and all(_same_value(left[k], right[k]) for k in right)
    if type(right) in (int, str, bytes, bool, float, type(None)):
        return left == right
    if type(right) in (set, frozenset):
        return {(type(x), repr(x)) for x in left} == {(type(x), repr(x)) for x in right}
    return left is right


def _expression(node, environment):
    """Interpret literals/names and bounded integer arithmetic, never calls."""
    if isinstance(node, ast.Constant):
        _require(type(node.value) in (int, str, bytes, bool, float, type(None)),
                 'V2_SOURCE_GUARD_EXPRESSION')
        return node.value
    if isinstance(node, ast.Name):
        if node.id in environment:
            return environment[node.id]
        if node.id in vars(builtins):
            return vars(builtins)[node.id]
        raise ValueError('V2_SOURCE_GUARD_EXPRESSION')
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        values = [_expression(item, environment) for item in node.elts]
        return tuple(values) if isinstance(node, ast.Tuple) else set(values) if isinstance(node, ast.Set) else values
    if isinstance(node, ast.Dict) and all(key is not None for key in node.keys):
        return {_expression(key, environment): _expression(value, environment)
                for key, value in zip(node.keys, node.values)}
    unary = {ast.USub: operator.neg, ast.UAdd: operator.pos, ast.Invert: operator.invert}
    binary = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
              ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
              ast.LShift: operator.lshift, ast.RShift: operator.rshift}
    if isinstance(node, ast.UnaryOp) and type(node.op) in unary:
        value = _expression(node.operand, environment)
        if type(value) is int and value.bit_length() <= 512:
            return unary[type(node.op)](value)
    if isinstance(node, ast.BinOp) and type(node.op) in binary:
        left, right = _expression(node.left, environment), _expression(node.right, environment)
        if isinstance(node.op, ast.Add) and type(left) is type(right) and type(left) in (str, bytes, tuple, list):
            _require(len(left) + len(right) <= 1 << 20, 'V2_SOURCE_GUARD_EXPRESSION')
            return left + right
        if type(left) is int and type(right) is int and max(left.bit_length(), right.bit_length()) <= 512:
            if type(node.op) in (ast.LShift, ast.RShift):
                _require(0 <= right <= 512, 'V2_SOURCE_GUARD_EXPRESSION')
            value = binary[type(node.op)](left, right)
            _require(value.bit_length() <= 1024, 'V2_SOURCE_GUARD_EXPRESSION')
            return value
    raise ValueError('V2_SOURCE_GUARD_EXPRESSION')


def _targets(node):
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _targets(item)]
    return []


def _inventory(code):
    result = [code]
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            result.extend(_inventory(value))
    return result


def _module_record(root, relative, raw):
    path = (root / relative).resolve()
    _require(path.read_bytes() == raw, 'V2_SOURCE_CHANGED_RESTART_REQUIRED')
    name = relative.removeprefix('formal/pon-nakamoto-v1/').removesuffix('.py').replace('/', '.')
    module = sys.modules.get(name)
    _require(type(module) is types.ModuleType and module.__name__ == name and
             Path(module.__file__).resolve() == path, 'V2_MODULE_ORIGIN')
    key = (str(path), hashlib.sha256(raw).digest())
    if key not in _CACHE:
        tree = ast.parse(raw)
        code = compile(raw, str(path), 'exec', dont_inherit=True)
        _CACHE[key] = (tree, _inventory(code))
    tree, codes = _CACHE[key]
    return {'name': name, 'module': module, 'tree': tree, 'codes': codes}


def _reference_code(record, qualname, line=None):
    values = [code for code in record['codes'] if code.co_qualname == qualname and
              (line is None or code.co_firstlineno == line)]
    _require(len(values) == 1, 'V2_SOURCE_GUARD_CODE_INVENTORY')
    return values[0]


def _default_value(actual, node, record):
    if isinstance(node, ast.Lambda):
        _require(type(actual) is types.FunctionType and
                 actual.__globals__ is vars(record['module']) and actual.__closure__ is None and
                 actual.__code__ == _reference_code(record, actual.__code__.co_qualname, node.lineno),
                 'V2_LOADED_DEFAULT_MISMATCH')
        _require(not hasattr(actual, '__wrapped__'), 'V2_LOADED_DEFAULT_MISMATCH')
        _defaults(actual, node.args, record)
        return
    try:
        expected = _expression(node, vars(record['module']))
    except (ValueError, TypeError, KeyError, ZeroDivisionError) as error:
        raise ValueError('V2_SOURCE_GUARD_UNSUPPORTED_DEFAULT') from error
    _require(_same_value(actual, expected), 'V2_LOADED_DEFAULT_MISMATCH')


def _defaults(function, arguments, record):
    defaults = function.__defaults__
    expected = arguments.defaults
    _require((defaults is None and not expected) or
             (type(defaults) is tuple and len(defaults) == len(expected)), 'V2_LOADED_DEFAULT_MISMATCH')
    for actual, node in zip(defaults or (), expected):
        _default_value(actual, node, record)
    expected_keywords = {argument.arg: value for argument, value in
                         zip(arguments.kwonlyargs, arguments.kw_defaults) if value is not None}
    actual_keywords = function.__kwdefaults__
    _require((actual_keywords is None and not expected_keywords) or
             (type(actual_keywords) is dict and set(actual_keywords) == set(expected_keywords)),
             'V2_LOADED_DEFAULT_MISMATCH')
    for name, node in expected_keywords.items():
        _default_value(actual_keywords[name], node, record)


def _function(actual, node, record, qualname, owner=None):
    if node.decorator_list:
        _require(len(node.decorator_list) == 1, 'V2_SOURCE_GUARD_DECORATOR')
        decorator = node.decorator_list[0]
        _require(isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name) and
                 decorator.func.id == 'lru_cache' and not decorator.args and
                 all(item.arg in ('maxsize', 'typed') for item in decorator.keywords),
                 'V2_SOURCE_GUARD_DECORATOR')
        _require(type(actual) is functools._lru_cache_wrapper, 'V2_LOADED_BINDING_MISMATCH')
        # Inspect the actual C wrapper referent, not inspect.unwrap's mutable
        # __wrapped__ attribute. A Python outer wrapper cannot hide behind it.
        functions = [item for item in gc.get_referents(actual) if type(item) is types.FunctionType]
        _require(len(functions) == 1 and actual.__wrapped__ is functions[0],
                 'V2_LOADED_WRAPPER_MISMATCH')
        parameters = {'maxsize': 128, 'typed': False}
        parameters.update({item.arg: _expression(item.value, vars(record['module']))
                           for item in decorator.keywords})
        _require(_same_value(actual.cache_parameters(), parameters), 'V2_LOADED_WRAPPER_MISMATCH')
        actual = functions[0]
    else:
        _require(type(actual) is types.FunctionType and not hasattr(actual, '__wrapped__'),
                 'V2_LOADED_BINDING_MISMATCH')
    _require(type(actual) is types.FunctionType and actual.__module__ == record['name'] and
             actual.__name__ == node.name and actual.__qualname__ == qualname and
             actual.__globals__ is vars(record['module']), 'V2_LOADED_BINDING_MISMATCH')
    _require(actual.__builtins__ is vars(builtins), 'V2_BUILTIN_BINDING_MISMATCH')
    _require(actual.__code__ == _reference_code(record, qualname), 'V2_LOADED_CODE_MISMATCH')
    freevars = actual.__code__.co_freevars
    closure = actual.__closure__ or ()
    _require(len(freevars) == len(closure), 'V2_LOADED_CLOSURE_MISMATCH')
    for name, cell in zip(freevars, closure):
        _require(name == '__class__' and owner is not None and cell.cell_contents is owner,
                 'V2_LOADED_CLOSURE_MISMATCH')
    _defaults(actual, node.args, record)


def _generated_function(actual, reference, owner, reference_owner):
    """Compare the installed dataclass generator's methods and real closures."""
    _require(type(actual) is types.FunctionType and actual.__code__ == reference.__code__ and
             actual.__globals__ is reference.__globals__ and
             _same_value(actual.__defaults__, reference.__defaults__) and
             _same_value(actual.__kwdefaults__, reference.__kwdefaults__), 'V2_LOADED_CLASS_MISMATCH')
    closure, expected = actual.__closure__ or (), reference.__closure__ or ()
    _require(len(closure) == len(expected), 'V2_LOADED_CLASS_MISMATCH')
    for left, right in zip(closure, expected):
        left, right = left.cell_contents, right.cell_contents
        if right is reference_owner:
            _require(left is owner, 'V2_LOADED_CLASS_MISMATCH')
        elif type(right) is types.FunctionType:
            _generated_function(left, right, owner, reference_owner)
        elif type(right) is set:
            # dataclasses' repr recursion set is runtime cache state, not code.
            _require(type(left) is set, 'V2_LOADED_CLASS_MISMATCH')
        else:
            _require(_same_value(left, right), 'V2_LOADED_CLASS_MISMATCH')


def _class(actual, node, record):
    _require(type(actual) is type and actual.__module__ == record['name'] and
             actual.__qualname__ == node.name, 'V2_LOADED_CLASS_MISMATCH')
    bases = tuple(_expression(value, vars(record['module'])) for value in node.bases) or (object,)
    _require(actual.__bases__ == bases and not node.keywords, 'V2_LOADED_CLASS_MISMATCH')
    for method in node.body:
        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _function(vars(actual).get(method.name), method, record,
                      node.name + '.' + method.name, actual)
    if not node.decorator_list:
        return
    _require(len(node.decorator_list) == 1, 'V2_SOURCE_GUARD_DECORATOR')
    decorator = node.decorator_list[0]
    _require(isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name) and
             decorator.func.id == 'dataclass' and not decorator.args and
             all(item.arg == 'frozen' for item in decorator.keywords), 'V2_SOURCE_GUARD_DECORATOR')
    annotations = {}
    for field in node.body:
        _require(isinstance(field, ast.AnnAssign) and isinstance(field.target, ast.Name) and
                 field.value is None, 'V2_SOURCE_GUARD_DATACLASS')
        annotations[field.target.id] = ast.unparse(field.annotation)
    _require(_same_value(actual.__annotations__, annotations), 'V2_LOADED_CLASS_MISMATCH')
    options = {item.arg: _expression(item.value, vars(record['module'])) for item in decorator.keywords}
    reference = dataclasses.dataclass(type(node.name, bases, {
        '__module__': record['name'], '__qualname__': node.name, '__annotations__': annotations}), **options)
    for name, value in vars(reference).items():
        if type(value) is types.FunctionType:
            _generated_function(vars(actual).get(name), value, actual, reference)
    _require(actual.__match_args__ == reference.__match_args__, 'V2_LOADED_CLASS_MISMATCH')


def _defined_bindings(record):
    namespace = vars(record['module'])
    for node in record['tree'].body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _function(namespace.get(node.name), node, record, node.name)
        elif isinstance(node, ast.ClassDef):
            _class(namespace.get(node.name), node, record)


def _builtin_bindings(record):
    namespace = vars(record['module'])
    _require(namespace.get('__builtins__') is builtins or
             namespace.get('__builtins__') is vars(builtins), 'V2_BUILTIN_BINDING_MISMATCH')
    declared = set()
    for node in record['tree'].body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            declared.add(node.name)
        elif isinstance(node, ast.Import):
            declared.update(item.asname or item.name.split('.')[0] for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                if item.name == '*':
                    module = sys.modules.get(node.module)
                    _require(type(module) is types.ModuleType, 'V2_IMPORT_BINDING_MISMATCH')
                    declared.update(vars(module).get('__all__',
                                    [name for name in vars(module) if not name.startswith('_')]))
                else:
                    declared.add(item.asname or item.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                declared.update(_targets(target))
    referenced = {instruction.argval for code in record['codes'] for instruction in
                  dis.get_instructions(code) if instruction.opname == 'LOAD_GLOBAL'}
    for name in referenced:
        if name in ('__name__', '__doc__', '__package__', '__loader__', '__spec__',
                    '__file__', '__cached__', '__builtins__'):
            continue  # Interpreter-supplied module metadata, not builtin calls.
        if name in vars(builtins) and name not in declared:
            _require(name not in namespace, 'V2_BUILTIN_BINDING_MISMATCH')


def _imports(record):
    expected = {}
    for node in record['tree'].body:
        if isinstance(node, ast.Import):
            for item in node.names:
                module_name = item.name if item.asname else item.name.split('.')[0]
                value = sys.modules.get(module_name, _MISSING)
                _require(value is not _MISSING, 'V2_IMPORT_BINDING_MISMATCH')
                expected[item.asname or item.name.split('.')[0]] = value
        elif isinstance(node, ast.ImportFrom) and node.module != '__future__':
            _require(node.level == 0, 'V2_SOURCE_GUARD_RELATIVE_IMPORT')
            module = sys.modules.get(node.module)
            # Some trusted installed packages expose a deprecation proxy
            # instead of a plain ModuleType. Repository module origins are
            # independently checked by _module_record before this pass.
            _require(module is not None, 'V2_IMPORT_BINDING_MISMATCH')
            for item in node.names:
                if item.name == '*':
                    names = vars(module).get('__all__', [key for key in vars(module) if not key.startswith('_')])
                    for name in names:
                        expected[name] = vars(module).get(name, _MISSING)
                else:
                    expected[item.asname or item.name] = getattr(module, item.name, _MISSING)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            expected.pop(node.name, None)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for name in _targets(target):
                    expected.pop(name, None)
    namespace = vars(record['module'])
    for name, value in expected.items():
        _require(value is not _MISSING and namespace.get(name, _MISSING) is value,
                 'V2_IMPORT_BINDING_MISMATCH')


def _constants(record):
    namespace = vars(record['module'])
    environment = dict(namespace)

    def bind(target, value):
        if isinstance(target, ast.Name):
            if target.id.isupper() and not target.id.startswith('_'):
                _require(target.id in namespace and _same_value(namespace[target.id], value),
                         'V2_LOADED_CONSTANT_MISMATCH')
            environment[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)) and type(value) in (tuple, list):
            _require(len(target.elts) == len(value), 'V2_SOURCE_GUARD_CONSTANT')
            for child, item in zip(target.elts, value):
                bind(child, item)

    for node in record['tree'].body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        try:
            value = _expression(node.value, environment)
        except (ValueError, TypeError, KeyError, ZeroDivisionError):
            continue  # Computed configuration/runtime objects are not executed here.
        for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
            bind(target, value)


def verify_sources(root, snapshots):
    """Check every source-defined binding before trusting repository helpers.

    ``snapshots`` is the reference's import-time source-byte closure.  Changes
    require process restart and a newly admitted program; V1's source is neither
    edited nor given new behavior by this V2-only caller.
    """
    records = []
    for relative, raw in snapshots.items():
        _require(type(relative) is str and type(raw) is bytes, 'V2_SOURCE_GUARD_SNAPSHOT')
        if relative.endswith('.py'):
            records.append(_module_record(root, relative, raw))
        else:
            _require((root / relative).read_bytes() == raw, 'V2_SOURCE_CHANGED_RESTART_REQUIRED')
    # Source-defined bindings are checked by NAME, never by deciding to skip a
    # replacement on the basis of its attacker-controlled __module__ metadata.
    for record in records:
        _builtin_bindings(record)
        _defined_bindings(record)
    for record in records:
        _imports(record)
        _constants(record)
