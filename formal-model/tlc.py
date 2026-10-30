"""Check Quint specifications with TLC; missing tools or broken output fail closed.

A spec under quint/ is compiled to TLA+ by `quint compile --target tlaplus`
(which uses Apalache) and explored by the TLC inside the Apalache jar. Every
problem with the tools or their output raises HarnessError, so a run that did
not happen can never read as a PASS.

Tools (see quint/README.md):
  QUINT          the quint executable (default: .tools/node_modules/.bin/quint, then PATH)
  APALACHE_JAR   the Apalache jar (default: ~/.quint/apalache-dist-<version>/apalache/lib/apalache.jar)
  TLC_WORKERS    TLC worker threads (default: 1, which keeps traces shortest)
  TLC_HEAP       JVM heap for TLC (default: 4G)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from harness import HarnessError

ROOT = Path(__file__).resolve().parent
SPECS = ROOT / 'quint'
QUINT_VERSION = '0.33.1'
APALACHE_VERSION = '0.62.4'

_COMPILED: dict[tuple, str] = {}


def quint_path() -> str:
    candidates = [os.environ.get('QUINT'), str(ROOT / '.tools/node_modules/.bin/quint'), shutil.which('quint')]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    raise HarnessError('quint is not installed (run formal-model/quint/setup-tools.sh)')


def apalache_jar() -> Path:
    jar = Path(os.environ.get('APALACHE_JAR')
               or Path.home() / f'.quint/apalache-dist-{APALACHE_VERSION}/apalache/lib/apalache.jar')
    if not jar.exists():
        raise HarnessError(f'the Apalache jar is missing at {jar} (run formal-model/quint/setup-tools.sh)')
    if shutil.which('java') is None:
        raise HarnessError('java (17 or later) is required for Apalache and TLC')
    return jar


def compile_tla(spec: str, main: str, properties: list[str]) -> str:
    """The TLA+ module for `main` in quint/<spec>, keeping the named properties."""
    path = SPECS / spec
    key = (str(path), path.stat().st_mtime_ns, main, tuple(properties))
    if key in _COMPILED:
        return _COMPILED[key]
    command = [quint_path(), 'compile', '--target', 'tlaplus', '--main', main, str(path)]
    if properties:
        command += ['--invariant', ','.join(properties)]
    apalache_jar()
    with tempfile.TemporaryDirectory(prefix='quint-compile-') as cwd:
        try:
            result = subprocess.run(command, capture_output=True, text=True, cwd=cwd, timeout=600)
        except (OSError, subprocess.SubprocessError) as error:
            raise HarnessError(f'quint compile {spec} {main}: {error}') from error
    match = re.search(rf'^-+ MODULE {re.escape(main)} -+$.*?^=+$', result.stdout, re.M | re.S)
    if result.returncode or match is None:
        raise HarnessError(f'quint compile {spec} {main} failed: {(result.stderr or result.stdout).strip()[-800:]}')
    _COMPILED[key] = match.group(0) + '\n'
    return _COMPILED[key]


@dataclass
class Run:
    states: int                    # distinct states TLC found
    complete: bool                 # the whole reachable state space was explored
    violated: str | None = None    # the property (Quint name) TLC found violated
    trace: list[tuple[str, dict]] = field(default_factory=list)  # (action, state) from the initial state on
    dumped: list[dict] = field(default_factory=list)  # with dump=True: every reachable state


def check(spec: str, main: str, invariants: list[str] = (), *, keep: list[str] = (), workers: int | None = None,
          timeout: int = 3600, dump: bool = False) -> Run:
    """Explore `main` with TLC; stop at the first state that violates one of `invariants`.

    `keep` lists every property the callers check on `main`, so that one compilation serves them all.
    With `dump`, every reachable state is returned too (as {variable: value}).
    """
    invariants = list(invariants)
    tla = compile_tla(spec, main, sorted(set(invariants) | set(keep)))
    jar = apalache_jar()
    names = {}
    for prop in invariants:
        found = re.findall(rf'^({re.escape(main)}_\w*_{re.escape(prop)}) ==', tla, re.M)
        if len(found) != 1:
            raise HarnessError(f'{spec} {main}: the property {prop} is not in the compiled module')
        names[found[0]] = prop
    workers = workers or int(os.environ.get('TLC_WORKERS', '1'))
    with tempfile.TemporaryDirectory(prefix='tlc-') as tmp:
        tmp = Path(tmp)
        (tmp / f'{main}.tla').write_text(tla)
        cfg = 'INIT q_init\nNEXT q_step\n' + ''.join(f'INVARIANT {name}\n' for name in names)
        (tmp / f'{main}.cfg').write_text(cfg)
        command = ['java', '-XX:+UseParallelGC', f'-Xmx{os.environ.get("TLC_HEAP", "4G")}', '-Xss64m',
                   f'-Djava.io.tmpdir={tmp}', '-cp', str(jar), 'tlc2.TLC', '-deadlock', '-nowarning',
                   '-workers', str(workers), '-metadir', str(tmp / 'meta'),
                   '-dumpTrace', 'json', str(tmp / 'trace.json'), '-config', f'{main}.cfg', f'{main}.tla']
        if dump:
            command[-3:-3] = ['-dump', str(tmp / 'states')]
        try:
            result = subprocess.run(command, capture_output=True, text=True, cwd=tmp, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as error:
            raise HarnessError(f'TLC {spec} {main}: {error}') from error
        out = result.stdout
        counts = re.findall(r'^(?:\d+ states generated, )?([\d,]+) distinct states found', out, re.M)
        if not counts:
            raise HarnessError(f'TLC {spec} {main}: no state count in the output: {out.strip()[-800:]}')
        states = int(counts[-1].replace(',', ''))
        if result.returncode == 0 and 'Model checking completed. No error has been found.' in out:
            if not dump:
                return Run(states, True)
            dumped = _dumped((tmp / 'states.dump').read_text(), main)
            if len(dumped) != states:
                raise HarnessError(f'TLC {spec} {main}: {len(dumped)} states dumped of {states}')
            return Run(states, True, dumped=dumped)
        violation = re.search(r'^Error: Invariant (\w+) is violated\.', out, re.M)
        if result.returncode == 12 and violation and violation.group(1) in names:
            trace_file = tmp / 'trace.json'
            if not trace_file.exists():
                raise HarnessError(f'TLC {spec} {main}: the counterexample was not written')
            return Run(states, False, names[violation.group(1)], _trace(json.loads(trace_file.read_text()), main))
        raise HarnessError(f'TLC {spec} {main} failed (exit {result.returncode}): {out.strip()[-1200:]}')


def _trace(data: dict, main: str) -> list[tuple[str, dict]]:
    steps = data.get('counterexample', {}).get('action', [])
    if not steps:
        raise HarnessError('TLC wrote an empty counterexample')
    prefix = re.compile(rf'^{re.escape(main)}_[a-z0-9]+_')

    def state(entry):
        return {prefix.sub('', name): value for name, value in entry[1].items()}

    trace = [('init', state(steps[0][0]))]
    for before, action, after in steps:
        trace.append((prefix.sub('', action['name']), state(after)))
    return trace


_TOKEN = re.compile(r'\s*(<<|>>|\|->|"(?:[^"\\]|\\.)*"|-?\d+|TRUE|FALSE|[A-Za-z_]\w*|[\[\]{},])')


def _value(text: str):
    """A TLA+ value as TLC prints it: records, sequences, sets, strings, integers, booleans."""
    tokens, at = [], 0
    while text[at:].strip():
        match = _TOKEN.match(text, at)
        if match is None:
            raise HarnessError(f'TLC printed a value that cannot be read: {text[at:at + 200]}')
        tokens.append(match.group(1))
        at = match.end()
    position = 0

    def parse():
        nonlocal position
        token = tokens[position]
        position += 1
        if token in ('<<', '{', '['):
            close = {'<<': '>>', '{': '}', '[': ']'}[token]
            items, record = [], {}
            while tokens[position] != close:
                if token == '[':
                    name = tokens[position]
                    if tokens[position + 1] != '|->':
                        raise HarnessError(f'TLC printed a function that is not a record: {text[:200]}')
                    position += 2
                    record[name] = parse()
                else:
                    items.append(parse())
                if tokens[position] == ',':
                    position += 1
            position += 1
            return record if token == '[' else items
        if token.startswith('"'):
            return json.loads(token)
        if token in ('TRUE', 'FALSE'):
            return token == 'TRUE'
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        raise HarnessError(f'TLC printed an unexpected token {token!r}')

    value = parse()
    if position != len(tokens):
        raise HarnessError(f'TLC printed a value with trailing text: {text[:200]}')
    return value


def _dumped(text: str, main: str) -> list[dict]:
    prefix = re.compile(rf'^{re.escape(main)}_[a-z0-9]+_')
    states = []
    for block in re.split(r'^State \d+:\s*$', text, flags=re.M)[1:]:
        state = {}
        for part in re.split(r'^/\\ ', block.strip(), flags=re.M):
            if part.strip():
                name, value = part.split(' = ', 1)
                state[prefix.sub('', name.strip())] = _value(value)
        states.append(state)
    return states


def describe(trace: list[tuple[str, dict]], flatten: str | None = None) -> list[str]:
    """One line per step: the action and the fields it changed.

    With `flatten`, the named record variable is unpacked so that its fields are shown.
    """
    lines = []
    previous: dict = {}
    for action, state in trace:
        if flatten:
            state = state[flatten]
        changed = {k: v for k, v in state.items() if previous.get(k, object()) != v}
        if action == 'init':
            changed = {}
        lines.append(f'{action}: ' + ', '.join(f'{k}={json.dumps(v, ensure_ascii=False)}' for k, v in changed.items()))
        previous = state
    return lines
