"""M4T: device approval, the recovery code and the passkey against a malicious server (Tamarin).

M4 and M4s assume that signatures, the code comparison and the recovery
encryption work. tamarin/device_approval.spthy checks those steps
symbolically against an adversary who is the network and the server: which
device keys the user's devices accept as approved (DA), that the approval the
user gives after comparing codes names the device they saw (DA-compared), and
that the history archive stays closed to the server (HS). The variants put
back the documented limits (a user who approves without comparing, first
contact) and remove one protection each (CONTROL).

Requires tamarin-prover (1.10 or later) and maude on PATH, or TAMARIN set to
the executable. Missing tools, a wellformedness warning or an incomplete
analysis are MODEL-GAP, never a PASS.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from common import record

ROOT = Path(__file__).resolve().parent
THEORY = ROOT / 'tamarin' / 'device_approval.spthy'


class TamarinError(Exception):
    pass


def prove(lemmas: list[str], flags: tuple[str, ...] = (), timeout: int = 1800) -> dict[str, tuple[str, list[str]]]:
    """{lemma: (verdict, trace)} with verdict 'verified' or 'falsified'; anything else raises."""
    tamarin = os.environ.get('TAMARIN') or shutil.which('tamarin-prover')
    if tamarin is None or shutil.which('maude') is None:
        raise TamarinError('tamarin-prover and maude are required (see tamarin/README.md)')
    command = [tamarin, *(f'--prove={lemma}' for lemma in lemmas), *(f'-D={flag}' for flag in flags), str(THEORY)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        raise TamarinError(f'tamarin-prover {" ".join(flags)}: {error}') from error
    out = result.stdout + result.stderr
    if result.returncode:
        raise TamarinError(f'tamarin-prover {" ".join(flags)} failed: {out.strip()[-800:]}')
    if re.search(r'wellformedness check failed', out):
        raise TamarinError(f'tamarin-prover {" ".join(flags)}: the theory is not wellformed: {out.strip()[-800:]}')
    summary = out.rsplit('summary of summaries:', 1)[-1]
    verdicts = {}
    for lemma in lemmas:
        match = re.search(rf'^\s*{re.escape(lemma)} \((?:all|exists)-traces?\): (verified|falsified|analysis incomplete)',
                          summary, re.M)
        if match is None or match.group(1) == 'analysis incomplete':
            raise TamarinError(f'{lemma} {" ".join(flags)}: no complete result')
        verdicts[lemma] = (match.group(1), _trace(out, lemma) if match.group(1) == 'falsified' else [])
    return verdicts


def _trace(out: str, lemma: str) -> list[str]:
    """The rule instances of the attack, in the order Tamarin printed them."""
    part = out.split(f'lemma {lemma}', 1)[-1].split('\nlemma ', 1)[0]
    return re.findall(r'^\s*(?:case|by) (.+)$', part, re.M)[:12]


RUNS = {
    # (flags, lemmas)
    'default': ((), ['DA', 'DA_compared', 'HS', 'passkey_alone_approves',
                     'exec_approval', 'exec_restore_code', 'exec_restore_passkey']),
    'tricked': (('TRICKED',), ['DA']),
    'tofu': (('TOFU',), ['DA']),
    'no-identity': (('CTL_NO_IDENTITY',), ['DA']),
    'untagged-proof': (('CTL_UNTAGGED_PROOF',), ['DA']),
    'raw-token': (('CTL_RAW_TOKEN',), ['DA', 'HS']),
}


def run() -> None:
    print('== M4T: device approval, recovery and passkeys against a malicious server (Tamarin) ==')
    results = {}
    for name, (flags, lemmas) in RUNS.items():
        try:
            results[name] = prove(lemmas, flags)
        except TamarinError as error:
            record('M4T', f'tools-{name}', f'Tamarin proved the {name} variant', 'HOLDS', False, str(error),
                   incomplete=True)
    if not results:
        return

    def check(check_id, title, expect, name, lemma, detail='', exists=False):
        if name not in results:
            return
        verdict, trace = results[name][lemma]
        # all-traces: falsified is a violation; exists-trace: verified means the trace exists.
        violated = verdict == ('verified' if exists else 'falsified')
        record('M4T', check_id, title, expect, violated, detail, witness=trace)

    for lemma, title in (('exec_approval', 'approval after comparing codes'),
                         ('exec_restore_code', 'restore with the recovery code'),
                         ('exec_restore_passkey', 'restore with the passkey')):
        if 'default' in results and results['default'][lemma][0] != 'verified':
            record('M4T', f'exec-{lemma}', f'{title} is reachable without compromise', 'HOLDS', False,
                   'the honest path is unreachable: the model is too strong', incomplete=True)
    check('DA', 'a device key the user\'s devices accept as approved belongs to one of the user\'s devices unless a '
                'device key, the recovery code or the passkey leaked (malicious server)', 'HOLDS', 'default', 'DA')
    check('DA-compared', 'an approval given after comparing the confirmation codes names the device whose code the '
                         'user saw, whatever device the server presents', 'HOLDS', 'default', 'DA_compared')
    check('HS', 'the server, holding every archive record and every retrieval token sent to it, cannot read history '
                'keys without the code or the passkey', 'HOLDS', 'default', 'HS')
    check('DA-passkey', 'whoever can use the passkey the recovery plan was wrapped with (the authenticator, or the '
                        'account that syncs it) can approve a new device without the code', 'LIMIT', 'default',
          'passkey_alone_approves', 'restoreHistory unwraps the code with the passkey; that is the designed shortcut',
          exists=True)
    check('DA-tricked', 'a user who approves without comparing the codes approves the server\'s device (M4 D4)',
          'LIMIT', 'tricked', 'DA')
    check('DA-tofu', 'a device that meets an account for the first time accepts whatever first device the server '
                     'shows (TOFU)', 'LIMIT', 'tofu', 'DA')
    check('DA-identity-ctl', 'if the decision named only the device ID, the server could register its own key under '
                             'that ID in another view and reuse the approval', 'CONTROL', 'no-identity', 'DA')
    check('DA-proof-ctl', 'if the session proof signed the bare challenge, the server could have an approved device '
                          'sign an approval of its own device as a login challenge', 'CONTROL', 'untagged-proof', 'DA')
    check('HS-token-ctl', 'if the retrieval token were the code itself, the server would learn the code at the first '
                          'restore, read the history and approve its own device', 'CONTROL', 'raw-token', 'HS')


if __name__ == '__main__':
    run()
