#!/usr/bin/env python3
"""Run every model and print a verdict table.

  python3 run.py            all models (M3 takes several minutes, ~9 GB peak)
  python3 run.py M1 M4      selected models only

Exit status: 0 when every check has its expected outcome, 1 when a design
finding (FINDING) or a model problem (MODEL-GAP / VACUOUS) is reported.
"""
from __future__ import annotations

import sys
from collections import Counter

import common

MODELS = {
    'M1c': ('conformance', 'model/implementation conformance'),
    'M1': ('m1_authorization', 'authorization algebra'),
    'M2': ('m2_hierarchy', 'role hierarchy'),
    'M3': ('m3_key_epochs', 'channel key epochs'),
    'M4': ('m4_devices', 'devices and sessions'),
    'M5': ('m5_audit', 'audit chain'),
    'M6': ('m6_profiles', 'profiles, avatars and profile warnings'),
}


def main(selected: list[str]) -> int:
    for key in selected or list(MODELS):
        module, _ = MODELS[key]
        __import__(module).run()
        print()
    counts = Counter(r.verdict for r in common.RESULTS)
    print('== SUMMARY ==')
    for verdict in ('PASS', 'LIMIT', 'FINDING', 'MODEL-GAP', 'VACUOUS'):
        if counts[verdict]:
            print(f'  {verdict:9} {counts[verdict]}')
    for result in common.RESULTS:
        if result.verdict in ('FINDING', 'MODEL-GAP', 'VACUOUS'):
            print(f'  {result.verdict}: {result.model} {result.check_id} {result.title}')
    return 1 if counts['FINDING'] or counts['MODEL-GAP'] or counts['VACUOUS'] else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
