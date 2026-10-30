#!/usr/bin/env python3
"""Run every model and print a verdict table.

  python3 run.py            all models (M3 about 7 minutes and ~0.9 GB, M8 about an hour on 4 cores,
                            M3Q about an hour, M4T about 7 minutes)
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
    'M2c': ('hierarchy_conformance', 'hierarchy guard implementation conformance'),
    'M3': ('m3_key_epochs', 'channel key epochs'),
    'M3Q': ('m3_quint', 'M3 in Quint, checked by TLC against the Python explorer'),
    'M3s': ('m3s_stall', 'the fresh-start stall rule over time'),
    'M3sQ': ('m3s_quint', 'M3s in Quint, checked by TLC against the Python explorer'),
    'M3r': ('m3r_own_commit', 'own group commits with lost answers'),
    'M3rQ': ('m3r_quint', 'M3r in Quint, checked by TLC against the Python explorer'),
    'M4': ('m4_devices', 'devices and sessions'),
    'M4s': ('m4s_sessions', 'credentials, sessions and sockets under concurrent requests'),
    'M4T': ('m4_tamarin', 'device approval, recovery and passkeys against a malicious server (Tamarin)'),
    'M5': ('m5_audit', 'audit chain'),
    'M5v': ('m5v_audit_view', 'the workspace audit view'),
    'M6': ('m6_profiles', 'profiles, avatars and profile warnings'),
    'M7': ('m7_forums', 'forum posts, replies and moderation'),
    'M8': ('m8_voice', 'voice calls: room grants, call registries and the SFU'),
    'M9': ('m9_messages', 'message events from a malicious server'),
    'M10': ('m10_ordering', 'withheld and reordered message events'),
    'M10Q': ('m10_quint', 'M10 in Quint, checked by TLC against the real client code'),
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
