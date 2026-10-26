"""Regression tests for false PASS results in the verification machinery."""
import contextlib
import copy
import io
import unittest
from unittest.mock import patch

from z3 import unknown

import common
import conformance
import harness
import m1_authorization
import m5v_audit_view
import m6_profiles
import m8_voice
import m9_messages
import run
from authz import Channel, Role, Workspace


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        common.RESULTS.clear()
        self.capture = contextlib.redirect_stdout(io.StringIO())
        self.capture.__enter__()

    def tearDown(self):
        self.capture.__exit__(None, None, None)
        common.RESULTS.clear()

    @staticmethod
    def workspace():
        return Workspace('o', {'r': Role('r', common.VIEW, 10)},
                         {'o': frozenset(), 'u': frozenset({'r'})},
                         {'c': Channel('c', None), 'v': Channel('v', None, voice=True)},
                         channel_overrides={('c', 'r'): (common.VIEW, common.VIEW)})

    @staticmethod
    def output():
        return {'permissions': common.PERM, 'channelScopedMask': common.CHANNEL_SCOPED, 'results': [{
            'masks': {'o': {'c': common.CHANNEL_SCOPED, 'v': common.CHANNEL_SCOPED, '__missing_channel__': -1},
                      'u': {'c': 0, 'v': common.VIEW, '__missing_channel__': -1},
                      '__nonmember__': {'c': -1, 'v': -1, '__missing_channel__': -1}},
            'viewers': {'c': ['o'], 'v': ['o', 'u']},
            'keyRecipients': {'c': ['o'], 'v': ['o']},
        }]}

    def execute(self, output, count=1):
        with patch.object(conformance, 'random_workspace', return_value=self.workspace()), \
                patch.object(conformance, 'run_harness', return_value=output), \
                patch.object(conformance, 'run_effects', lambda: None):
            conformance.run(cases=count)

    @staticmethod
    def call_change():
        before = Workspace('o', {'r': Role('r', common.VIEW | common.CONNECT, 10)},
                           {'o': frozenset(), 'u': frozenset({'r'})}, {'v': Channel('v', None, voice=True)})
        after = Workspace('o', {'r': Role('r', common.VIEW, 10)},
                          {'o': frozenset(), 'u': frozenset({'r'})}, {'v': Channel('v', None, voice=True)})
        return before, after

    def execute_effects(self, effects):
        before, after = self.call_change()
        output = {'results': [{'effects': effects}]}
        with patch.object(conformance, 'random_workspace', return_value=before), \
                patch.object(conformance, 'mutate', return_value=after), \
                patch.object(conformance, 'run_harness', return_value=output):
            conformance.run_effects(cases=1)

    def test_room_effects_with_the_lost_call_pass(self):
        self.execute_effects([{'channelId': 'v', 'lostUserIds': [], 'gainedUserIds': [], 'lostCallUserIds': ['u']}])
        self.assertEqual([r.verdict for r in common.RESULTS], ['PASS', 'PASS'])

    def test_room_effects_without_the_lost_call_are_a_finding(self):
        self.execute_effects([])
        self.assertEqual(common.RESULTS[-1].verdict, 'FINDING')

    def test_missing_room_effects_are_incomplete(self):
        for output in ({'results': []}, {'results': [{}]}, None):
            with self.subTest(output=output):
                common.RESULTS.clear()
                before, after = self.call_change()
                with patch.object(conformance, 'random_workspace', return_value=before), \
                        patch.object(conformance, 'mutate', return_value=after), \
                        patch.object(conformance, 'run_harness', return_value=output):
                    conformance.run_effects(cases=1)
                self.assert_incomplete()

    def assert_incomplete(self):
        self.assertTrue(common.RESULTS)
        self.assertTrue(all(r.verdict == 'MODEL-GAP' for r in common.RESULTS))

    def test_missing_runtime_is_not_pass(self):
        with patch.object(conformance, 'run_harness', side_effect=harness.HarnessError('missing runtime')):
            conformance.run()
            conformance.run_effects()
        self.assert_incomplete()

    def test_complete_results_and_deny_mutant(self):
        self.execute(self.output())
        self.assertEqual([r.verdict for r in common.RESULTS], ['PASS', 'PASS', 'PASS'])

    def test_truncated_results_are_not_zipped_away(self):
        self.execute(self.output(), count=400)
        self.assert_incomplete()

    def test_extra_results_are_not_ignored(self):
        output = self.output()
        output['results'] *= 2
        self.execute(output)
        self.assert_incomplete()

    def test_missing_user_or_channel_is_not_a_zero_comparison_pass(self):
        for key in ('o', 'u', '__nonmember__'):
            with self.subTest(key=key):
                common.RESULTS.clear()
                output = self.output()
                del output['results'][0]['masks'][key]
                self.execute(output)
                self.assert_incomplete()

    def test_permissions_are_checked_against_implementation(self):
        output = copy.deepcopy(self.output())
        output['permissions']['VIEW_CHANNELS'] = 1 << 20
        self.execute(output)
        self.assert_incomplete()

    def test_malformed_shapes_fail_closed(self):
        for output in (None, [], {'results': []}, {**self.output(), 'results': []}):
            with self.subTest(output=output):
                common.RESULTS.clear()
                self.execute(output)
                self.assert_incomplete()

    def test_missing_key_recipients_are_incomplete(self):
        output = self.output()
        del output['results'][0]['keyRecipients']
        self.execute(output)
        self.assert_incomplete()

    def test_key_recipient_mismatch_is_a_finding(self):
        output = self.output()
        output['results'][0]['keyRecipients']['c'] = []
        self.execute(output)
        self.assertEqual(common.RESULTS[-1].verdict, 'FINDING')

    def test_real_mask_mismatch_is_a_finding(self):
        output = self.output()
        output['results'][0]['masks']['u']['c'] = common.VIEW
        self.execute(output)
        self.assertEqual(common.RESULTS[-1].verdict, 'FINDING')

    def test_empty_avatar_corpus_is_not_three_passes(self):
        with patch.object(m6_profiles, 'run_harness', return_value=[]):
            m6_profiles.e_run()
        self.assert_incomplete()

    def test_duplicate_avatar_cases_are_incomplete(self):
        with patch.object(m6_profiles, 'run_harness', return_value=[{'name': 'valid-rgba'}] * 22):
            m6_profiles.e_run()
        self.assert_incomplete()

    def test_solver_unknown_is_not_unsat(self):
        with patch.object(m1_authorization, 'Solver') as solver:
            solver.return_value.check.return_value = unknown
            solver.return_value.reason_unknown.return_value = 'injected interruption'
            m1_authorization.prove('test', 'unknown is not a proof', 'HOLDS', True)
        self.assert_incomplete()

    def test_missing_node_is_an_explicit_harness_error(self):
        with patch.object(harness.shutil, 'which', return_value=None):
            with self.assertRaises(harness.HarnessError):
                harness.run_harness('authz-harness.mts')

    def test_empty_requested_sample_is_rejected(self):
        with self.assertRaises(ValueError):
            conformance.run(cases=0)

    def test_projector_harness_errors_and_gaps_are_not_passes(self):
        complete = {'histories': 5000, 'results': {p: {'violations': 0, 'example': None} for p in m9_messages.PROPERTIES}}
        missing = copy.deepcopy(complete)
        del missing['results']['MI-reply']
        for output in (harness.HarnessError('missing runtime'), missing, {**complete, 'histories': 3}, None):
            with self.subTest(output=str(output)[:40]):
                common.RESULTS.clear()
                effect = {'side_effect': output} if isinstance(output, Exception) else {'return_value': output}
                with patch.object(m9_messages, 'run_harness', **effect):
                    m9_messages.run()
                self.assert_incomplete()

    def test_unfinished_sfu_exploration_is_not_a_pass(self):
        for output in (harness.HarnessError('timed out'), {'complete': False, 'states': 100, 'violations': []},
                       {'complete': True, 'states': 1, 'violations': []}):
            with self.subTest(output=str(output)[:40]):
                common.RESULTS.clear()
                effect = {'side_effect': output} if isinstance(output, Exception) else {'return_value': output}
                with patch.object(m8_voice, 'run_harness', **effect):
                    m8_voice.run_m8b()
                self.assert_incomplete()

    def test_unfinished_key_exploration_is_not_a_pass(self):
        for output in (harness.HarnessError('timed out'), {'complete': False, 'states': 100, 'violations': []},
                       {'complete': True, 'states': 1, 'violations': []}):
            with self.subTest(output=str(output)[:40]):
                common.RESULTS.clear()
                effect = {'side_effect': output} if isinstance(output, Exception) else {'return_value': output}
                with patch.object(m8_voice, 'run_harness', **effect):
                    m8_voice.run_m8k()
                self.assert_incomplete()

    def test_key_harness_keeps_a_violation_apart_from_an_equal_state(self):
        # Sending the key to C after learning that C left reaches the same clients as sending it just before;
        # the search must still report the first (it once merged the two by their client state).
        try:
            out = harness.run_harness('voice-keys-harness.mts', {'scenario': 'join-leave', 'mutation': 'pre-fix-rotation',
                                                                 'stop': ['KL']}, timeout=120)
        except harness.HarnessError as error:
            self.skipTest(str(error))
        self.assertTrue(out['complete'])
        self.assertEqual([v['property'] for v in out['violations']], ['KL'])
        self.assertEqual(out['violations'][0]['trace'][-2:], ['tell a that c left', 'resolve sign(a#3)'])

    def test_key_harness_reports_a_message_stuck_behind_a_rotation(self):
        # With the receive queue shared with rotations (0eda053), a key message waits for the receiver's own
        # rotation, which waits for the server; KT must see it although the search otherwise looks complete.
        try:
            out = harness.run_harness('voice-keys-harness.mts', {'scenario': 'join', 'mutation': 'shared-receive-queue',
                                                                 'stop': ['KT']}, timeout=120)
        except harness.HarnessError as error:
            self.skipTest(str(error))
        self.assertTrue(out['complete'])
        self.assertEqual([v['property'] for v in out['violations']], ['KT'])

    def test_hierarchy_guard_gaps_are_not_passes(self):
        import hierarchy_conformance
        for output in (None, {'results': []}, {'results': [{}]}):
            with self.subTest(output=output):
                common.RESULTS.clear()
                with patch.object(hierarchy_conformance, 'run_harness', return_value=output):
                    hierarchy_conformance.guard_checks(1, steps=2)
                self.assert_incomplete()

    def test_unclassified_audit_action_is_a_model_gap(self):
        actions = m5v_audit_view.source_actions() | {'channel.something.new'}
        with patch.object(m5v_audit_view, 'source_actions', return_value=actions), \
                patch.object(m5v_audit_view, 'run_harness', side_effect=harness.HarnessError('skip')):
            m5v_audit_view.run()
        verdicts = {r.check_id: r.verdict for r in common.RESULTS}
        self.assertEqual(verdicts['AV-catalog'], 'MODEL-GAP')
        self.assertEqual(verdicts['AV-case'], 'MODEL-GAP')

    def test_stall_rule_counts_each_loss_of_access_from_its_own_time(self):
        # R-057: Z loses view after Y's loss has been 15 minutes old, then Y gains view again. One time for the
        # whole group lets the manager replace the group at once; each member's own time does not.
        import m3s_stall
        steps = ['Y1: publish package', 'authz: Z gains view', 'Z1: publish package',
                 'clock: the 24-hour genesis wait ends', 'Y1: genesis with {Y1,Z1}', 'authz: Y loses view',
                 'clock: 15 minutes pass', 'X1: publish package', 'authz: Z loses view', 'authz: Y gains view']
        fresh_start = 'X1: fresh start: manager, changes stalled with {X1}'
        for loss_time, permitted in (('group', True), ('member', False)):
            with self.subTest(loss_time=loss_time):
                rules = m3s_stall.StallRules(loss_time=loss_time)
                v = m3s_stall.base_variant(rules)
                s = m3s_stall.s_initial(v)
                for step in steps:
                    s = next(nxt for action, nxt in m3s_stall.s_transitions(s, rules, v)
                             if m3s_stall.s_label(s, v, action) == step)
                labels = [m3s_stall.s_label(s, v, action) for action, _ in m3s_stall.s_transitions(s, rules, v)]
                self.assertEqual(fresh_start in labels, permitted)
                self.assertFalse(m3s_stall.truly_stalled(s, v))

    def test_incomplete_result_sets_runner_exit_failure(self):
        with patch.object(conformance, 'run_harness', side_effect=harness.HarnessError('missing')):
            self.assertEqual(run.main(['M1c']), 1)


if __name__ == '__main__':
    unittest.main()
