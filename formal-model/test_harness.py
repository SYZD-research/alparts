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
                         {'o': frozenset(), 'u': frozenset({'r'})}, {'c': Channel('c', None)},
                         channel_overrides={('c', 'r'): (common.VIEW, common.VIEW)})

    @staticmethod
    def output():
        return {'permissions': common.PERM, 'channelScopedMask': common.CHANNEL_SCOPED, 'results': [{
            'masks': {'o': {'c': common.CHANNEL_SCOPED, '__missing_channel__': -1},
                      'u': {'c': 0, '__missing_channel__': -1},
                      '__nonmember__': {'c': -1, '__missing_channel__': -1}},
            'viewers': {'c': ['o']},
        }]}

    def execute(self, output, count=1):
        with patch.object(conformance, 'random_workspace', return_value=self.workspace()), \
                patch.object(conformance, 'run_harness', return_value=output):
            conformance.run(cases=count)

    def assert_incomplete(self):
        self.assertTrue(common.RESULTS)
        self.assertTrue(all(r.verdict == 'MODEL-GAP' for r in common.RESULTS))

    def test_missing_runtime_is_not_pass(self):
        with patch.object(conformance, 'run_harness', side_effect=harness.HarnessError('missing runtime')):
            conformance.run()
        self.assert_incomplete()

    def test_complete_results_and_deny_mutant(self):
        self.execute(self.output())
        self.assertEqual([r.verdict for r in common.RESULTS], ['PASS', 'PASS'])

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

    def test_unclassified_audit_action_is_a_model_gap(self):
        actions = m5v_audit_view.source_actions() | {'channel.something.new'}
        with patch.object(m5v_audit_view, 'source_actions', return_value=actions), \
                patch.object(m5v_audit_view, 'run_harness', side_effect=harness.HarnessError('skip')):
            m5v_audit_view.run()
        verdicts = {r.check_id: r.verdict for r in common.RESULTS}
        self.assertEqual(verdicts['AV-catalog'], 'MODEL-GAP')
        self.assertEqual(verdicts['AV-case'], 'MODEL-GAP')

    def test_incomplete_result_sets_runner_exit_failure(self):
        with patch.object(conformance, 'run_harness', side_effect=harness.HarnessError('missing')):
            self.assertEqual(run.main(['M1c']), 1)


if __name__ == '__main__':
    unittest.main()
