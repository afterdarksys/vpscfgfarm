"""Regression tests for production safety; all transports are local or injected."""
import concurrent.futures
import contextlib
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from vpscfg import contracts, executor, journal, lock, syncplan, verify, vpsexec
from vpscfg.control import Guard
from vpscfg.gates import DENY_ALWAYS_FLOOR, Refused


def append_process(directory, start, index):
    journal.JOURNAL_DIR = Path(directory)
    with mock.patch('vpscfg.telemetry.push_event'):
        start.wait(10)
        for n in range(10):
            journal.append('parallel', {'event': '%s:%s' % (index, n)})


class CommandSafetyTest(unittest.TestCase):
    def test_writing_forms_and_custom_executables_are_not_reads(self):
        for command in ('sort -o output input', 'find /tmp -fprint0 output',
                        'git branch created', 'wget https://example.invalid/file',
                        './cat', '/tmp/cat', 'uniq input output', 'date -s tomorrow',
                        'hostname changed', 'curl --config settings',
                        'curl --data-binary @payload http://host', 'git diff --ext-diff'):
            with self.subTest(command=command):
                self.assertNotEqual(vpsexec.classify(command, DENY_ALWAYS_FLOOR)[0], 'read')

    def test_quoted_find_glob_is_literal_and_remains_a_read(self):
        self.assertEqual(vpsexec.classify("find /tmp -name '*.log'", DENY_ALWAYS_FLOOR)[0], 'read')

    def test_dynamic_arguments_cannot_hide_options_or_forbidden_verbs(self):
        for command in ('sort {-o,output,input}', 'sort *', 'find *', 'docker volume p*'):
            with self.subTest(command=command), self.assertRaises(Refused):
                vpsexec.classify(command, DENY_ALWAYS_FLOOR)

    def test_frozen_dispatch_never_executes_a_write_disguised_as_read(self):
        policy = {'allowed_verbs': ['exec'], 'hosts': {'fixture': {'posture': 'frozen'}},
                  'deny_always': DENY_ALWAYS_FLOOR}
        transport = mock.Mock()
        with mock.patch('vpscfg.sshconfig.load', return_value={'fixture': {}}), \
                mock.patch('vpscfg.sshconfig.machines', return_value={}):
            for command in ('sort -o output input', './cat', 'git branch created', 'wget https://example.invalid/file'):
                with self.subTest(command=command), self.assertRaises(Refused):
                    vpsexec.dispatch(['fixture', command], guard=Guard(policy, True),
                                     policy={'groups': {}, 'runbooks': []}, ssh=transport)
        transport.assert_not_called()

    def test_redirection_prefix_is_not_a_discard(self):
        self.assertNotEqual(vpsexec.classify('echo hi >/dev/null-created', DENY_ALWAYS_FLOOR)[0], 'read')

    def test_newline_cannot_hide_a_mutating_segment(self):
        self.assertEqual(vpsexec.classify('echo hi\ntouch marker', DENY_ALWAYS_FLOOR)[0], 'mutating')

    def test_shell_equivalent_floor_is_refused(self):
        for command in ('docker volume "prune" -f', 'docker volu"me" pr\\une -f',
                        'docker volume --force prune', 'docker compose down --remove-orphans -v',
                        'rm -fr /tmp/x', 'rm --recursive --force /tmp/x',
                        'kubectl delete --wait=false namespace production'):
            with self.subTest(command=command), self.assertRaises(Refused):
                vpsexec.classify(command, DENY_ALWAYS_FLOOR)

    def test_literal_whitespace_is_preserved(self):
        command = "echo 'two  spaces'"
        self.assertEqual(vpsexec.build_remote_command(command, None), command)
        self.assertNotEqual(vpsexec.normalize(command), vpsexec.normalize("echo 'two spaces'"))


class DurableJournalTest(unittest.TestCase):
    def test_concurrent_processes_preserve_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = multiprocessing.get_context('spawn')
            start = ctx.Event()
            workers = [ctx.Process(target=append_process, args=(tmp, start, i)) for i in range(4)]
            for worker in workers:
                worker.start()
            start.set()
            for worker in workers:
                worker.join(20)
                if worker.is_alive():
                    worker.terminate()
                    worker.join()
                    self.fail('journal worker hung')
                self.assertEqual(worker.exitcode, 0)
            result = journal.chain_verify('parallel', tmp)
            self.assertEqual(result['entries'], 40)
            self.assertTrue(result['ok'], result)

    def test_unreadable_is_not_an_empty_healthy_journal(self):
        with mock.patch.object(journal, '_read_snapshot', side_effect=PermissionError('denied')):
            self.assertFalse(journal.chain_verify('blocked')['ok'])

    def test_sync_failure_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(journal, 'JOURNAL_DIR', Path(tmp)), \
                mock.patch('vpscfg.telemetry.push_event'), mock.patch('os.fsync', side_effect=OSError('disk')):
            with self.assertRaises(OSError):
                journal.append('test', {'event': 'must persist'})

    def test_incomplete_tail_refuses_append(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(journal, 'JOURNAL_DIR', Path(tmp)):
            path = Path(tmp) / 'test.jsonl'
            path.write_text('{"event":')
            with self.assertRaises(OSError):
                journal.append('test', {'event': 'must refuse'})
            self.assertEqual(path.read_text(), '{"event":')


class HealthDeadlineTest(unittest.TestCase):
    def test_invalid_parameters_refuse_before_deployment(self):
        for parameters in ({'timeout': float('nan')}, {'timeout': -1}, {'expect': 'success'}):
            with self.subTest(parameters=parameters), self.assertRaises(Refused):
                verify.validate_checks({'verify': [{'http': {'url': 'https://example.invalid', **parameters}}]})
    def test_startup_is_polled_until_healthy(self):
        now = [0.0]
        replies = iter([(0, 'running starting'), (0, 'running healthy')])
        def sleep(seconds):
            now[0] += seconds
        result = verify._check_container({'name': 'svc', 'state': 'healthy', 'within': '90s'},
                                         'fixture', runner=lambda h, n: next(replies),
                                         clock=lambda: now[0], sleep=sleep)
        self.assertTrue(result['ok'])
        self.assertEqual(now[0], 2)

    def test_polling_stops_at_deadline(self):
        now = [0.0]
        def sleep(seconds):
            now[0] += seconds
        runner = mock.Mock(return_value=(0, 'running starting'))
        result = verify._check_container({'name': 'svc', 'state': 'healthy', 'within': '3s'},
                                         'fixture', runner=runner, clock=lambda: now[0], sleep=sleep)
        self.assertFalse(result['ok'])
        self.assertEqual(now[0], 3)
        self.assertLessEqual(runner.call_count, 3)

    def test_invalid_deadlines_refuse(self):
        for value in ('forever', '-1s', '0s', '999999m', True):
            with self.subTest(value=value), self.assertRaises(Refused):
                verify.deadline_seconds(value)

    def test_empty_verification_is_never_success(self):
        self.assertFalse(verify.run_checks({'verify': []}, 'fixture')[0])
        with self.assertRaises(Refused):
            contracts._validate({'service': 's', 'host': 'fixture', 'monitor_only': True, 'verify': []}, 'fixture')


class LockOwnershipTest(unittest.TestCase):
    def test_stale_owner_cannot_release_newer_lock(self):
        def local(host, command):
            result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, timeout=5)
            return result.returncode, result.stdout, result.stderr
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(lock, 'LOCK_DIR', tmp + '/lock'):
            token = lock.acquire('fixture', 'operator', 'fixture', runner=local)
            self.assertFalse(lock.release('fixture', token='wrong-owner', runner=local))
            self.assertTrue(Path(lock.LOCK_DIR).is_dir())
            self.assertTrue(lock.release('fixture', token=token, runner=local))
            newer = lock.acquire('fixture', 'other', 'fixture', runner=local)
            self.assertFalse(lock.release('fixture', token=token, runner=local))
            self.assertTrue(lock.release('fixture', token=newer, runner=local))

    def test_vpsexec_timeout_keeps_mutation_lock(self):
        calls = []
        def remote(host, command, **kwargs):
            calls.append(command)
            if command == 'echo mutation':
                raise subprocess.TimeoutExpired(command, 1)
            return 0, '', ''
        plan = vpsexec.build_plan(['fixture'], 'echo mutation', {}, 'mutating', None)
        with mock.patch('vpscfg.journal.append'):
            result = vpsexec._run_one_host('fixture', plan, Guard({'deny_always': DENY_ALWAYS_FLOOR}, True),
                                          'fixture', remote, 1, False)
        self.assertNotEqual(result['rc'], 0)
        self.assertIn('lock retained', result['error'])
        self.assertFalse(any('rmdir' in command for command in calls))


class DeploymentSafetyTest(unittest.TestCase):
    def setUp(self):
        self.source = tempfile.TemporaryDirectory()
        self.addCleanup(self.source.cleanup)
        (Path(self.source.name) / 'x').write_text('fixture')
        self.guard = Guard({'allowed_verbs': ['deploy'], 'mode': 'test', 'mutation_enabled': True,
                            'hosts': {'fixture': {'posture': 'test'}},
                            'scopes': {'unlocked': ['service:fixture/svc']},
                            'deny_always': DENY_ALWAYS_FLOOR}, True)
        self.contract = {'service': 'svc', 'host': 'fixture', 'repo': self.source.name,
                         'deploy_dir': '/opt/svc', 'sync': {'include': ['x'], 'never': ['.env']},
                         'pre': [{'backup': 'tar czf /root/{service}-pre-{ts}.tar.gz {deploy_dir}'}],
                         'build': 'echo build', 'verify': [{'container': {'name': 'svc'}}]}
        self.commands = []

    def ssh(self, host, command):
        self.commands.append(command)
        return 0, '', ''

    def apply(self, **kwargs):
        with mock.patch('vpscfg.executor.journal.append'), contextlib.redirect_stdout(io.StringIO()):
            return executor.apply(self.guard, self.contract, 'deploy', 'fixture',
                                  'service:fixture/svc', [], reason='fixture', **kwargs)

    def test_partial_sync_attempts_restore_and_retains_recovery_lock(self):
        with self.assertRaises(Refused):
            self.apply(ssh=self.ssh, run_local=lambda argv: (23, '', 'partial transfer'),
                       checks=lambda c, h: (True, []))
        self.assertTrue(any(c.startswith('tar xzf') for c in self.commands))
        self.assertFalse(any('rmdir' in c for c in self.commands))

    def test_unknown_remote_completion_retains_lock(self):
        def transport(host, command):
            self.commands.append(command)
            if command.startswith('cd '):
                raise subprocess.TimeoutExpired(command, 120)
            return 0, '', ''
        with self.assertRaises(subprocess.TimeoutExpired):
            self.apply(ssh=transport, run_local=lambda argv: (0, '', ''))
        self.assertFalse(any('rmdir' in c for c in self.commands))
        self.assertFalse(any(c.startswith('tar xzf') for c in self.commands))

    def test_empty_verification_refuses_before_transport(self):
        self.contract['verify'] = []
        with self.assertRaises(Refused):
            self.apply(ssh=self.ssh)
        self.assertEqual(self.commands, [])

    def test_missing_source_refuses_before_transport(self):
        self.contract['sync']['include'] = ['missing']
        with self.assertRaisesRegex(Refused, 'missing'):
            self.apply(ssh=self.ssh)
        self.assertEqual(self.commands, [])

    def test_ssh_disconnect_is_not_a_completed_remote_failure(self):
        result = subprocess.CompletedProcess(['ssh'], 255, '', 'connection lost')
        with mock.patch('subprocess.run', return_value=result):
            for transport in (executor._default_ssh, vpsexec._default_ssh):
                with self.assertRaisesRegex(OSError, 'unknown'):
                    transport('fixture', 'true')

    def test_real_local_sync_and_archive_recovery(self):
        # Model one host with actual shell, tar and rsync, mapping only its
        # /root backup directory into the fixture. No SSH or fleet access.
        root = Path(self.source.name).resolve()
        deployed, archives = root / 'deployed', root / 'archives'
        deployed.mkdir()
        archives.mkdir()
        (deployed / 'x').write_text('previous release')
        self.contract.update(deploy_dir=str(deployed), build='true')
        def remote(host, command):
            self.commands.append(command)
            if 'command -v docker' in command:
                return 0, 'NO_DOCKER\n', ''
            command = command.replace('/root/', str(archives) + '/')
            result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, timeout=10)
            return result.returncode, result.stdout, result.stderr
        def local(argv):
            actual = list(argv)
            actual[-1] = actual[-1].split(':', 1)[1]
            result = subprocess.run(actual, capture_output=True, text=True, timeout=10)
            # Transfer really happens before the injected partial failure.
            if '--dry-run' not in actual:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((deployed / 'x').read_text(), 'fixture')
                return 23, result.stdout, 'injected partial transfer'
            return result.returncode, result.stdout, result.stderr
        with mock.patch.object(lock, 'LOCK_DIR', str(root / 'host-lock')):
            with self.assertRaisesRegex(Refused, 'sync'):
                self.apply(ssh=remote, run_local=local, checks=lambda c, h: (True, []))
            self.assertEqual((deployed / 'x').read_text(), 'previous release')
            self.assertTrue((root / 'host-lock' / 'owner').exists())


class SyncLayoutTest(unittest.TestCase):
    def test_nested_file_keeps_parent_and_excludes_protected_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst = root / 'source', root / 'destination'
            (src / 'routes').mkdir(parents=True)
            dst.mkdir()
            (src / 'routes' / 'handler.py').write_text('code')
            (src / 'routes' / '.env').write_text('must not transfer')
            (src / 'unselected').write_text('must not transfer')
            (dst / 'routes').mkdir()
            (dst / 'routes' / '.env').write_text('host-only')
            contract = {'repo': str(src), 'host': 'fixture', 'deploy_dir': '/opt/svc',
                        'sync': {'include': ['routes/handler.py', 'routes/.env'],
                                 'never': ['routes/.env']}}
            for argv in syncplan.rsync_argvs(contract, dry_run=False):
                argv[-1] = str(dst) + '/'
                subprocess.run(argv, capture_output=True, check=True)
            self.assertEqual((dst / 'routes' / 'handler.py').read_text(), 'code')
            self.assertFalse((dst / 'handler.py').exists())
            self.assertEqual((dst / 'routes' / '.env').read_text(), 'host-only')
            self.assertFalse((dst / 'unselected').exists())


class ReadOnlyWrapperTest(unittest.TestCase):
    """Against the example estate's governor (web1 frozen, edge1 test) with the
    diagnostic verbs allowed; tests/estate/ reruns these against the estate's
    own governor."""

    FROZEN = 'web1'
    TEST = 'edge1'

    def _policy(self, root):
        policy = json.loads((root / 'contrib' / 'example-estate' / 'vpscfg-control.json').read_text())
        policy['allowed_verbs'] += ['ports', 'backup-verify']
        return policy

    def test_diagnostics_pass_frozen_host_outer_gate(self):
        root = Path(__file__).resolve().parent.parent
        spec = importlib.util.spec_from_file_location('control_review', root / 'vpscfg-control.py')
        wrapper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wrapper)
        policy = self._policy(root)
        for verb in ('ports', 'logs', 'backup-verify'):
            with self.subTest(verb=verb), mock.patch.object(wrapper, 'journal'):
                self.assertTrue(wrapper.judge(policy, [self.FROZEN, verb, 'fixture'])['read_only'])

    def test_both_outer_doors_refuse_shell_equivalent_floor(self):
        import importlib.machinery
        root = Path(__file__).resolve().parent.parent
        policy = self._policy(root)
        for name in ('vpsexec', 'vpscfg-control.py'):
            loader = importlib.machinery.SourceFileLoader('outer_fixture', str(root / name))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            wrapper = importlib.util.module_from_spec(spec)
            loader.exec_module(wrapper)
            for command in ('docker volume "prune" -f', 'rm -fr /tmp/x', 'docker volu\\\nme prune'):
                argv = [self.TEST, command] if name == 'vpsexec' else [self.TEST, 'show', command]
                with self.subTest(door=name, command=command), mock.patch.object(wrapper, 'journal'), \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    wrapper.judge(policy, argv)


if __name__ == '__main__':
    unittest.main()
