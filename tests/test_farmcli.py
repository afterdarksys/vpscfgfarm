import unittest
from unittest.mock import patch
from pathlib import Path
from vpscfg.farmcli import route, backend_command, ipxe_script, main, ACTIONS


class FarmCliTest(unittest.TestCase):
    def test_refuse_invalid_backend_operands(self):
        for backend, action, operand in [('esxi', 'off', '-1'), ('esxi', 'on', '1; reboot'),
                                          ('fusion', 'start', '-x.vmx'), ('fusion', 'stop', '/a\nb.vmx'),
                                          ('ipmi', 'raw', None), ('idrac', 'status', 'extra')]:
            with self.subTest(backend=backend, operand=operand):
                with self.assertRaises(ValueError):
                    backend_command(backend, action, operand)

    def test_refuse_ipxe_injection(self):
        for url in ['http://example.com/boot', 'https://u:p@example.com/b',
                    'https://example.com/b\nreboot', 'https://example.com/${x}',
                    'https://example.com/b;reboot']:
            with self.assertRaises(ValueError):
                ipxe_script(url)

    def test_host_selector_cannot_inject_flags(self):
        with self.assertRaises(ValueError):
            route(['host', 'ipmi', '--run', 'off'])

    def test_alias_equivalence(self):
        for domain in ('host', 'vps', 'cloud'):
            for args in [['status'], ['exec', 'lab', 'uptime'], ['--help']]:
                self.assertEqual(route([domain] + args), route(args, domain + 'cfgfarm'))

    def test_all_actions_enter_existing_exec_door(self):
        for backend, actions in ACTIONS.items():
            for action in actions:
                args = ['host', backend, 'lab', action]
                if backend == 'esxi' and action != 'list':
                    args += ['42']
                if backend == 'fusion' and action != 'list':
                    args += ['/VMs/test machine.vmx']
                args += ['--reason', 'lab maintenance', '--run', '--approve=abc']
                door, forwarded = route(args)
                self.assertEqual(door, 'vpsexec')
                self.assertEqual(forwarded[0], 'lab')
                self.assertEqual(forwarded[-4:], args[-4:])

    def test_dispatch_uses_pinned_isolated_interpreter(self):
        with patch('vpscfg.farmcli.os.execv', side_effect=OSError('test')) as execute:
            self.assertEqual(main(['host', 'ipmi', 'lab', 'off'], 'cfgfarm', Path('/tool'), '/python'), 2)
        self.assertEqual(execute.call_args[0][1],
                         ['/python', '-I', '/tool/vpsexec', 'lab', 'ipmitool chassis power off'])

    def test_ipxe_draft(self):
        self.assertEqual(ipxe_script('https://boot.example.com/boot.ipxe'),
                         '#!ipxe\ndhcp || exit\nchain --autofree https://boot.example.com/boot.ipxe || exit\n')
