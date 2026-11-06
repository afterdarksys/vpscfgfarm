"""Unified CLI and vendor command plans.

Threats: fixed actions and validated operands prevent shell/option injection.
Remote execution always enters vpsexec, retaining its governor, approval,
posture, deny floor and journal checks. Vendor tools and remote configuration
must be trusted; SSH access outside these doors is not controlled here.
"""
import os
import re
import shlex
from urllib.parse import urlsplit

ALIASES = {'hostcfgfarm': 'host', 'vpscfgfarm': 'vps', 'cloudcfgfarm': 'cloud'}
ACTIONS = {
    'ipmi': {'status': 'ipmitool chassis power status',
             'sensors': 'ipmitool sensor list',
             'on': 'ipmitool chassis power on',
             'off': 'ipmitool chassis power off',
             'reset': 'ipmitool chassis power reset',
             'pxe': 'ipmitool chassis bootdev pxe'},
    'idrac': {'status': 'racadm serveraction powerstatus',
              'on': 'racadm serveraction powerup',
              'off': 'racadm serveraction powerdown',
              'reset': 'racadm serveraction hardreset'},
    'pxe': {'once': 'ipmitool chassis bootdev pxe',
            'efi-once': 'ipmitool chassis bootdev pxe options=efiboot',
            'status': 'ipmitool chassis bootparam get 5'},
    'esxi': {'list': 'vim-cmd vmsvc/getallvms',
             'status': 'vim-cmd vmsvc/power.getstate',
             'on': 'vim-cmd vmsvc/power.on',
             'off': 'vim-cmd vmsvc/power.off',
             'shutdown': 'vim-cmd vmsvc/power.shutdown',
             'reset': 'vim-cmd vmsvc/power.reset'},
    'fusion': {'list': 'vmrun -T fusion list',
               'start': 'vmrun -T fusion start',
               'stop': 'vmrun -T fusion stop',
               'reset': 'vmrun -T fusion reset',
               'suspend': 'vmrun -T fusion suspend'},
}
HELP = '''Usage: cfgfarm {host|vps|cloud} [existing contracted-door arguments]
       cfgfarm {host|vps|cloud} exec HOST 'COMMAND' [vpsexec flags]
       cfgfarm host BACKEND HOST ACTION [VM] [vpsexec flags]
       cfgfarm host ipxe script HTTPS_URL
Aliases: hostcfgfarm = cfgfarm host; vpscfgfarm = cfgfarm vps;
         cloudcfgfarm = cfgfarm cloud
Backends/actions:
''' + '\n'.join('  %s: %s' % (k, ', '.join(v)) for k, v in ACTIONS.items()) + '''
All backend commands run over governed SSH using tools on that host.
No vendor passwords are accepted. Mutations require the existing vpsexec
--reason, --run and approval flow. Unrecognized vendor reads require approval.
PXE once selects the next boot device; it does not reboot or install a server.
iPXE script prints a local draft; publish it separately through vpsexec push.
'''


def backend_command(backend, action, operand=None):
    if backend not in ACTIONS or action not in ACTIONS[backend]:
        raise ValueError('unknown backend/action')
    needs_vm = (backend == 'esxi' and action != 'list') or (backend == 'fusion' and action != 'list')
    if needs_vm:
        if backend == 'esxi':
            if not operand or not re.fullmatch(r'[1-9][0-9]*', operand):
                raise ValueError('ESXi VM must be a positive numeric inventory ID')
        elif not operand or not operand.startswith('/') or not operand.endswith('.vmx') or any(c in operand for c in '\r\n\x00'):
            raise ValueError('Fusion VM must be an absolute .vmx path')
    elif operand is not None:
        raise ValueError('this action takes no VM operand')
    command = ACTIONS[backend][action]
    if needs_vm:
        command += ' ' + shlex.quote(operand)
        if backend == 'fusion':
            command += ' nogui' if action == 'start' else ' soft'
    return command


def ipxe_script(url):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or not re.fullmatch(r'[A-Za-z0-9:/._~%?=&+@,-]+', url)):
        raise ValueError('use an HTTPS URL without credentials, whitespace or iPXE variables')
    return '#!ipxe\ndhcp || exit\nchain --autofree %s || exit\n' % url


def route(argv, name='cfgfarm'):
    args = list(argv)
    if name in ALIASES:
        args.insert(0, ALIASES[name])
    if not args or args[0] in ('-h', '--help'):
        return None, HELP
    domain = args.pop(0)
    if domain not in ('host', 'vps', 'cloud'):
        raise ValueError('expected host, vps or cloud')
    if not args or args == ['--help']:
        return None, HELP
    if args[0] == 'exec':
        return 'vpsexec', args[1:]
    if domain == 'host' and args[0] == 'ipxe':
        if len(args) != 3 or args[1] != 'script':
            raise ValueError('usage: cfgfarm host ipxe script HTTPS_URL')
        return None, ipxe_script(args[2])
    if domain == 'host' and args[0] in ACTIONS:
        if len(args) < 3:
            raise ValueError('backend requires HOST ACTION [VM]')
        backend, host, action = args[:3]
        if not re.fullmatch(r'[@A-Za-z0-9][A-Za-z0-9_.,@-]*', host):
            raise ValueError('invalid governed host selector')
        rest = args[3:]
        operand = rest.pop(0) if rest and not rest[0].startswith('--') else None
        command = backend_command(backend, action, operand)
        return 'vpsexec', [host, command] + rest
    return 'vpscfg-control.py', args


def main(argv, name, root, interpreter):
    try:
        door, args = route(argv, name)
        if door is None:
            print(args)
            return 0
        os.execv(interpreter, [interpreter, '-I', str(root / door)] + args)
    except (ValueError, OSError) as exc:
        import sys
        print('REFUSED: %s' % exc, file=sys.stderr)
        return 2
