"""Command line interface."""
import argparse
import json
import sys
from . import __version__
from .audit import audit


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, self.prog + ': error: ' + message + '\n')


def main(argv=None):
    parser = Parser(prog='encryption-claim-audit', description='Offline audit of documented at-rest protection promises against Python source.')
    parser.add_argument('path', nargs='?', default='.')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--ignore', action='append', default=[], metavar='GLOB')
    parser.add_argument('--fail-on', choices=['MEDIUM', 'HIGH'], default='MEDIUM')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    try:
        result = audit(args.path, args.ignore)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print('FAIL' if result['findings'] else 'PASS')
        for finding in result['findings']:
            print('{severity} {rule}: {note}'.format(**finding))
            for item in finding['evidence']:
                print('  ' + json.dumps(item, sort_keys=True))
        if args.verbose:
            print(json.dumps(result, indent=2, sort_keys=True))
        for error in result['errors']:
            print('Analysis error: ' + json.dumps(error), file=sys.stderr)
    if result['errors']:
        return 1
    return 2 if any(f['severity'] == 'HIGH' or args.fail_on == 'MEDIUM' for f in result['findings']) else 0


if __name__ == '__main__':
    sys.exit(main())
