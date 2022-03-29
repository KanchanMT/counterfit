import argparse
from cmd2 import with_argparser
from cmd2 import with_category

from core.state import CFState
from counterfit.core.output import CFPrint

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action="store_true", help="print a summary ", default=False)


@with_argparser(parser)
@with_category("Counterfit Commands")
def do_run(self, args: argparse.Namespace) -> None:
    """Run an attack
    """

    target_to_scan = CFState.state().get_active_target()
    if not target_to_scan:
        CFPrint.warn("Active target not set. Try 'interact <target>''")
        return

    active_attack = CFState.state().active_target.get_active_attack()
    CFState.state().run_attack(active_attack)