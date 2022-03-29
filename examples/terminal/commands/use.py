import argparse
from typing import List
from cmd2 import with_argparser
from cmd2 import with_category
from counterfit.core.output import CFPrint
from counterfit.core import utils
from core.state import CFState


# return a list of attack names
def get_attacks():
    frameworks = frameworks = CFState.state().get_frameworks()

    attacks = []

    for framework_name, framework in frameworks.items():
        for temp_attack in list(framework["attacks"].keys()):
            attacks.append(temp_attack)

    return attacks


parser = argparse.ArgumentParser()
parser.add_argument("attack", choices=get_attacks(),
                    help="The attack to use, either <attack name> or <attack id>")


@with_argparser(parser)
@with_category("Counterfit Commands")
def do_use(self, args: argparse.Namespace) -> None:
    """Select an attack to use on the active target.
    Use 'interact' to select a target first.
    """

    if not CFState.state().active_target:
        CFPrint.warn(
            "Not interacting with any targets. Try interacting with a target.")
        return False

    if args.attack in CFState.state().active_target.attacks:  # existing attack
        attack = CFState.state().active_target.attacks[args.attack]
    else:
        try:
            scan_id = utils.set_id()
            new_attack = CFState.state().build_new_attack(
                target=CFState.state().active_target,
                attack=args.attack,
                scan_id=scan_id
            )
            CFState.state().active_target.set_active_attack(new_attack)

        except Exception as error:
            CFPrint.warn(f"Failed to build {args.attack}: {error}")
    

    

