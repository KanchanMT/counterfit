import argparse
from typing import List
from unittest import result
from cmd2 import with_argparser
from cmd2 import with_category

from counterfit import CFPrint
from counterfit import set_id
from core.state import CFState
from counterfit.core.optimize import optimize

from counterfit import Counterfit


# return a list of attack names
def get_attacks():
    frameworks = CFState.state().get_frameworks()

    attacks = []

    for framework_name, framework in frameworks.items():
        for temp_attack in list(framework["attacks"].keys()):
            attacks.append(temp_attack)

    return attacks


parser = argparse.ArgumentParser()
parser.add_argument("-a", "--attacks", nargs='+', required=True, choices=get_attacks())
parser.add_argument("-o", "--optimize", action="store_true")
parser.add_argument("-i", "--num_iters", type=int, default=1)
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("-s", "--summary", action="store_true", help="also summarize scans by class label")


@with_argparser(parser)
@with_category("Counterfit Commands")
def do_scan(self, args):
    """[summary]

    Args:
        args.attacks (str): The list of attacks to run
        args.options (str): How attack parameters are selected
    """

    target = CFState.state().get_active_target()
    if not target:
        CFPrint.warn("Active target not set. Try 'interact <target>")
        return
    else:
        CFPrint.success(
            f"Scanning Target: {target.target_name} ({target.target_id})")

        scan_id = set_id()

        for attack in args.attacks:
            if args.optimize:
                optimize(
                    scan_id=scan_id,
                    target=target,
                    attack=attack,
                    num_iters=args.num_iters
                )
            else:
                results = {}
                for attack in args.attacks:
                    cfattack = Counterfit.attack_builder(target, attack)
                    Counterfit.attack_runner(cfattack)
                    results[cfattack.attack_id] = cfattack.final_outputs