import argparse
from cmd2 import with_category
from cmd2 import with_argparser

from counterfit.core.output import CFPrint

from core.state import CFState

def get_targets():
    targets = []
    for target_name, target_obj in sorted(CFState.state().get_targets().items()):
        targets.append(target_name)
    return targets

parser = argparse.ArgumentParser()
parser.add_argument("target", choices=get_targets())

@with_argparser(parser)
@with_category("Counterfit Commands")
def do_interact(self, args: argparse.Namespace) -> None:
    """Sets the the active target. 

    Args:
        target (str): The target to interact with.
    """

    # Load the target
    target = CFState.state().get_targets().get(args.target, None)
    try:
        new_target = CFState.state().build_new_target(target)
        CFPrint.success(
            f"{target.target_name} successfully loaded!")

    except Exception as e:
        CFPrint.failed(
            f"Could not load {target.target_name}: {e}\n")

    # Set it as the active target
    CFState.state().set_active_target(new_target)
