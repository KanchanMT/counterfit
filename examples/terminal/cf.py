import os
import sys
import argparse
import warnings

from core.config import Config
from core.terminal import Terminal

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"  # make tensorflow quiet
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)

if sys.version_info < (3, 7):
    sys.exit("[!] Python 3.7+ is required")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config")
    parser.add_argument("-d", "--debug", help="run counterfit with debug enabled")
    args = parser.parse_args()

    # create the terminal
    terminal = Terminal()

    print(Config.start_banner)

    terminal.load_commands()

    # run the terminal loop
    sys.exit(terminal.cmdloop())