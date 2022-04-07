from .core.core import Counterfit
from .core.attacks import CFAttack
from .core.targets import CFTarget
from .core.options import CFOptions
from .core.frameworks import CFFramework
from .core.logger import CFLogger
from .core.output import CFPrint
from .core.utils import set_id

from . import (
    core,
    frameworks,
    reporting,
    data
)

__version__ = "1.1.0"
name = "counterfit"