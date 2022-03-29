import pytest
import sys
import numpy as np

import warnings
warnings.filterwarnings('ignore')

from targets import CreditFraud
from targets import Digits
from targets import DigitKeras
from targets import MovieReviewsTarget
from targets import SatelliteImages
from targets import YoloV3Target

from counterfit import Counterfit

# @pytest.fixture(params=[CreditFraud, SatelliteImagesTarget, Digits, DigitKeras, YoloV3Target])
# def target(request):
#     yield request.param

# @pytest.fixture(params=list(Counterfit.get_frameworks().keys()))

def test_hop_skip_jump_attack():
    target = CreditFraud()
    attack = "hop_skip_jump"

    target.load()
    cfattack = Counterfit.build_attack(target, attack)
    clip_values = (0., 1.)

    cfattack.options.update({"clip_values": clip_values})

    Counterfit.run_attack(cfattack)


def test_targeted_hop_skip_jump_attack():
    target = CreditFraud()
    attack = "hop_skip_jump"

    target.load()
    cfattack = Counterfit.build_attack(target, attack)
    clip_values = (0., 1.)
    cfattack.options.update(
        {
            "clip_values": clip_values,
            "targeted": True,
            "target_labels": np.array([1, 7])
        }
    )

    Counterfit.run_attack(cfattack)