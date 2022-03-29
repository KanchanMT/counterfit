# import os

# for module in os.listdir(os.path.dirname(__file__)):
#     if module == "__init__.py" or module[-3:] != ".py":
#         continue
#     else:
#         __import__("targets." + module[:-3], locals(), globals())

# del module

from counterfit.core.targets import CFTarget

from .creditfraud import CreditFraud
from .digits_blackbox import Digits
from .digits_keras import DigitKeras
from .movie_reviews import MovieReviewsTarget
from .satellite import SatelliteImages
from .yolov3 import YoloV3Target