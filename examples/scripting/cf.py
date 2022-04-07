# imports
import sys, os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from counterfit import Counterfit
from counterfit.core import optimize

from targets import CreditFraud
from targets import DigitKeras
from targets import Digits

attacks = ["mi_face"]
target = Digits()
target.load()

for attack in attacks: 
    cfattack = Counterfit.build_attack(target, attack)
    Counterfit.run_attack(cfattack)

print(cfattack.results)