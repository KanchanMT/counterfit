# Counterfit is not installed as a package and is not part of search path. 

from counterfit import Counterfit
from counterfit.core.utils import set_id
from counterfit.core.optimize import optimize

# Individual attack
attack = "hop_skip_jump"

# Set the target
target = Counterfit.targets()["creditfraud"]
target = Counterfit.target_builder(target)

# Individual attack
cfattack = Counterfit.attack_builder(target, attack)
results = Counterfit.attack_runner(cfattack)

# Optimized attack
scan_id = set_id()
optuna_study = optimize(scan_id, target, attack)
print(optuna_study.best_trials[0].params)

# Attack with best params
cfattack = Counterfit.attack_builder(target, attack)
cfattack.options.update_attack_parameters(optuna_study.best_trials[0].params)
results = Counterfit.attack_runner(cfattack)
