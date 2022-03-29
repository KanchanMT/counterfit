import optuna
import numpy as np
from counterfit.core import Counterfit

# Optimization function
def max_abs_change(cfattack):
    batch_size = len(cfattack.results)
    i_0 = np.atleast_2d(cfattack.samples)
    i_f = np.array(cfattack.results)
    i_0 = i_0.reshape(batch_size, -1).astype(float)
    i_f = i_f.reshape(batch_size, -1).astype(float)
    
    max_abs_change = np.atleast_1d(abs(i_f - i_0).max(axis=-1))

    return max_abs_change

def num_queries(cfattack):
    return cfattack.logger.num_queries

def optimize(scan_id, target, attack, num_iters=2):
    def objective(trial):
        cfattack = Counterfit.attack_builder(target, attack)
        params = {}

        for k, v in cfattack.options.attack_parameters.items():
            if v.get("optimize"):
                if v["optimize"].get("uniform"):
                    params[k] = trial.suggest_int(k, v["optimize"]["uniform"]["min"], v["optimize"]["uniform"]["max"])

        cfattack.options.update_attack_parameters(params)

        try:
            Counterfit.attack_runner(cfattack)
            return max_abs_change(cfattack), cfattack.logger.num_queries, cfattack.success
        except Exception as error:
            print(error)
            return 1, 50000, 0

    sampler = optuna.samplers.TPESampler()
    study = optuna.create_study(study_name=scan_id, sampler=sampler, directions=["minimize", "minimize", "maximize"])
    study.optimize(objective, n_trials=num_iters, gc_after_trial=True)

    return study
