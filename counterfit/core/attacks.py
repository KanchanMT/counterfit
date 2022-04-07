import os
import orjson
import datetime
from counterfit.core import utils
from counterfit.core.logger import get_attack_logger_obj

class CFAttack:
    """
    The base class for all attacks in all frameworks.
    """

    def __init__(
        self,
        name,
        target,
        framework,
        attack,
        options,
        scan_id=None):

        
        # Parent framework
        self.name = name
        self.attack_id = utils.set_id()
        self.scan_id = scan_id
        self.target = target
        self.framework = framework
        self.attack = attack
        self.options = options

        # Attack information
        self.created_on = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        self.attack_status = "pending"

        # Algo parameters
        self.samples = None
        self.initial_labels = None
        self.initial_outputs = None

        # Attack results
        self.final_outputs = None
        self.final_labels = None
        self.results = None
        self.success = None
        self.elapsed_time = None

        # reporting
        self.run_summary = None

        # Get the samples.
        self.samples = target.get_samples(
            self.options.cf_options["sample_index"]["current"]
        )

        self.logger = self.set_logger(logger=self.options.cf_options["logger"]["current"])
        self.target.logger = self.logger

    def prepare_attack(self):
        # Send a request to the target for the selected sample
        self.initial_outputs, self.initial_labels = self.target.get_sample_labels(
            self.samples)   

    def set_results(self, results: object) -> None:
        self.results = results

    def set_status(self, status: str) -> None:
        self.attack_status = status

    def set_success(self, success: bool = False) -> None:
        self.success = success

    def set_logger(self, logger):
        new_logger = get_attack_logger_obj(logger)
        logger = new_logger()
        return logger
        
    def set_elapsed_time(self, start_time, end_time):
        self.elapsed_time = end_time - start_time

    def get_results_folder(self):
        results_folder = self.target.get_results_folder()

        if not os.path.exists(results_folder):
            os.mkdir(results_folder)
        
        scan_folder = os.path.join(results_folder, self.attack_id)
        if not os.path.exists(scan_folder):
            os.mkdir(scan_folder)
        
        return scan_folder

    def save_run_summary(self, filename=None, verbose=False):
        run_summary = {
            "sample_index": self.options.sample_index,
            "initial_labels": self.initial_labels,
            "final_labels": self.final_labels,
            "elapsed_time": self.elapsed_time,
            "num_queries": self.logger.num_queries,
            "success": self.success,
            "results": self.results
        }

        if verbose:
            run_summary["input_samples"] = self.samples

        data = orjson.dumps(
            run_summary,
            option=orjson.OPT_SERIALIZE_NUMPY | orjson.OPT_APPEND_NEWLINE
        )

        if not filename:
            results_folder = self.get_results_folder()
            filename = f"{results_folder}/run_summary.json"

        with open(filename, "w") as summary_file:
            summary_file.write(data.decode())
