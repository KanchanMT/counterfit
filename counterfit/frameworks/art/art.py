
import numpy as np
import importlib
import inspect
import pathlib
import glob
import yaml
import re

from rich.table import Table
from counterfit.core.attacks import CFAttack
from counterfit.core.output import CFPrint
from counterfit.core.frameworks import CFFramework
from counterfit.core.targets import CFTarget
from counterfit.core.reporting import get_target_data_type_obj

from .utils import attack_factory
from art.utils import compute_success_array, random_targets


class ArtFramework(CFFramework):
    def __init__(self):
        super().__init__()

    @classmethod
    def get_attacks(cls, framework_path=f"{pathlib.Path(__file__).parent.resolve()}/attacks"):
        attacks = {}
        files = glob.glob(f"{framework_path}/*.yml")

        for attack in files:
            with open(attack, 'r') as f:
                data = yaml.safe_load(f)
        
            attacks[data['attack_name']] = data

        return attacks

    @classmethod
    def get_classifiers(cls):
        """
        Load ART classifiers
        """
        classifiers = {}
        base_import = importlib.import_module(f"art.estimators.classification")
        
        for classifier in base_import.__dict__.values():
            if inspect.isclass(classifier):
                if len(classifier.__subclasses__()) > 0:
                    for subclass in classifier.__subclasses__():
                        if "classification" not in subclass.__module__:
                            continue

                        if "classifier" in subclass.__module__:
                            continue

                        else:
                            classifier_name = re.findall(
                                r"\w+", str(subclass).split(".")[-1])[0]
                            classifiers[classifier_name] = subclass
        return classifiers

    @classmethod
    def build(cls, target: CFTarget, attack: str) -> object:
        """
        Build the attack.

        Initialize parameters.
        Set samples.
        """
        # Return the correct estimator for the target selected.
        # Keep an empty classifier around for extraction attacks.
        classifier = cls.classifier(target)

        loaded_attack = attack_factory(attack)

        # Build the classifier
        if "BlackBox" in classifier.__name__:
            target_classifier = classifier(
                target.predict_wrapper,
                target.input_shape,
                len(target.output_classes)
            )

        # Everything else takes a model file.
        else:
            target_classifier = classifier(
                model=target.model
            )

        loaded_attack._estimator = target_classifier

        return loaded_attack

    @classmethod
    def run(cls, cfattack: CFAttack):

        # Give the framework an opportunity to preprocess any thing in the attack.
        cls.pre_attack_processing(cfattack)
        
        # Find the appropriate "run" function
        attack_attributes = cfattack.attack.__dir__()

        # Run the attack. Each attack type has it's own execution function signature.
        if "infer" in attack_attributes:
            results = cfattack.attack.infer(
                np.array(cfattack.samples, dtype=np.float32), y=np.array(cfattack.target.output_classes, dtype=np.float32))

        elif "reconstruct" in attack_attributes:
            results = cfattack.attack.reconstruct(
                np.array(cfattack.samples, dtype=np.float32))

        elif "generate" in attack_attributes:
            if "CarliniWagnerASR" == cfattack.name:
                y = cfattack.target.output_classes
            elif "FeatureAdversariesNumpy" in attack_attributes:
                y = cfattack.samples
            elif "FeatureAdversariesPyTorch" in attack_attributes:
                y = cfattack.samples
            elif "FeatureAdversariesTensorFlowV2" in attack_attributes:
                y = cfattack.samples
            else:
                y = None

            if "ZooAttack" == cfattack.name:
                # patch ZooAttack
                cfattack.attack.estimator.channels_first = True

            print("----------------------------------------------------------------------")
            print(random_targets(np.array(cfattack.initial_labels), len(cfattack.target.output_classes)))
            print("----------------------------------------------------------------------")

            results = cfattack.attack.generate(
                x=np.array(cfattack.samples, dtype=np.float32),
                y=random_targets(np.array(cfattack.initial_labels), len(cfattack.target.output_classes)))

        elif "poison" in attack_attributes:
            results = cfattack.attack.poison(
                np.array(cfattack.samples, dtype=np.float32))

        elif "poison_estimator" in attack_attributes:
            results = cfattack.attack.poison(
                np.array(cfattack.samples, dtype=np.float32))

        elif "extract" in attack_attributes:
            # Returns a thieved classifier
            training_shape = (
                len(cfattack.target.X), *cfattack.target.input_shape)

            samples_to_query = cfattack.target.X.reshape(
                training_shape).astype(np.float32)
            results = cfattack.attack.extract(
                x=samples_to_query, thieved_classifier=cfattack.attack.estimator)

            cfattack.thieved_classifier = results
        else:
            print("Not found!")
        return results
    
    @classmethod
    def pre_attack_processing(cls, cfattack: CFAttack):
        cls.set_parameters(cfattack)

    @staticmethod
    def post_attack_processing(cfattack: CFAttack):
        attack_attributes = cfattack.attack.__dir__()

        if "generate" in attack_attributes:
            current_datatype = cfattack.target.data_type
            current_dt_report_gen = get_target_data_type_obj(current_datatype)
            cfattack.summary = current_dt_report_gen.get_run_summary(cfattack)
            # current_dt_report_gen.print_run_summary(summary)
            
        elif "extract" in attack_attributes:
            # Override default reporting for the attack type
            extract_table = Table(header_style="bold magenta")
            # Add columns to extraction table
            extract_table.add_column("Success")
            extract_table.add_column("Copy Cat Accuracy")
            extract_table.add_column("Elapsed time")
            extract_table.add_column("Total Queries")

            # Add data to extraction table
            success = cfattack.success[0]  # Starting value
            thieved_accuracy = cfattack.results
            elapsed_time = cfattack.elapsed_time
            num_queries = cfattack.logger.num_queries
            extract_table.add_row(str(success), str(
                thieved_accuracy), str(elapsed_time), str(num_queries))

            CFPrint.output(extract_table)

    @classmethod
    def classifier(cls, target: CFTarget):
        # this code attempts to match the .target_classifier attribute of a target with an ART
        classifiers = cls.get_classifiers()

        if not hasattr(target, "target_classifier"):
            return classifiers.get("BlackBoxClassifierNeuralNetwork")
        else:
            for classifier in classifiers.keys():
                if target.target_classifier.lower() in classifier.lower():
                    return classifiers.get(classifier)

    def check_success(self, cfattack: CFAttack) -> bool:
        attack_attributes = set(cfattack.attack.__dir__())

        if "generate" in attack_attributes:
            return self.evasion_success(cfattack)

        elif "extract" in attack_attributes:
            return self.extraction_success(cfattack)

    def evasion_success(self, cfattack: CFAttack):
        if cfattack.options.__dict__.get("targeted") == True:
            labels = cfattack.options.target_labels
            targeted = True
        else:
            labels = cfattack.initial_labels
            targeted = False

        success = compute_success_array(
            cfattack.attack._estimator,
            cfattack.samples,
            labels,
            cfattack.results,
            targeted
        )

        final_outputs, final_labels = cfattack.target.get_sample_labels(
            cfattack.results)
        cfattack.final_labels = final_labels
        cfattack.final_outputs = final_outputs
        return success

    def extraction_success(self, cfattack: CFAttack):
        training_shape = (
            len(cfattack.target.X), *cfattack.target.input_shape)
        training_data = cfattack.target.X.reshape(training_shape)

        victim_preds = np.atleast_1d(np.argmax(
            cfattack.target.predict_wrapper(x=training_data), axis=1))
        thieved_preds = np.atleast_1d(np.argmax(
            cfattack.thieved_classifier.predict(x=training_data), axis=1))

        acc = np.sum(victim_preds == thieved_preds) / len(victim_preds)

        cfattack.results = acc

        if acc > 0.1:  # TODO add to options struct
            return [True]
        else:
            return [False]

    def set_parameters(self) -> None:
        # ART has its own set_params function. Use it.
        attack_params = {}
        for k, v in self.options.attack_parameters.items():
            attack_params[k] = v["current"]
        self.attack.set_params(**attack_params)
    
