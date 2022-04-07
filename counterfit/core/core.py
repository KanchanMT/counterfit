import glob
import os
import yaml
import time
import importlib
import inspect
import traceback

from counterfit.core.targets import CFTarget
from counterfit.core.output import CFPrint
from counterfit.core.attacks import CFAttack
from counterfit.core.options import CFOptions

class Counterfit:

    # Frameworks
    @classmethod
    def get_frameworks(cls):
        """Imports the available frameworks from the frameworks folder. Adds the loaded frameworks into self.frameworks. Frameworks contain the methods required for managing the attacks that are found within the framework.

        Args:
            frameworks_path (str): A folder path where frameworks are kept. 
        """
        frameworks = {}
        cf_frameworks = importlib.import_module("counterfit.frameworks")
        for framework in cf_frameworks.CFFramework.__subclasses__():
            framework_name = framework.__module__.split(".")[-1]

            frameworks[framework_name] = {}
            frameworks[framework_name]["attacks"] = {}
            frameworks[framework_name]["module"] = framework

            framework_path = os.path.dirname(inspect.getfile(framework)) 

            for attack in glob.glob(f"{framework_path}/attacks/*.yml"):
                with open(attack, 'r') as f:
                    data = yaml.safe_load(f)

                if data["attack_name"] not in frameworks[framework_name]["attacks"].keys():
                    frameworks[framework_name]["attacks"][data['attack_name']] = data

        return frameworks

    @classmethod
    def build_target(
        cls, 
        data_type: str, 
        endpoint: str, 
        output_classes: list,
        classifier: str,
        input_shape: tuple,
        load_func: object,
        predict_func: object,
        X: list) -> CFTarget:

        try:
            target = CFTarget(
                data_type=data_type, 
                endpoint=endpoint,
                output_classes=output_classes, 
                classifier=classifier,
                input_shape=input_shape,
                load=load_func,
                predict=predict_func,
                X=X
            )

        except Exception as error:
            CFPrint.failed(f"Failed to build target: {error}")
    
        try:
            target.load()
        
        except Exception as error:
            CFPrint.failed(f"Failed to load target: {error}")
        
        CFPrint.success(f"Successfully created target")
        return target

    @classmethod
    def build_attack(
        cls,
        target: CFTarget,
        attack: str,
        scan_id: str = None) -> CFAttack:
        """Build a new CFAttack. 
        
        Search through the loaded frameworks for the attack and create a new CFAttack object for use.

        Args:
            target_name (CFTarget, required): The target object.
            attack_name (str, required): The attack name.
            scan_id (str, Optional): A unique value
 
        Returns:
            CFAttack: A new CFAttack object.
        """

        # Resolve the attack
        try:
            for k, v in cls.get_frameworks().items():
                if attack in list(v["attacks"].keys()):
                    framework = v["module"]()
                    attack = v["attacks"][attack]

        except Exception as error:
            CFPrint.failed(f"Failed to load framework or resolve {attack}: {error}")
            traceback.print_exc()

        # Ensure the attack is compatible with the target
        if target.data_type not in attack["attack_data_tags"]:
            CFPrint.failed(f"Target data type ({target.data_type}) is not compatible with the attack chosen ({attack['attack_data_tags']})")
            return False

        if hasattr(target, "classifier"):
            CFPrint.warn("Target classifier may not be compatible with this attack.")
        else:
            CFPrint.warn("Target does not have classifier attribute set. Counterfit will treat the target as a blackbox.")

        # Have the framework build the attack.
        try:
            new_attack = framework.build(
                target=target,
                attack=attack["attack_class"] # The dotted path of the attack. 
            )

        except Exception as error:
            CFPrint.failed(f"Framework failed to build attack: {error}")
            traceback.print_exc()

        # Create a CFAttack object
        try:
            cfattack = CFAttack(
                name=attack["attack_class"],
                target=target,
                framework=framework,
                attack=new_attack,
                options=CFOptions(attack["attack_parameters"])
            )

        except Exception as error:
            CFPrint.failed(f"Failed to build CFAttack: {error}")
            traceback.print_exc()

        return cfattack

    @classmethod
    def run_attack(cls, cfattack: CFAttack) -> bool:
        """Run a prepared attack. Get the appropriate framework and execute the attack.

        Args:
            attack_id (str, required): The attack id to run.

        Returns:
            Attack: A new Attack object with an updated cfattack_class. Additional properties set in this function include, attack_id (str)
            and the parent framework (str). The framework string is added to prevent the duplication of code in run_attack.
        """

        # Set the initial values for the attack. Samples, logger, etc.
        cfattack.prepare_attack()

        # Run the attack
        cfattack.set_status("running")

        # Start timing the attack for the elapsed_time metric
        start_time = time.time()

        # Run the attack
        try:
            results = cfattack.framework.run(cfattack)
        except Exception as error:
            # postprocessing steps for failed attacks
            success = [False] * len(cfattack.initial_labels)

            CFPrint.failed(
                f"Failed to run {cfattack.attack_id} ({cfattack.name}): {error}")

            results = None
            return

        # postprocessing steps for successful attacks
        finally:

            # Stop the timer
            end_time = time.time()

            # Set the elapsed time metric
            cfattack.set_elapsed_time(start_time, end_time)

            # Set the results the attack returns
            # Results are attack and framework specific. 
            cfattack.set_results(results)

            # Determine the success of the attack
            success = cfattack.framework.check_success(cfattack)

            # Set the success value
            cfattack.set_success(success)

            # Give the framework an opportunity to process the results, generate reports, etc
            cfattack.framework.post_attack_processing(cfattack)

            # Mark the attack as complete
            cfattack.set_status("complete")

            # Let the user know the attack has completed successfully.
            CFPrint.success(
                f"Attack completed {cfattack.attack_id}")
