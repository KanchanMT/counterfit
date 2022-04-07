# state.py
# This file keeps track of all load targets.
import os
import importlib
import sys
import inspect
import sys

from counterfit.core.output import CFPrint
from counterfit.core.attacks import CFAttack
from counterfit.core.targets import CFTarget
from counterfit.core import utils
from counterfit.core import Counterfit


class CFState:
    """Singleton class responsible for managing targets and attacks. Instantiation of a class is restricted to one object.
    """
    __instance__ = None

    def __init__(self):
        if CFState.__instance__ is None:
            CFState.__instance__ = self
        else:
            raise Exception("You cannot create another CFState class")

        self.frameworks = {}
        self.targets = {}
        self.scans = {}
        self.active_target = None

    @staticmethod
    def state():
        """Static method to fetch the current instance.
        """
        if not CFState.__instance__:
            CFState.__instance__ = CFState()
        return CFState.__instance__
    
    # Frameworks
    def get_frameworks(self) -> dict:
        """Get all available frameworks

        Args:
            None

        Returns:
            dict: all frameworks.
        """
        return Counterfit.frameworks()

    # Targets
    def get_targets(self, targets_path = "../targets"):
        """Imports available targets from the targets folder. Adds the loaded frameworks to CFState.targets.
        Targets contain the data and methods to interact with a target machine learning system.

        Args:
            targets_path (str): Folder path to where targets are kept
        """
        cftargets = {}

        sys.path.append("..")
        target_cls = importlib.import_module("targets")
        for _, obj in inspect.getmembers(target_cls):
            if inspect.isclass(obj):
                if issubclass(obj, CFTarget) and obj is not CFTarget:
                    target_name = obj.target_name
                    cftargets[target_name] = obj

        return cftargets


    def reload_target(self):
        """Reloads the active target.
        """
        if not self.active_target:
            CFPrint.failed("No active target")
            return

        else:
            # Get the framework to reload
            target_name = self.active_target.target_name
            target_to_reload = self.targets[target_name]

            # Get the attacks
            attacks = target_to_reload.attacks
            active_attack = target_to_reload.active_attack

            # Get the class we want to instantiate after module reload
            target_class = target_to_reload.__class__.__name__

            # Reload the module
            reloaded_module = importlib.reload(
                sys.modules[target_to_reload.__module__])

            # Reload the target
            reloaded_target = reloaded_module.__dict__.get(
                target_class)()

            # Delete the old class
            del self.targets[target_name]

            # Replace the old module with the new one
            self.targets[target_name] = reloaded_target

            # Load the attacks.
            target_to_load = self.load_target(target_name)

            # Set it as the active target
            self.set_active_target(target_to_load)

            # Replace the history
            self.active_target.attacks = attacks
            self.active_target.active_attack = active_attack

    def set_active_attack(self, attack) -> None:
        """Sets the active attack

        Args:
            attack_id (str): The attack_id of the attack to use. 
        """
        CFPrint.success(f"Using {attack.attack_id}")
        self.active_attack = attack

    def get_active_attack(self) -> None:
        """Get the active attack
        """
        if self.active_attack is None:
            return None
        return self.active_attack

    def get_attacks(self, scan_id: str = None) -> dict:
        """Get all of the attacks

        Args:
            scan_id (str, optional): The scan_id to filter on. Defaults to None.

        Returns:
            dict: [description]
        """
        if scan_id:
            scans_by_scan_id = {}
            for attack_id, attack in self.attacks.items():
                if attack.scan_id == scan_id:
                    scans_by_scan_id[attack_id] = attack
            return scans_by_scan_id
        else:
            return self.attacks

    def get_active_target(self) -> Target:
        """Get the active target

        Returns:
            Target: The active target.
        """
        return self.active_target

    def add_attack_to_target(self, target_name: str, cfattack: CFAttack) -> None:
        """After a CFAttack object has been built, add it to the target for tracking.

        Args:
            target_name (str): The target name
            cfattack (CFAttack): The CFAttack object to add.
        """
        target = self.targets.get(target_name)
        target.add_attack(cfattack)

        #self.attacks[attack.attack_id] = attack

    def set_active_target(self, target: CFTarget) -> None:
        """Set the active target with the target name provided.

        Args:
            target (Target): The target object to set as the active target
        """
        self.active_target = target

    def build_new_target(self, target):
        new_target = Counterfit.build_target(
            target
        )

        return new_target

    def build_new_attack(self, target, attack, scan_id):
        new_attack = Counterfit.build_attack(
            target,
            attack,
            scan_id
        )

        return new_attack

    def run_attack(self, attack: CFAttack):
        Counterfit.attack_runner(attack)

