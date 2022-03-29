class CFErrors:
    class ActiveTarget(Exception):
        def __init__(self, message="No active target") -> None:
            self.message = message
            super().__init__(self.message)

    class ActiveAttack(Exception):
        def __init__(self, message="No active attack") -> None:
            self.message = message
            super().__init__(self.message)

    class BuildTarget(Exception):
        def __init__(self, message="Failed to builed target") -> None:
            self.message = message
            super().__init__(self.message)
