import orjson
class CFLogger:
    """Base class for all loggers.

    Returns:
        [type]: [description]
    """

    def __init__(self) -> None:
        pass

class BasicLogger(CFLogger):
    """The default logger. Only logs the number of queries against a model.
    """
    def __init__(self, **kwargs):
        self.num_queries = 0

    def log(self, item):
        self.num_queries += 1

class JSONLogger(CFLogger):
    """Logs queries to a json file saved to disk.
    """
    def __init__(self, **kwargs):
        self.num_queries = 0
        #self.filename = f"{filepath}/logs.json"
        self.logs = []

    def log(self, item):
        # with open(self.filename, "a+") as log_file:
        # data = orjson.dumps(
        #     item,
        #     option=orjson.OPT_SERIALIZE_NUMPY | orjson.OPT_APPEND_NEWLINE
        # )

        self.logs.append(item)
        self.num_queries += 1

def get_attack_logger_obj(logger_type: str) -> object:
    """Factory method to get the requested logger.

    Args:
        logger_type ([type]): [description]

    Raises:
        KeyError: [description]

    Returns:
        [type]: [description]
    """

    attack_logger_obj_map = {
        'basic': BasicLogger,
        'json': JSONLogger
    }

    if logger_type not in attack_logger_obj_map:
        raise KeyError(
            f'Logger is not supported {logger_type}...Please provide one of: {list(attack_logger_obj_map.keys())}...')

    return attack_logger_obj_map[logger_type]
