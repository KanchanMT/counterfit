import datetime
import inspect
import os
import pathlib
from typing import Union

from abc import abstractmethod


import numpy as np
from counterfit.core.output import CFPrint
from counterfit.core.utils import set_id

class CFTarget:
    """Base class for all targets.
    """

    def __init__(self, **kwargs):
        self.target_id = set_id()

        for k, v in kwargs.items():
            setattr(self, k, v)

    @abstractmethod
    def load(self):
        """Loads data, models, etc in preparation. Is called by `interact`.

        Raises:
            NotImplementedError: Is required to be implemented by a framework.
        """
        raise NotImplementedError
    
    @abstractmethod
    def predict(self, x: np.ndarray) -> np.ndarray:
        """The predict interface to the target model.

        Raises:
            NotImplementedError: Is required to be implemented by a framework.
        """
        raise NotImplementedError

    def get_samples(self, sample_index: Union[int, list, range] = 0) -> np.ndarray:
        """This function helps to directly set sample_index and samples for a target not depending on attack.

        Args:
            sample_index (int, list or range, optional): [single or multiple indices]. Defaults to 0.

        Returns:
            np.ndarray: [description]
        """
        if hasattr(sample_index, "__iter__"):
            sample_index = list(sample_index)  # in case "range" was used
            # multiple index
            if type(self.X[sample_index[0]]) is str:
                # multiple index (str)
                out = np.array([self.X[i] for i in sample_index])
                batch_shape = (-1,)
            else:
                # multiple index (numpy)
                out = np.array([self.X[i] for i in sample_index])
                batch_shape = (-1,) + self.input_shape
        elif type(self.X[sample_index]) is str:
            # single index (string)
            # array of strings (textattack)
            out = np.array(self.X[sample_index])
            batch_shape = (-1,)
        else:
            # single index (array)
            # array of arrays (art)
            out = np.atleast_2d(self.X[sample_index])
            batch_shape = (-1,) + self.input_shape

        return out.reshape(batch_shape)

    def predict_wrapper(self, x, **kwargs):
        output = self.predict(x)
        if self.logger:
            labels = self.outputs_to_labels(output)
            for sample, tmp_output in zip(x, output):
                try:
                    log_entry = {
                        "timestamp": datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
                        "input": np.array(sample).flatten().reshape(-1).tolist(),
                        "output": tmp_output,
                        "labels": labels
                    }

                    self.logger.log(log_entry)

                except Exception as e:
                    print(e)
                    continue

        return output

    def fullpath(self, file: str) -> str:
        """A conveiance function

        Args:
            file (str): The file tp get the full path for.

        Returns:
            str: The full path of the file
        """
        basedir = pathlib.Path(os.path.abspath(
            inspect.getfile(self.__class__))).parent.resolve()
        return os.path.join(basedir, file)

    def get_sample_labels(self, samples):
        """A covienance function to get outputs and labels for a target query.

        Args:
            samples ([type]): [description]

        Returns:
            [type]: [description]
        """
        output = self.predict_wrapper(samples)
        labels = self.outputs_to_labels(output)
        return output, labels

    def outputs_to_labels(self, output):
        """Default multiclass label selector via argmax. User can override this function if, for example, one wants to choose a specific threshold
        Args:
            output ([type]): [description]

        Returns:
            [type]: [description]
        """
        output = np.atleast_2d(output)
        return [self.output_classes[i] for i in np.argmax(output, axis=1)]

    def get_results_folder(self, folder="results"):
        return os.path.join(os.curdir, folder)

    def get_data_type_obj(self):
        target_data_types = {
            'text': "TextReportGenerator",
            'image': "ImageReportGenerator",
            'tabular': "TabularReportGenerator"
        }
        
        if self.data_type not in target_data_types.keys():
            CFPrint.failed(f"{self.data_type} not supported. Choose one of {list(target_data_types.keys())}")
            return 

        return target_data_types[self.data_type]