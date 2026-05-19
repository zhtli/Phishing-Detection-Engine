"""base_transformation.py: Defines the base class for feature extraction transformations."""
__author__ = "Ondřej Ondryáš <xondry02@vut.cz>"

import abc

from pandas import DataFrame


class Transformation(abc.ABC):
    def __new__(cls, *args, **kwargs):
        # This enables transformations not to explicitly define a constructor that accepts
        # the configuration object, while others can define it.
        if cls.__init__ is object.__init__:
            def new_init(_self, _config):
                pass

            cls.__init__ = new_init

        return super().__new__(cls)

    @abc.abstractmethod
    def transform(self, df: DataFrame) -> DataFrame:
        raise NotImplementedError("the transform method must be implemented in the subclass")

    @property
    @abc.abstractmethod
    def features(self) -> dict[str, str]:
        raise NotImplementedError("the features property must be implemented in the subclass")
