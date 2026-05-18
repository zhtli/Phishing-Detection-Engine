"""util.py: A collection of shared utility functions for all the components."""
__author__ = "Ondřej Ondryáš <xondry02@vut.cz>"

import json
import logging
import os
import sys
import tomllib
from datetime import datetime
from typing import TypeVar, Type, Any, cast

import pydantic
from pydantic import ValidationError, BaseModel


_logger = logging.getLogger("stub")
_logger.setLevel(logging.INFO)
_logger.addHandler(logging.StreamHandler(sys.stderr))
_config: dict | None = None
_config_file: str | None = None
_last_config_modify_time = -1


def get_config_file() -> str:
    """
    Retrieves the path to the configuration file.

    The function retrieves the path from the environment variable APP_CONFIG_FILE.
    If the environment variable is not set, it defaults to './config.toml'. The function checks if the file
    exists and raises a FileNotFoundError if it does not.

    Returns:
        str: The path to the configuration file.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
    """
    global _config_file, _last_config_modify_time
    if _config_file:
        return _config_file

    config_file = os.getenv("APP_CONFIG_FILE")
    if config_file is None:
        config_file = "./config.toml"

    if not os.path.isfile(config_file):
        raise FileNotFoundError("Configuration file not found: " + config_file)

    _config_file = os.path.abspath(config_file)
    _last_config_modify_time = os.stat(_config_file).st_mtime
    return _config_file


def read_config() -> dict:
    """Reads the configuration file specified by the environment variable APP_CONFIG_FILE."""
    global _config
    if _config:
        return _config

    with open(get_config_file(), "rb") as f:
        _config = tomllib.load(f)
        return _config


def get_safe(data: dict, path: str) -> Any | None:
    """Gets a value from a nested dictionary, returning None if the path doesn't exist."""
    if data is None:
        return None

    try:
        for key in path.split("."):
            if data is None:
                return None
            data = data[key]
        return data
    except (KeyError, TypeError):
        return None


def timestamp_now_millis() -> int:
    """Returns the current UNIX timestamp in milliseconds."""
    return int(datetime.now().timestamp() * 1e3)


TModel = TypeVar('TModel', bound=BaseModel)


def ensure_model(model_class: Type[TModel], data: dict | str | bytes | None) -> TModel | None:
    """
    Validates the provided data against the specified Pydantic model class.

    This function takes a model class and a dictionary of data as input. It attempts to validate the data against
    the model class using the model's `model_validate` method. If the data is valid, the function returns the validated
    model. If the data is not valid, the function logs a warning and returns None.

    If an exception occurs during the validation process, the function logs an error and returns None.

    Args:
        model_class (Type[TModel]): The class of the model against which to validate the data.
        data (dict | None): The data to validate. If None, the function immediately returns None.

    Returns:
        TModel | None: The validated model if the data is valid, None otherwise.
    """
    if data is None:
        return None

    if isinstance(data, bytes) or isinstance(data, str):
        if len(data) == 0:
            return None
        else:
            data = json.loads(data)

    try:
        return model_class.model_validate(data)
    except ValidationError as e:
        _logger.warning("Invalid model",
                        extra={"properties": {"input_data": data, "model": model_class.__name__, "errors": e.errors()}})
        return None
    except Exception as e:
        _logger.error("Error validating model", exc_info=e,
                      extra={"properties": {"input_data": data, "model": model_class.__name__}})
        return None


def dump_model(obj: Any) -> bytes:
    if isinstance(obj, pydantic.BaseModel):
        return obj.model_dump_json(indent=None, by_alias=True,
                                   context={"separators": (',', ':')}).encode('utf-8', errors='ignore')
    else:
        return json.dumps(obj, indent=None, separators=(',', ':')).encode('utf-8', errors='ignore')
