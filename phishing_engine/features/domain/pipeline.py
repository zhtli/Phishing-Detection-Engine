"""extractor.py: The feature extraction process implementation.
Provides the extract_features function that takes raw data, passes it through the configured transformations and returns
 a DataFrame of feature vectors. The list of transformations is initialized from the configuration.

Originally authored by Ondřej Ondryáš <xondry02@vut.cz> as part of DomainRadar."""

from collections import OrderedDict
from typing import Iterable

import pandas as pd
from pandas import DataFrame

from phishing_engine.features.common.base import Transformation
from .flatten import DomainRecordFlattener
from .transformations.dns import DNSTransformation
from .transformations.drop_columns import DropColumnsTransformation
from .transformations.geo import GeoTransformation
from .transformations.ip import IPTransformation
from .transformations.lexical import LexicalTransformation
from .transformations.rdap_dn import RDAPDomainTransformation
from .transformations.rdap_ip import RDAPAddressTransformation

_all_transformations = OrderedDict([
    ("dns", DNSTransformation),
    ("ip", IPTransformation),
    ("geo", GeoTransformation),
    ("lexical", LexicalTransformation),
    ("rdap_dn", RDAPDomainTransformation),
    ("rdap_ip", RDAPAddressTransformation),
    ("drop", DropColumnsTransformation)
])
"""An ordered dictionary of all data transformer classes.
 The order in this dictionary determines the order in which the transformations will be applied to the data. 
 The keys are used in the configuration to enable or disable specific transformations."""
_enabled_transformations: list[Transformation] = []
"""A list of all enabled and initialized transformer objects."""
_record_flattener = DomainRecordFlattener()
"""Reshapes each raw domain record into the flat column layout the transformations consume."""
_added_columns_names: list = []
"""A list of the names of all columns added by the transformations."""
_added_columns_with_types: dict = {}
"""A dictionary of the names of all columns added by the transformations and their target DataFrame types."""
_all_columns_with_types: dict = {}
"""A dictionary of all output columns and their target DataFrame types, including the flattened columns
produced from the raw record."""


def init_transformations(config: dict):
    """
    Initializes the transformation list and other metadata based on the `enabled_transformations` key
    in the configuration. If the key is not present, all transformations are enabled.

    This method takes a configuration dictionary as input. It checks for the presence of the 'enabled_transformations'
    key in the dictionary. If the key is present, it initializes the transformation list with the transformations
    specified by the key. If the key is not present, it initializes the transformation list with all available
    transformations.

    The method also updates the metadata related to the transformations, including the names of the columns added by
    the transformations and their target DataFrame types.

    Args:
        config (dict): The configuration dictionary.

    Raises:
        ValueError: If the 'enabled_transformations' key in the configuration dictionary contains an invalid
        transformation identifier.
    """
    global _enabled_transformations, _added_columns_names, _added_columns_with_types, _all_columns_with_types

    enabled_transformation_ids: Iterable[str] | None = config.get("enabled_transformations", None)
    if enabled_transformation_ids is None:
        _enabled_transformations = [trans(config) for trans in _all_transformations.values()]
    else:
        _enabled_transformations.clear()
        for tid, transformation in _all_transformations.items():
            if tid in enabled_transformation_ids:
                _enabled_transformations.append(transformation(config))

    target_features = {}
    for transformation in _enabled_transformations:
        target_features = target_features | transformation.features

    _added_columns_names = target_features.keys()
    _added_columns_with_types = {k: v for k, v in target_features.items() if not k.startswith("tmp_")}
    _all_columns_with_types = _added_columns_with_types | DomainRecordFlattener.datatypes


def extract_features(raw_data: Iterable[dict]) -> tuple[DataFrame | None, dict[str, Exception]]:
    """
    Extracts features from the raw data by passing it through the transformations enabled in the configuration.

    This function takes an iterable of dictionaries as input, each representing one entry of raw data. It passes the
    raw data through the transformations that have been enabled in the configuration. The `init_transformations`
    function must be called once before this function can be used.

    The function returns a tuple. The first element of the tuple is a DataFrame where each row represents one input
    entry and the columns are the extracted features. The second element of the tuple is a dictionary of exceptions
    that occurred during the feature extraction process.

    Args:
        raw_data (Iterable[dict]): An iterable of dictionaries, each representing one entry of raw data.

    Returns:
        tuple[DataFrame | None, dict[str, Exception]]: A tuple where the first element is a DataFrame of extracted
        features and the second element is a dictionary of exceptions.
    """
    # Flatten each raw record into the column layout the transformations expect
    flattened_records = []
    errors = {}
    for raw_data_entry in raw_data:
        if raw_data_entry is None:
            # Ignore empty entries
            continue
        if raw_data_entry.get("invalid_data"):
            errors[raw_data_entry.get("domain_name", "?")] = ValueError("Invalid data")
            continue
        if len(raw_data_entry.get("domain_name", "")) == 0:
            errors[raw_data_entry.get("domain_name", "?")] = ValueError("Missing domain name")
            continue

        try:
            # Reshape the nested record into flat columns
            flattened_records.append(_record_flattener.flatten(raw_data_entry))
        except Exception as e:
            errors[raw_data_entry.get("domain_name", "?")] = e
    # If all entries were filtered out, return None
    if len(flattened_records) == 0:
        return None, errors
    # Create a DataFrame where each row is one entry from the raw_data iterable
    data_frame = DataFrame(flattened_records, copy=False)
    # Create new columns
    new_cols = DataFrame(columns=_added_columns_names)
    data_frame = pd.concat([data_frame, new_cols], axis=1)
    if data_frame.columns.has_duplicates:
        raise ValueError("Invalid input: after adding the features, the DataFrame contains duplicate columns.")
    # Ensure timezone-aware datetime columns before astype
    datetime_cols = [
        name for name, dtype in _all_columns_with_types.items()
        if isinstance(dtype, str) and "datetime64" in dtype and "UTC" in dtype and name in data_frame.columns
    ]
    if datetime_cols:
        for col in datetime_cols:
            data_frame[col] = pd.to_datetime(data_frame[col], utc=True, errors="coerce")
    # Set correct datatypes
    data_frame = data_frame.astype(_all_columns_with_types, copy=False)
    # Apply the transformations
    for transformation in _enabled_transformations:
        data_frame = transformation.transform(data_frame)
    # Ensure the datatypes for the new columns
    # TODO: evaluate if this is necessary
    data_frame = data_frame.astype(_added_columns_with_types, copy=False)
    # Return the final DataFrame
    return data_frame, errors
