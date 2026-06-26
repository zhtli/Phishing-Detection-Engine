# Portions of this file are derived from DomainRadar
# (https://github.com/nesfit/domainradar), Copyright (c) 2024 FIT BUT, FIT CTU,
# licensed under BSD-3-Clause. See THIRD_PARTY_NOTICES at the repository root.
"""drop_columns.py: A transformation that drops columns from the DataFrame that should not be
a part of the feature vector."""
__author__ = "Ondřej Ondryáš <xondry02@vut.cz>"

from pandas import DataFrame

from phishing_engine.features.common.base import Transformation

_to_drop = [
    "dns_zone",
    "dns_evaluated_on",
    "dns_email_extras",
    "dns_ttls",
    "dns_SOA",
    "dns_zone_SOA",
    "dns_A",
    "dns_AAAA",
    "dns_CNAME",
    "dns_MX",
    "dns_NS",
    "dns_TXT",
    "rdap_entities",
    "rdap_expiration_date",
    "rdap_last_changed_date",
    "rdap_registration_date",
    "rdap_evaluated_on",
    "rdap_dnssec",
    "ip_data",
    "countries",
    "latitudes",
    "longitudes"
]


class DropColumnsTransformation(Transformation):
    def transform(self, df: DataFrame) -> DataFrame:
        df.drop(columns=_to_drop, errors='ignore', inplace=True)
        return df

    @property
    def features(self) -> dict[str, str]:
        return {}
