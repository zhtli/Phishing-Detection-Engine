"""rdap_dn.py: Feature extraction transformations for RDAP domain data."""
__authors__ = [
    "Ondřej Ondryáš <xondry02@vut.cz>",
    "Radek Hranický <hranicky@fit.vut.cz>",
    "Adam Horák <ihorak@fit.vut.cz>"
]

from pandas import DataFrame
import pandas as pd

from .base_transformation import Transformation
from ._helpers import get_normalized_entropy, simhash, todays_midnight_timestamp


def _get_rdap_domain_features(rdap_entities):
    registrar_name_len = 0
    registrar_name_entropy = 0
    registrar_name_hash = 0

    registrant_name_len = 0
    registrant_name_entropy = 0

    administrative_name_len = 0
    administrative_name_entropy = 0

    administrative_email_len = 0
    administrative_email_entropy = 0

    if rdap_entities is not None:
        if "registrar" in rdap_entities and rdap_entities["registrar"] is not None and len(
                rdap_entities["registrar"]) > 0:
            if "name" in rdap_entities["registrar"][0] and rdap_entities["registrar"][0]["name"] is not None:
                registrar_name_len = len(rdap_entities["registrar"][0]["name"])
                registrar_name_entropy = get_normalized_entropy(rdap_entities["registrar"][0]["name"])
                registrar_name_hash = simhash(
                    rdap_entities["registrar"][0]["name"])  # Makes sense due more than in registrant

        if "registrant" in rdap_entities and rdap_entities["registrant"] is not None and len(
                rdap_entities["registrant"]) > 0:
            if "name" in rdap_entities["registrant"][0] and rdap_entities["registrant"][0]["name"] is not None:
                registrant_name_len = len(rdap_entities["registrant"][0]["name"])
                registrant_name_entropy = administrative_email_entropy = get_normalized_entropy(
                    rdap_entities["registrant"][0]["name"])

        if "administrative" in rdap_entities and rdap_entities["administrative"] is not None and len(
                rdap_entities["administrative"]) > 0:
            if "name" in rdap_entities["administrative"][0] \
                    and rdap_entities["administrative"][0]["name"] is not None:
                administrative_name_len = len(rdap_entities["administrative"][0]["name"])
                administrative_name_entropy = get_normalized_entropy(rdap_entities["administrative"][0]["name"])
            if "email" in rdap_entities["administrative"][0] \
                    and rdap_entities["administrative"][0]["email"] is not None:
                administrative_email_len = len(rdap_entities["administrative"][0]["email"])
                administrative_email_entropy = get_normalized_entropy(rdap_entities["administrative"][0]["email"])

    return registrar_name_len, registrar_name_entropy, registrar_name_hash, registrant_name_len, registrant_name_entropy, \
        administrative_name_len, administrative_name_entropy, \
        administrative_email_len, administrative_email_entropy


class RDAPDomainTransformation(Transformation):
    def transform(self, df: DataFrame) -> DataFrame:
        extraction_ts = todays_midnight_timestamp()
        day_sec = 60 * 60 * 24

        registration_period = df['rdap_expiration_date'] - df['rdap_registration_date']
        registration_period_days = registration_period.dt.total_seconds() / day_sec
        df['rdap_registration_period'] = registration_period_days.where(
            registration_period_days.isna(),
            registration_period_days.clip(lower=0)
        )

        def _compute_time_feats(row):
            reg = row['rdap_registration_date']
            last = row['rdap_last_changed_date']
            exp = row['rdap_expiration_date']

            if pd.isna(reg):
                age = pd.NA
                active_time = pd.NA
            else:
                age = max(0, (extraction_ts - reg).total_seconds() / day_sec)
                active_end = extraction_ts if pd.isna(exp) or exp > extraction_ts else exp
                active_time = max(0, (active_end - reg).total_seconds() / day_sec)

            if pd.isna(last):
                last_change = pd.NA
            else:
                last_change = max(0, (extraction_ts - last).total_seconds() / day_sec)

            return pd.Series({
                'rdap_domain_age': age,
                'rdap_time_from_last_change': last_change,
                'rdap_domain_active_time': active_time
            })

        df[['rdap_domain_age', 'rdap_time_from_last_change', 'rdap_domain_active_time']] = df.apply(
            _compute_time_feats, axis=1
        )

        df["rdap_has_dnssec"] = df["rdap_dnssec"].astype("bool")
        df["rdap_registrar_name_len"], df["rdap_registrar_name_entropy"], df["rdap_registrar_name_hash"], \
            df["rdap_registrant_name_len"], df["rdap_registrant_name_entropy"], \
            df["rdap_admin_name_len"], df["rdap_admin_name_entropy"], \
            df["rdap_admin_email_len"], df["rdap_admin_email_entropy"] = zip(
            *df["rdap_entities"].apply(_get_rdap_domain_features)
        )

        return df

    @property
    def features(self) -> dict[str, str]:
        return {
            "rdap_registration_period": "Float64",
            "rdap_domain_age": "Float64",
            "rdap_time_from_last_change": "Float64",
            "rdap_domain_active_time": "Float64",
            "rdap_has_dnssec": "bool",
            "rdap_registrar_name_len": "Int64",
            "rdap_registrar_name_entropy": "Float64",
            "rdap_registrar_name_hash": "Int64",
            "rdap_registrant_name_len": "Int64",
            "rdap_registrant_name_entropy": "Float64",
            "rdap_admin_name_len": "Int64",
            "rdap_admin_name_entropy": "Float64",
            "rdap_admin_email_len": "Int64",
            "rdap_admin_email_entropy": "Float64"
        }
