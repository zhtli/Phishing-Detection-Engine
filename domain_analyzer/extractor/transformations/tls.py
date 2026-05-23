"""tls.py: Feature extraction transformations for TLS data."""
__authors__ = [
    "Ondřej Ondryáš <xondry02@vut.cz>",
    "Radek Hranický <hranicky@fit.vut.cz>",
    "Adam Horák <ihorak@fit.vut.cz>"
]

import datetime

from cryptography import x509
from cryptography.x509 import Certificate, ExtensionNotFound, ObjectIdentifier, Extension
from cryptography.x509.oid import ExtensionOID, NameOID
from pandas import DataFrame, Series
from pandas.errors import OutOfBoundsDatetime

from extractor.transformations.base_transformation import Transformation
from ._helpers import todays_midnight_timestamp, hash_md5

_tls_version_ids = {
    "TLSv1": 0,
    "TLSv1.1": 1,
    "TLSv1.2": 2,
    "TLSv1.3": 3
}

_tls_cipher_ids = {
    'ECDHE-RSA-AES128-GCM-SHA256': 0,
    'TLS_AES_128_GCM_SHA256': 1,
    'TLS_AES_256_GCM_SHA384': 2,
    'ECDHE-ECDSA-CHACHA20-POLY1305': 3,
    'ECDHE-RSA-AES128-SHA': 3,
    'ECDHE-RSA-CHACHA20-POLY1305': 4,
    'ECDHE-RSA-AES256-GCM-SHA384': 5,
    'ECDHE-ECDSA-AES128-GCM-SHA256': 6,
    'TLS_CHACHA20_POLY1305_SHA256': 7,
    'ECDHE-ECDSA-AES256-GCM-SHA384': 8,
    'ECDHE-RSA-AES256-SHA384': 9,
    'AES128-SHA256': 10,
    'DHE-RSA-AES256-GCM-SHA384': 11,
    'AES256-SHA256': 12,
    'AES128-SHA': 13,
    'DHE-RSA-AES128-GCM-SHA256': 14
}


def _cert_is_self_signed(certificate: Certificate):
    try:
        authority_key_identifier = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        subject_key_identifier = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    except ExtensionNotFound:
        return False

    return authority_key_identifier == subject_key_identifier


def _encode_policy(oid: ObjectIdentifier):
    if not oid:
        return 0
    encoded = int(oid.dotted_string.replace('.', ''))
    return encoded % 2147483647


def _make_tls_features(tls_data: dict, collection_date: datetime.datetime):
    row = Series(dtype=object, index=TLSTransformation.all_columns)

    if tls_data is None:
        row["tls_has_tls"] = False
        return row

    # FEATURES
    tls_version_id = _tls_version_ids.get(tls_data['protocol'], 0)
    tls_cipher_id = _tls_cipher_ids.get(tls_data['cipher'], 0)

    # Certificate features #
    common_names = []

    # ROOT CERTIFICATE #
    root_crt_validity_len = -1
    root_crt_lifetime = -1
    # root_crt_time_to_expire = -1

    # LEAF CERTIFICATE #
    leaf_crt_validity_len = -1
    leaf_crt_lifetime = -1
    # leaf_cert_time_to_live = -1

    # BASIC FEATURES #
    mean_cert_len = -1
    broken_chain = 0
    expired_chain = 0

    # EXTENSION FEATURES #
    total_extension_count = -1
    critical_extensions = -1
    any_policy_cnt = 0
    percentage_of_policies = 0
    server_auth = 0
    client_auth = 0
    unknown_policy_cnt = 0
    X_509_used_cnt = 0
    iso_policy_used_cnt = 0
    isoitu_policy_used_cnt = 0
    iso_policy_oid = None
    isoitu_policy_oid = None
    CA_count = 0  # Ration of CA certificates in chain
    CA_ratio = 0
    leaf_cert_organization = ""
    root_cert_organization = ""
    is_self_signed = 0

    # NUMBER OF SUBJECTS if SAN #
    subject_count = 0
    # NUMBER OF SLDs
    unique_SLDs = set()

    # Processing of certificates and root especialy #
    all_certs = tls_data['certificates']
    if len(all_certs) == 0:
        row["tls_has_tls"] = False
        return row

    mean_len = 0
    cert_counter = 0

    cert: Certificate
    for cert in all_certs:
        cert_counter += 1

        # Validity length
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        if valid_from is None or valid_to is None:
            validity_len = None
        else:
            validity_len = int((valid_to - valid_from).total_seconds())
        validity_len = round(int(validity_len) / (60 * 60 * 24))
        if validity_len < 0:
            broken_chain = 1
            break

        # Parse issuer info
        issuer = cert.issuer
        common_name, organization, country = None, None, None
        for attr in issuer:
            if attr.oid == NameOID.COMMON_NAME:
                common_name = attr.value
            elif attr.oid == NameOID.ORGANIZATION_NAME:
                organization = attr.value
            elif attr.oid == NameOID.COUNTRY_NAME:
                country = attr.value

        try:
            lifetime = round((collection_date - valid_from).total_seconds() / (60 * 60 * 24))
        except OutOfBoundsDatetime:
            # print(certificate['validity_start'], collection_date)
            lifetime = -1

        try:
            time_to_expire = round((valid_to - collection_date).total_seconds() / (60 * 60 * 24))
        except OutOfBoundsDatetime:
            # print(certificate['validity_end'], collection_date)
            time_to_expire = -1

        if time_to_expire < 0:
            expired_chain = 1
            break

        if cert_counter == 1:
            # The leaf certificate comes first
            leaf_cert_organization = organization
            leaf_crt_validity_len = validity_len
            leaf_crt_lifetime = lifetime
            # leaf_cert_time_to_live = time_to_expire
            if _cert_is_self_signed(cert):
                is_self_signed = 1
        elif cert_counter == len(all_certs):
            # The root certificate comes last
            root_cert_organization = organization
            root_crt_validity_len = validity_len
            root_crt_lifetime = lifetime
            # root_crt_time_to_expire = time_to_expire

        if common_name is not None:
            common_names.append(common_name)

        mean_len += validity_len
        mean_cert_len = mean_len / cert_counter

        # EXTENSIONS #
        total_extension_count += len(cert.extensions)
        extension: Extension
        for extension in cert.extensions:
            if extension.critical:
                critical_extensions += 1

            if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                subject_count = len(extension.value)

                # count SLDs
                for name in extension.value.get_values_for_type(x509.DNSName):
                    if len(name) >= 2:
                        unique_SLDs.add(name)
            elif extension.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                for usage in extension.value:
                    if usage == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                        server_auth += 1
                    elif usage == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                        client_auth += 1
            elif extension.oid == ExtensionOID.CERTIFICATE_POLICIES:
                any_policy_cnt += 1

                policy: x509.PolicyInformation
                for policy in extension.value:
                    policy_oid = policy.policy_identifier.dotted_string

                    if policy_oid == x509.oid.CertificatePoliciesOID.ANY_POLICY:
                        X_509_used_cnt += 1
                    elif policy_oid.startswith("1."):
                        iso_policy_used_cnt += 1
                    elif policy_oid.startswith("2."):
                        isoitu_policy_used_cnt += 1
                    else:
                        unknown_policy_cnt += 1
            elif extension.oid == ExtensionOID.BASIC_CONSTRAINTS:
                if extension.value.ca:
                    CA_count += 1

    # computation of certificate chain features
    percentage_of_policies = (any_policy_cnt / cert_counter)
    CA_ratio = (CA_count / cert_counter)

    # round float value to 1 decimal place #
    mean_cert_len = round(mean_cert_len, 1)

    # Set the features
    row["tls_has_tls"] = True
    row["tls_chain_len"] = tls_data['count']
    row["tls_is_self_signed"] = is_self_signed
    row["tls_root_authority_hash"] = hash_md5(root_cert_organization or "")
    row["tls_leaf_authority_hash"] = hash_md5(leaf_cert_organization or "")
    row["tls_negotiated_version_id"] = tls_version_id
    row["tls_negotiated_cipher_id"] = tls_cipher_id
    row["tls_root_cert_validity_len"] = root_crt_validity_len
    row["tls_leaf_cert_validity_len"] = leaf_crt_validity_len
    row["tls_broken_chain"] = broken_chain
    row["tls_expired_chain"] = expired_chain
    row["tls_total_extension_count"] = total_extension_count
    row["tls_critical_extensions"] = critical_extensions
    row["tls_with_policies_crt_count"] = any_policy_cnt
    row["tls_percentage_crt_with_policies"] = percentage_of_policies
    row["tls_x509_anypolicy_crt_count"] = X_509_used_cnt
    row["tls_iso_policy_crt_count"] = iso_policy_used_cnt
    row["tls_joint_isoitu_policy_crt_count"] = isoitu_policy_used_cnt
    row["tls_subject_count"] = subject_count
    row["tls_server_auth_crt_count"] = server_auth
    row["tls_client_auth_crt_count"] = client_auth
    row["tls_CA_certs_in_chain_ratio"] = CA_ratio
    row["tls_unique_SLD_count"] = len(unique_SLDs)
    row["tls_common_name_count"] = len(common_names)

    return row


class TLSTransformation(Transformation):
    _col_names = {
        "tls_has_tls": "bool",  # Has TLS  # FIXME
        "tls_chain_len": "Int64",  # Length of certificate chain
        "tls_is_self_signed": "Int64",  # Is self-signed  # FIXME
        "tls_root_authority_hash": "Int64",  # Hash of root certificate authority
        "tls_leaf_authority_hash": "Int64",  # Hash of leaf certificate authority
        "tls_negotiated_version_id": "Int64",  # Evaluated TLS version
        "tls_negotiated_cipher_id": "Int64",  # Evaluated cipher
        "tls_root_cert_validity_len": "float64",  # Total validity time of root certificate
        # NOTUSED # "tls_root_cert_lifetime": "Int64",  # How long was the root certificate valid at the time of collection
        # NOTUSED # "tls_root_cert_validity_remaining": "Int64",  # Time to expire of root certificate from time of collection
        "tls_leaf_cert_validity_len": "float64",  # Total validity time of leaf certificate
        # NOTUSED # "tls_leaf_cert_lifetime": "Int64",  # How long was the leaf certificate valid at the time of collection
        # NOTUSED # "tls_leaf_cert_validity_remaining": "Int64",  # Time to expire of leaf certificate from time of collection
        # NOTUSED # "tls_mean_certs_validity_len": "Int64",  # Mean validity time of all certificates in chain including root
        "tls_broken_chain": "Int64",  # Chain was never valid: "Int64",  # FIXME
        "tls_expired_chain": "Int64",  # Chain already expired at time of collection  # FIXME
        "tls_total_extension_count": "Int64",  # Total number of extensions in certificate
        "tls_critical_extensions": "Int64",  # Total number of critical extensions in certificate
        "tls_with_policies_crt_count": "Int64",  # Number of certificates enforcing specific encryption policy
        # Percentage of certificates enforcing specific encryption policy
        "tls_percentage_crt_with_policies": "float64",
        "tls_x509_anypolicy_crt_count": "Int64",  # Number of certificates enforcing X509 - ANY policy
        # Number of certificates supporting Joint ISO-ITU-T policy (OID root is 1)
        "tls_iso_policy_crt_count": "Int64",
        # Number of certificates supporting Joint ISO-ITU-T policy (OID root is 2)
        "tls_joint_isoitu_policy_crt_count": "Int64",
        # NOTUSED # "tls_iso_policy_oid": "Int64",  # OID of ISO policy (if any or 0)
        # NOTUSED # "tls_isoitu_policy_oid": "Int64",  # OID of ISO/ITU policy (if any or 0)
        # NOTUSED # "tls_unknown_policy_crt_count": "Int64",  # How many certificates uses unknown (not X509v3: "Int64", not version 1: "Int64", not version 2) policy
        "tls_subject_count": "Int64",  # How many subjects can be found in SAN extension (can be linked to phishing)
        # How many certificates are used for server authentication
        "tls_server_auth_crt_count": "Int64",
        "tls_client_auth_crt_count": "Int64",  # How many certificates are used for client authentication
        # NOTUSED # "CA_certs_in_chain_count": "Int64",  # Count of CA certificates (can sign other certificates)
        "tls_CA_certs_in_chain_ratio": "float64",  # Ration of CA certificates in chain
        "tls_unique_SLD_count": "Int64",  # Number of unique SLDs in SAN extension
        # NOTUSED # "tls_common_names": "Int64",  # List of common names in certificate chain (CATEGORICAL!)
        "tls_common_name_count": "Int64",  # Number of common names in certificate chain
    }
    all_columns = list(_col_names.keys())

    def transform(self, df: DataFrame) -> DataFrame:
        date = todays_midnight_timestamp()
        df[TLSTransformation.all_columns] = df["tls"].apply(_make_tls_features, args=(date,))
        return df

    @property
    def features(self) -> dict[str, str]:
        return TLSTransformation._col_names
