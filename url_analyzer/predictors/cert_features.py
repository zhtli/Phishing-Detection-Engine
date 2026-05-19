import os
import re
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from predictors.ns_log import NsLog


class cert_features:
    def __init__(self, data_dir=None):
        self.logger = NsLog("log")
        self.data_dir = data_dir or self._resolve_data_dir()
        self.cert_dirs = {
            "legitimate": os.path.join(self.data_dir, "benign_data", "CERT"),
            "phish": os.path.join(self.data_dir, "phish_data", "CERT"),
        }
        self.pem_re = re.compile(
            br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            flags=re.DOTALL,
        )

    def _resolve_data_dir(self):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        data_dir = os.path.join(base_dir, "data")
        if os.path.isdir(data_dir):
            return data_dir

        fallback_dir = os.path.abspath("data")
        return fallback_dir

    def feature_defaults(self):
        return {
            "cert_validity_days": -1,
            "cert_san_total": -1,
            "cert_san_dns": -1,
            "cert_validation_type": -1,
        }

    def _get_san_counts(self, cert):
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            return -1, -1

        names = ext.value
        dns = names.get_values_for_type(x509.DNSName)
        ip = names.get_values_for_type(x509.IPAddress)
        email = names.get_values_for_type(x509.RFC822Name)
        uri = names.get_values_for_type(x509.UniformResourceIdentifier)
        return len(dns) + len(ip) + len(email) + len(uri), len(dns)

    def _extract_policy_oids(self, cert):
        try:
            ext = cert.extensions.get_extension_for_class(x509.CertificatePolicies)
        except x509.ExtensionNotFound:
            return []
        return [policy.policy_identifier.dotted_string for policy in ext.value]

    def _classify_validation_type(self, cert):
        policy_oids = self._extract_policy_oids(cert)
        if "2.23.140.1.1" in policy_oids:
            return 2 # EV
        if "2.23.140.1.2.2" in policy_oids:
            return 1 # OV
        if "2.23.140.1.2.1" in policy_oids:
            return 0 # DV

        subject = cert.subject
        has_org = bool(subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME))
        has_jurisdiction = bool(
            subject.get_attributes_for_oid(NameOID.JURISDICTION_COUNTRY_NAME)
            or subject.get_attributes_for_oid(NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME)
            or subject.get_attributes_for_oid(NameOID.JURISDICTION_LOCALITY_NAME)
        )
        if has_jurisdiction:
            return 2 # EV
        if has_org:
            return 1 # OV
        return 0 # DV

    def from_cert_file(self, cert_file, class_label):
        features = self.feature_defaults()
        if not cert_file:
            return features

        cert_dir = self.cert_dirs.get(class_label)
        if not cert_dir:
            return features

        path = Path(cert_dir) / str(cert_file)
        return self.from_cert_path(path)

    def from_cert_path(self, cert_path):
        features = self.feature_defaults()
        if not cert_path:
            return features

        path = Path(cert_path)
        if not path.exists():
            return features

        cert = x509.load_pem_x509_certificate(path.read_bytes())

        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        if nb and na:
            features["cert_validity_days"] = (na - nb).days

        san_total, san_dns = self._get_san_counts(cert)
        features["cert_san_total"] = san_total
        features["cert_san_dns"] = san_dns

        features["cert_validation_type"] = self._classify_validation_type(cert)

        return features

    def from_pem_string(self, cert_pem):
        features = self.feature_defaults()
        if not cert_pem:
            return features

        cert_bytes = cert_pem if isinstance(cert_pem, (bytes, bytearray)) else str(cert_pem).encode("utf-8")
        cert = x509.load_pem_x509_certificate(cert_bytes)

        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        if nb and na:
            features["cert_validity_days"] = (na - nb).days

        san_total, san_dns = self._get_san_counts(cert)
        features["cert_san_total"] = san_total
        features["cert_san_dns"] = san_dns

        features["cert_validation_type"] = self._classify_validation_type(cert)

        return features
