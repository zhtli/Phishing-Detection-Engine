"""rdap_ip.py: Feature extraction transformations for RDAP IP data."""
__authors__ = [
    "Ondřej Ondryáš <xondry02@vut.cz>",
    "Radek Hranický <hranicky@fit.vut.cz>",
    "Adam Horák <ihorak@fit.vut.cz>"
]

from pandas import DataFrame

from .base_transformation import Transformation
from ._helpers import get_normalized_entropy


def get_rdap_ip_features(ip_data):
    ip_v4_count = 0
    ip_v6_count = 0

    # Relates to the first IP address where those fields are not empty
    rdap_ip_avg_administrative_name_len = 0
    rdap_ip_avg_administrative_name_entropy = 0
    rdap_ip_avg_administrative_email_len = 0
    rdap_ip_avg_administrative_email_entropy = 0

    rdap_ip_sum_administrative_name_len = 0
    rdap_ip_sum_administrative_name_entropy = 0
    rdap_ip_sum_administrative_email_len = 0
    rdap_ip_sum_administrative_email_entropy = 0

    ip_shortest_v4_prefix_len = 0
    ip_longest_v4_prefix_len = 0
    ip_shortest_v6_prefix_len = 0
    ip_longest_v6_prefix_len = 0

    if ip_data is not None:
        ip_count = len(ip_data)
        for ip in ip_data:
            if ip["rdap"] is not None:
                # Examine IP and network information
                if ip["rdap"]["ip_version"] is not None:
                    ip_version = ip["rdap"]["ip_version"]
                    if ip_version == 4:
                        ip_v4_count += 1
                    else:
                        ip_v6_count += 1

                    if ip["rdap"]["network"] is not None:
                        prefix_len = ip["rdap"]["network"].prefixlen

                        if ip_version == 4:  # IPv4
                            if ip_shortest_v4_prefix_len == 0:
                                ip_shortest_v4_prefix_len = prefix_len
                            if ip_longest_v4_prefix_len == 0:
                                ip_longest_v4_prefix_len = prefix_len
                            if prefix_len < ip_shortest_v4_prefix_len:
                                ip_shortest_v4_prefix_len = prefix_len
                            if prefix_len > ip_longest_v4_prefix_len:
                                ip_longest_v4_prefix_len = prefix_len
                        else:  # IPv6
                            if ip_shortest_v6_prefix_len == 0:
                                ip_shortest_v6_prefix_len = prefix_len
                            if ip_longest_v6_prefix_len == 0:
                                ip_longest_v6_prefix_len = prefix_len
                            if prefix_len < ip_shortest_v6_prefix_len:
                                ip_shortest_v6_prefix_len = prefix_len
                            if prefix_len > ip_longest_v6_prefix_len:
                                ip_longest_v6_prefix_len = prefix_len

                # Examine RDAP entities
                if ip["rdap"]["entities"] is not None and len(ip["rdap"]["entities"]) > 0:
                    if "administrative" in ip["rdap"]["entities"] and ip["rdap"]["entities"][
                        "administrative"] is not None and \
                            len(ip["rdap"]["entities"]["administrative"]) > 0:
                        if "name" in ip["rdap"]["entities"]["administrative"][0] and \
                                ip["rdap"]["entities"]["administrative"][0]["name"] is not None:
                            rdap_ip_sum_administrative_name_len += len(
                                ip["rdap"]["entities"]["administrative"][0]["name"])
                            rdap_ip_sum_administrative_name_entropy += get_normalized_entropy(
                                ip["rdap"]["entities"]["administrative"][0]["name"])
                        if "email" in ip["rdap"]["entities"]["administrative"][0] and \
                                ip["rdap"]["entities"]["administrative"][0]["email"] is not None:
                            rdap_ip_sum_administrative_email_len += len(
                                ip["rdap"]["entities"]["administrative"][0]["email"])
                            rdap_ip_sum_administrative_email_entropy += get_normalized_entropy(
                                ip["rdap"]["entities"]["administrative"][0]["email"])

            if ip_count > 0:
                rdap_ip_avg_administrative_name_len = rdap_ip_sum_administrative_name_len / ip_count
                rdap_ip_avg_administrative_name_entropy = rdap_ip_sum_administrative_name_entropy / ip_count
                rdap_ip_avg_administrative_email_len = rdap_ip_sum_administrative_email_len / ip_count
                rdap_ip_avg_administrative_email_entropy = rdap_ip_sum_administrative_email_entropy / ip_count

    return ip_v4_count, ip_v6_count, \
        ip_shortest_v4_prefix_len, ip_longest_v4_prefix_len, ip_shortest_v6_prefix_len, ip_longest_v6_prefix_len, \
        rdap_ip_avg_administrative_name_len, rdap_ip_avg_administrative_name_entropy, \
        rdap_ip_avg_administrative_email_len, rdap_ip_avg_administrative_email_entropy,


class RDAPAddressTransformation(Transformation):
    def transform(self, df: DataFrame) -> DataFrame:
        df["rdap_ip_v4_count"], df["rdap_ip_v6_count"], \
            df["rdap_ip_shortest_v4_prefix_len"], df["rdap_ip_longest_v4_prefix_len"], \
            df["rdap_ip_shortest_v6_prefix_len"], df["rdap_ip_longest_v6_prefix_len"], \
            df["rdap_ip_avg_admin_name_len"], df["rdap_ip_avg_admin_name_entropy"], \
            df["rdap_ip_avg_admin_email_len"], df["rdap_ip_avg_admin_email_entropy"], \
            = zip(*df["ip_data"].apply(get_rdap_ip_features))

        return df

    @property
    def features(self) -> dict[str, str]:
        return {
            "rdap_ip_v4_count": "Int64", "rdap_ip_v6_count": "Int64",
            "rdap_ip_shortest_v4_prefix_len": "Int64", "rdap_ip_longest_v4_prefix_len": "Int64",
            "rdap_ip_shortest_v6_prefix_len": "Int64", "rdap_ip_longest_v6_prefix_len": "Int64",
            "rdap_ip_avg_admin_name_len": "float64", "rdap_ip_avg_admin_name_entropy": "float64",
            "rdap_ip_avg_admin_email_len": "float64", "rdap_ip_avg_admin_email_entropy": "float64"
        }
