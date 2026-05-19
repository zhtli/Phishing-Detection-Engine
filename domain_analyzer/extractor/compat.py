"""compat.py: A compatibility transformation that converts the raw data collected by the DomainRadar Collector
into a format that can be used by the "legacy" transformations."""
__author__ = "Ondřej Ondryáš <xondry02@vut.cz>"

import ipaddress
from datetime import datetime, UTC

from util import get_safe

class CompatibilityTransformation:
    datatypes = {
        "domain_name": "str",
        "dns_email_extras": "object",
        "dns_ttls": "object",
        "dns_zone": "str",
        "dns_SOA": "object",
        "dns_zone_SOA": "object",
        "dns_A": "object",
        "dns_AAAA": "object",
        "dns_TXT": "object",
        "dns_NS": "object",
        "dns_MX": "object",
        "dns_CNAME": "object",
        "dns_has_dnskey": "Int64",
        "dns_evaluated_on": "datetime64[ms, UTC]",
        "rdap_evaluated_on": "datetime64[ms, UTC]",
        "rdap_registration_date": "datetime64[ms, UTC]",
        "rdap_expiration_date": "datetime64[ms, UTC]",
        "rdap_last_changed_date": "datetime64[ms, UTC]",
        "rdap_dnssec": "object",
        "rdap_entities": "object",
        "ip_data": "object",
        "countries": "object",
        "latitudes": "object",
        "longitudes": "object"
    }


    def transform(self, data: dict) -> dict:
        dns_data = data.get("dns") or {}
        rdap_data = data.get("rdap") or {}

        ip_data = self._make_ip_data(data)
        country_codes, latitudes, longitudes = self._flatten_ip_data(ip_data)

        reg_date = self._ensure_utc_datetime(rdap_data.get("registration_date"))
        exp_date = self._ensure_utc_datetime(rdap_data.get("expiration_date"))
        last_changed_date = self._ensure_utc_datetime(get_safe(rdap_data, "last_changed_date"))

        dns_zone = get_safe(data, "dns.remarks.zone")
        dns_has_dnskey = get_safe(data, "dns.remarks.has_dnskey")

        dns_cname = get_safe(dns_data, "CNAME.value")
        if dns_cname is None and isinstance(dns_data.get("CNAME"), str):
            dns_cname = dns_data.get("CNAME")

        res = {
            "domain_name": data.get("domain_name", ""),
            "dns_email_extras": self._make_email_extras(data),
            "dns_ttls": dns_data.get("ttls", None),
            "dns_zone": dns_zone,
            "dns_SOA": dns_data.get("SOA"),
            "dns_zone_SOA": dns_data.get("zone_SOA"),
            "dns_A": dns_data.get("A", None),
            "dns_AAAA": dns_data.get("AAAA", None),
            "dns_TXT": dns_data.get("TXT", None),
            "dns_NS": self._make_ns(dns_data),
            "dns_MX": self._make_mx(dns_data),
            "dns_CNAME": dns_cname,
            "dns_has_dnskey": 1 if dns_has_dnskey else 0,
            "dns_evaluated_on": get_safe(data, "remarks.dns_evaluated_on"),
            "rdap_evaluated_on": get_safe(data, "remarks.rdap_evaluated_on"),
            "rdap_registration_date": reg_date,
            "rdap_expiration_date": exp_date,
            "rdap_last_changed_date": last_changed_date,
            "rdap_dnssec": rdap_data.get("dnssec", None),
            "rdap_entities": rdap_data.get("entities"),
            "ip_data": ip_data,
            "countries": country_codes,
            "latitudes": latitudes,
            "longitudes": longitudes
        }

        return res

    @staticmethod
    def _flatten_ip_data(ip_data: list):
        """
        Flattens the IP data by extracting country codes, latitudes, and longitudes.

        This method takes a list of IP data dictionaries as input. Each dictionary is expected to have a 'geo' key
        containing a dictionary with 'country_code', 'latitude', and 'longitude' keys. The method iterates over the list
        and appends the values of these keys to respective lists. If the 'geo' key is not present or its value is None,
        the IP data dictionary is skipped.

        Args:
            ip_data (list): A list of dictionaries containing IP data.

        Returns:
            tuple: A tuple containing three lists - country codes, latitudes, and longitudes extracted from the IP data.
        """
        country_codes = []
        latitudes = []
        longitudes = []

        for ip in ip_data:
            if ip["geo"] is None:
                continue
            country_codes.append(ip['geo']['country_code'])
            latitudes.append(ip['geo']['latitude'])
            longitudes.append(ip['geo']['longitude'])

        return country_codes, latitudes, longitudes

    @staticmethod
    def _make_email_extras(data: dict) -> dict:
        """
        Extracts and returns the presence of SPF, DKIM, and DMARC records from the DNS TXT records.

        This method takes a dictionary of raw data as input and checks the DNS TXT records for the presence of SPF,
        DKIM, and DMARC records. It returns a dictionary with boolean values indicating the presence of these records.

        Args:
            data (dict): A dictionary containing the raw data collected by the DomainRadar collector.

        Returns:
            dict: A dictionary with keys 'spf', 'dkim', and 'dmarc'. The values are boolean indicating the presence of
            the respective records in the DNS TXT records.
        """
        ret = {
            "spf": False,
            "dkim": False,
            "dmarc": False
        }

        dns_remarks = get_safe(data, "dns.remarks") or {}
        if "has_spf" in dns_remarks:
            ret["spf"] = bool(dns_remarks.get("has_spf"))
        if "has_dkim" in dns_remarks:
            ret["dkim"] = bool(dns_remarks.get("has_dkim"))
        if "has_dmarc" in dns_remarks:
            ret["dmarc"] = bool(dns_remarks.get("has_dmarc"))

        return ret

    @staticmethod
    def _make_ns(dns_data: dict) -> list | None:
        ns = dns_data.get("NS")
        if ns is None:
            return None
        if isinstance(ns, dict):
            return list(ns.keys())

        return None

    @staticmethod
    def _make_mx(dns_data: dict) -> list | None:
        mx = dns_data.get("MX")
        if mx is None:
            return None
        if isinstance(mx, dict):
            res = []
            for name, info in mx.items():
                if info is None:
                    continue
                res.append({"name": name, "priority": info.get("priority")})
            return res

        return None


    @staticmethod
    def _ensure_utc_datetime(dt: datetime | None) -> datetime | None:
        """
        Ensures that the provided datetime object is timezone-aware and in UTC.

        This method takes a datetime object as input and returns a datetime object that is timezone-aware and in UTC.
        If the input datetime object is naive (i.e., not timezone-aware), it is assumed to be in UTC.
        If the input datetime object is already timezone-aware, it is converted to UTC.

        Args:
            dt (datetime | None): The input datetime object. If None, None is returned.

        Returns:
            datetime | None: The input datetime object converted to a timezone-aware datetime object in UTC.
            If the input was None, None is returned.
        """
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)

    @staticmethod
    def _make_ip_average_rtt(results_for_ip: dict) -> float:
        """
        Calculates the average round-trip time (RTT) for the IP addresses related to a domain name.

        If an IP result does not have the 'average_rtt' key or if the key's value is not a number, the result is not
        included in the calculation. If none of the IP results have the 'average_rtt' key, the method returns 0.0.

        Args:
            results_for_ip (dict): A dictionary containing the results from the IP-based collectors.

        Returns:
            float: The average round-trip time (RTT) for the IP address.
        """
        count = 0
        total = 0
        for collector, results in results_for_ip.items():
            if collector.startswith("rtt") and results["statusCode"] == 0:
                data = results.get("data", {})
                col_count = data.get("received", 0)
                count += col_count
                total += data.get("avg", 0) * col_count

        return total / count if count > 0 else 0.0

    def _make_ip_data(self, data: dict) -> list[dict]:
        """
        Extracts and formats the IP data from the raw data.

        This method takes a dictionary of raw data as input and extracts the IP data. The IP data includes information
        about the IP address, the record from which it was obtained, ASN details, RDAP details, geolocation details,
        average round-trip time (RTT), and NERD reputation.

        The method returns a list of dictionaries, each representing an IP address and its associated data. If the IP
        data is not present in the raw data, an empty list is returned.

        Args:
            data (dict): A dictionary containing the raw data collected by the DomainRadar collector.

        Returns:
            list[dict]: A list of dictionaries representing the IP data. Each dictionary contains the IP address and its
            associated data, including ASN details, RDAP details, geolocation details, average RTT, and NERD reputation.
        """

        schema_ip_data = data.get("ip_data")
        if not isinstance(schema_ip_data, list):
            return []

        ret = []
        for ip_entry in schema_ip_data:
            if not isinstance(ip_entry, dict):
                continue

            ip_value = ip_entry.get("ip")
            if not ip_value:
                continue

            asn = ip_entry.get("asn")
            rdap = ip_entry.get("rdap")
            if isinstance(rdap, dict):
                network = rdap.get("network")
                if isinstance(network, dict):
                    addr = network.get("network_address")
                    prefix_len = network.get("prefix_length")
                    if addr and prefix_len is not None:
                        try:
                            rdap = dict(rdap)
                            if addr.startswith("/"):
                                addr = addr[1:]
                            rdap["network"] = ipaddress.ip_network(
                                f"{addr}/{prefix_len}", strict=False)
                        except ValueError:
                            rdap = dict(rdap)
                            rdap["network"] = None
                    else:
                        rdap = dict(rdap)
                        rdap["network"] = None
                ip_version = rdap.get("ip_version")
                if isinstance(ip_version, str) and ip_version.isdigit():
                    rdap["ip_version"] = int(ip_version)

            average_rtt = get_safe(ip_entry, "remarks.average_rtt")
            if average_rtt is None:
                average_rtt = 0.0

            ret.append({
                "ip": ip_value,
                "from_record": ip_entry.get("from_record"),
                "asn": asn if asn else None,
                "rdap": rdap if rdap else None,
                "geo": ip_entry.get("geo"),
                "average_rtt": average_rtt,
                "nerd_rep": ip_entry.get("nerd_rep") or -1
            })

        return ret