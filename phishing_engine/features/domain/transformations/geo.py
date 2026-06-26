# Portions of this file are derived from DomainRadar
# (https://github.com/nesfit/domainradar), Copyright (c) 2024 FIT BUT, FIT CTU,
# licensed under BSD-3-Clause. See THIRD_PARTY_NOTICES at the repository root.
"""geo.py: Feature extraction transformations for geolocation data."""
__authors__ = [
    "Ondřej Ondryáš <xondry02@vut.cz>",
    "Radek Hranický <hranicky@fit.vut.cz>",
    "Adam Horák <ihorak@fit.vut.cz>"
]

from pandas import DataFrame

from phishing_engine.features.common.base import Transformation
from phishing_engine.features.common.helpers import get_stddev, get_mean, get_min, get_max

_continents = {
    'North America': [33, 187, 111, 81],
    'South America': [24, 7, 138, 36, 38, 51, 137, 168, 188],
    'Europe': [186, 61, 84, 65, 165, 184, 140, 143, 123, 17, 67, 141, 169, 10, 170, 26, 47, 60, 130, 82, 42,
               158, 100, 159, 94, 56, 101, 107, 77, 109, 108, 114, 99],
    'Africa': [127, 58, 52, 162, 89, 183, 3, 167, 117, 5, 118, 66, 102, 32, 126, 27, 106, 103, 194, 161, 153,
               35, 195, 70, 145, 19, 179, 28, 164, 176, 156, 98, 34, 55, 120, 63, 23, 62, 96, 71, 54, 109,
               48, 39, 87],
    'Asia': [37, 78, 79, 132, 14, 86, 139, 180, 174, 119, 81, 1, 152, 189, 104, 122, 193, 166, 88, 31, 11,
             185, 172, 83, 92, 87, 95, 157, 131, 91, 64, 115, 8, 142, 13, 175, 44, 20, 105],
    'Oceania': [9, 136, 124, 59, 160, 190, 120, 97, 149, 102, 90]
}

_continent_ids = {
    'Unknown': 0,
    'North America': 1,
    'South America': 2,
    'Europe': 3,
    'Africa': 4,
    'Asia': 5,
    'Oceania': 6
}

_country_ids = {'AF': 1, 'AX': 76, 'AL': 2, 'DZ': 3, 'AS': 77, 'AD': 4, 'AO': 5, 'AI': 78, 'AQ': 79, 'AG': 6, 'AR': 7,
                'AM': 8, 'AW': 80, 'AU': 9, 'AT': 10, 'AZ': 11, 'BS': 12, 'BH': 13, 'BD': 14, 'BB': 15, 'BY': 16,
                'BE': 17, 'BZ': 18, 'BJ': 19, 'BM': 81, 'BT': 20, 'BO': 82, 'BQ': 83, 'BA': 22, 'BW': 23, 'BV': 84,
                'BR': 24, 'IO': 85, 'BN': 86, 'BG': 26, 'BF': 27, 'BI': 28, 'KH': 31, 'CM': 32, 'CA': 33, 'CV': 87,
                'KY': 88, 'CF': 34, 'TD': 35, 'CL': 36, 'CN': 37, 'CX': 89, 'CC': 90, 'CO': 38, 'KM': 39, 'CG': 40,
                'CD': 91, 'CK': 92, 'CR': 41, 'CI': 29, 'HR': 42, 'CU': 43, 'CW': 93, 'CY': 44, 'CZ': 45, 'DK': 47,
                'DJ': 48, 'DM': 49, 'DO': 50, 'EC': 51, 'EG': 52, 'SV': 53, 'GQ': 54, 'ER': 55, 'EE': 56, 'ET': 58,
                'FK': 94, 'FO': 95, 'FJ': 59, 'FI': 60, 'FR': 61, 'GF': 96, 'PF': 97, 'TF': 98, 'GA': 62, 'GM': 63,
                'GE': 64, 'DE': 65, 'GH': 66, 'GI': 99, 'GR': 67, 'GL': 100, 'GD': 68, 'GP': 101, 'GU': 102, 'GT': 69,
                'GG': 103, 'GN': 70, 'GW': 71, 'GY': 72, 'HT': 73, 'HM': 104, 'VA': 105, 'HN': 75, 'HK': 106, 'HU': 76,
                'IS': 77, 'IN': 78, 'ID': 79, 'IR': 107, 'IQ': 81, 'IE': 82, 'IM': 108, 'IL': 83, 'IT': 84, 'JM': 85,
                'JP': 86, 'JE': 109, 'JO': 87, 'KZ': 88, 'KE': 89, 'KI': 90, 'KP': 110, 'KR': 111, 'KW': 91, 'KG': 92,
                'LA': 112, 'LV': 94, 'LB': 95, 'LS': 96, 'LR': 97, 'LY': 98, 'LI': 99, 'LT': 100, 'LU': 101, 'MO': 113,
                'MK': 114, 'MG': 102, 'MW': 103, 'MY': 104, 'MV': 105, 'ML': 106, 'MT': 107, 'MH': 108, 'MQ': 115,
                'MR': 109, 'MU': 110, 'YT': 116, 'MX': 111, 'FM': 117, 'MD': 118, 'MC': 114, 'MN': 115, 'ME': 116,
                'MS': 119, 'MA': 117, 'MZ': 118, 'MM': 119, -1: 120, 'NR': 121, 'NP': 122, 'NL': 123, 'NC': 120,
                'NZ': 124, 'NI': 125, 'NE': 126, 'NG': 127, 'NU': 121, 'NF': 122, 'MP': 123, 'NO': 130, 'OM': 131,
                'PK': 132, 'PW': 133, 'PS': 124, 'PA': 135, 'PG': 136, 'PY': 137, 'PE': 138, 'PH': 139, 'PN': 125,
                'PL': 140, 'PT': 141, 'PR': 126, 'QA': 142, 'RE': 127, 'RO': 143, 'RU': 128, 'RW': 145, 'BL': 129,
                'SH': 130, 'KN': 146, 'LC': 147, 'MF': 131, 'PM': 132, 'VC': 148, 'WS': 149, 'SM': 150, 'ST': 151,
                'SA': 152, 'SN': 153, 'RS': 154, 'SC': 155, 'SL': 156, 'SG': 157, 'SX': 133, 'SK': 158, 'SI': 159,
                'SB': 160, 'SO': 161, 'ZA': 162, 'GS': 134, 'SS': 164, 'ES': 165, 'LK': 166, 'SD': 167, 'SR': 168,
                'SJ': 135, 'SZ': 57, 'SE': 169, 'CH': 170, 'SY': 136, 'TW': 137, 'TJ': 172, 'TZ': 138, 'TH': 174,
                'TL': 175, 'TG': 176, 'TK': 139, 'TO': 177, 'TT': 178, 'TN': 179, 'TR': 180, 'TM': 181, 'TC': 140,
                'TV': 182, 'UG': 183, 'UA': 184, 'AE': 185, 'GB': 186, 'US': 187, 'UM': 141, 'UY': 188, 'UZ': 189,
                'VU': 190, 'VE': 142, 'VN': 143, 'VG': 144, 'VI': 145, 'WF': 146, 'EH': 147, 'YE': 193, 'ZM': 194,
                'ZW': 195}

_malicious_domain_top_hosting_countries = [
    187,  # USA
    144,  # Russia
    37,  # China
    24,  # Brazil
    192,  # Vietnam
    184,  # Ukraine
    78,  # India
]


def get_continent_name(country_name):
    for continent, countries in _continents.items():
        if country_name in countries:
            return continent
    return None


def get_continent_id(country_name):
    try:
        continent_name = get_continent_name(country_name)
    except:
        continent_name = "Unknown"

    if continent_name in _continent_ids.keys():
        return _continent_ids[continent_name]
    else:
        return 0


def hash_continents(countries):
    if not countries:
        return 0

    continents_set = set()
    for country_name in countries:
        try:
            continent_id = get_continent_id(country_name)
            continents_set.add(continent_id)
        except:
            continue

    hash = 0
    continent_ids_count = len(_continent_ids)

    for continent_id in continents_set:
        hash += continent_id

        if continent_id > continent_ids_count:
            hash *= 2

    return hash % 2147483647


def get_continent_count(countries):
    if not countries:
        return 0

    continents_set = set()
    for country_name in countries:
        try:
            continent_id = get_continent_id(country_name)
            continents_set.add(continent_id)
        except:
            continue

    return len(continents_set)


def hash_countries(countries):
    if not countries:
        return 0

    country_ids_set = set()
    for country_name in countries:
        country_id = 300  # Unknown
        if country_name in _country_ids:
            country_id = _country_ids[country_name]
        country_ids_set.add(country_id)

    hash = 0
    country_ids_count = len(_country_ids)

    for country_id in country_ids_set:
        hash += country_id

        if hash > country_ids_count:
            hash *= 2

    return hash % 2147483647


def has_malicious_hosting_country(countries):
    if not countries:
        return 0

    for country_name in countries:
        if country_name in _country_ids:
            country_id = _country_ids[country_name]
            if country_id in _malicious_domain_top_hosting_countries:
                return 1

    return 0


class GeoTransformation(Transformation):
    def transform(self, df: DataFrame) -> DataFrame:
        df['geo_countries_count'] = df['countries'].apply(
            lambda countries: len(list(set(countries))) if countries is not None else 0)
        df['geo_continents_count'] = df['countries'].apply(get_continent_count)

        df['geo_malic_host_country'] = df['countries'].apply(has_malicious_hosting_country)

        df['geo_lat_stdev'] = df['latitudes'].apply(get_stddev)
        df['geo_lon_stdev'] = df['longitudes'].apply(get_stddev)
        df['geo_mean_lat'] = df['latitudes'].apply(get_mean)  # Central latitude
        df['geo_mean_lon'] = df['longitudes'].apply(get_mean)  # Central longitude

        df['geo_min_lat'] = df['latitudes'].apply(get_min)
        df['geo_max_lat'] = df['latitudes'].apply(get_max)
        df['geo_min_lon'] = df['longitudes'].apply(get_min)
        df['geo_max_lon'] = df['longitudes'].apply(get_max)

        df['geo_lat_range'] = df.apply(
            lambda row: (row['geo_max_lat'] - row['geo_min_lat']) if row['geo_max_lat'] is not None and row[
                'geo_min_lat'] is not None else 0.0, axis=1)
        df['geo_lon_range'] = df.apply(
            lambda row: (row['geo_max_lon'] - row['geo_min_lon']) if row['geo_max_lon'] is not None and row[
                'geo_min_lon'] is not None else 0.0, axis=1)

        df['geo_centroid_lat'] = df.apply(
            lambda row: (row['geo_min_lat'] + row['geo_max_lat'] / 2) if row['geo_min_lat'] is not None and row[
                'geo_max_lat'] is not None else 0.0, axis=1)
        df['geo_centroid_lon'] = df.apply(
            lambda row: (row['geo_min_lon'] + row['geo_max_lon'] / 2) if row['geo_min_lon'] is not None and row[
                'geo_max_lon'] is not None else 0.0, axis=1)

        df['geo_estimated_area'] = df['geo_lat_range'] * df['geo_lon_range']  # area of the bounding box

        df["geo_continent_hash"] = df["countries"].apply(hash_continents)
        df["geo_countries_hash"] = df["countries"].apply(hash_countries)

        return df

    @property
    def features(self) -> dict[str, str]:
        return {
            'geo_countries_count': "Int64",
            'geo_continents_count': "Int64",
            'geo_malic_host_country': "Int64",
            'geo_lat_stdev': "float64",
            'geo_lon_stdev': "float64",
            'geo_mean_lat': "float64",
            'geo_mean_lon': "float64",
            'geo_min_lat': "float64",
            'geo_max_lat': "float64",
            'geo_min_lon': "float64",
            'geo_max_lon': "float64",
            'geo_lat_range': "float64",
            'geo_lon_range': "float64",
            'geo_centroid_lat': "float64",
            'geo_centroid_lon': "float64",
            'geo_estimated_area': "float64",
            'geo_continent_hash': "Int64",
            'geo_countries_hash': "Int64"
        }
