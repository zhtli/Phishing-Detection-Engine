
import json
import datetime
import os

import pandas as pd

from url_analyzer.predictors.ns_log import NsLog
from url_analyzer.predictors.json2csv import json2csv
from traceback import format_exc
from url_analyzer.predictors.domain_parser import domain_parser
from url_analyzer.predictors.rule_extraction import rule_extraction


class Preprocessing():
    def __init__(self):
        self.logger = NsLog("log")

        self.json2csv_object = json2csv()
        self.parser_object = domain_parser()
        self.rule_calculation = rule_extraction()

        self.dataset_frames = {"legitimate": pd.DataFrame(), "phish": pd.DataFrame()}
        self.url_metadata = {}

        self.path_input = "./input/"
        self.path_csv = "./output/csv/"
        self.path_features = "./output/features/"
        self.path_parsed_domain = "./output/domain_parser/"

        os.makedirs(self.path_csv, exist_ok=True)
        os.makedirs(self.path_features, exist_ok=True)
        os.makedirs(self.path_parsed_domain, exist_ok=True)

    def _resolve_data_dir(self):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        data_dir = os.path.join(base_dir, "data")
        if os.path.isdir(data_dir):
            return data_dir

        fallback_dir = os.path.abspath("data")
        return fallback_dir

    def _list_csv_files(self, dir_path):
        try:
            return sorted(
                os.path.join(dir_path, name)
                for name in os.listdir(dir_path)
                if name.lower().endswith(".csv")
            )
        except FileNotFoundError:
            self.logger.error("Data directory not found: {0}".format(dir_path))
            return []

    def _read_df_from_csv(self, file_path):
        try:
            df = pd.read_csv(file_path)
            if df.empty:
                return pd.DataFrame()
            return df
        except Exception:
            self.logger.error("Error reading dataset file: {0}".format(file_path))
            self.logger.error("Error : {0}".format(format_exc()))

        return pd.DataFrame()

    def _filter_desktop_success(self, df):
        if df.empty or "final_url" not in df.columns:
            return pd.DataFrame()

        filtered = df[(df["user_agent"] == "desktop") & (df["error"].fillna(False) == False)].copy()
        if filtered.empty:
            return filtered

        filtered = filtered[filtered["final_url"].notna()]
        filtered = filtered.drop_duplicates(subset=["final_url"], keep="first")
        return filtered

    def _extract_urls_from_filtered(self, df):
        if df.empty:
            return []

        return df["final_url"].tolist()

    def _build_metadata_map(self, df):
        if df.empty or "final_url" not in df.columns:
            return {}

        keep_cols = [
            "final_url",
            "redirect_count",
            "cert_valid",
            "cert_file",
        ]
        existing_cols = [col for col in keep_cols if col in df.columns]
        meta_df = df[existing_cols].drop_duplicates(subset=["final_url"], keep="first")
        metadata = {}
        for _, row in meta_df.iterrows():
            url = row.get("final_url")
            if not url:
                continue
            metadata[url] = {
                "redirect_count": row.get("redirect_count"),
                "cert_valid": row.get("cert_valid"),
                "cert_file": row.get("cert_file"),
            }

        return metadata

    def _collect_df_from_dir(self, dir_path, label):
        frames = []
        csv_files = self._list_csv_files(dir_path)

        if not csv_files:
            self.logger.debug("No CSV datasets found for {0}: {1}".format(label, dir_path))
            return pd.DataFrame()

        for csv_file in csv_files:
            df = self._read_df_from_csv(csv_file)
            if not df.empty:
                frames.append(df)

        if not frames:
            self.logger.debug("No rows loaded for {0}: {1}".format(label, dir_path))
            return pd.DataFrame()

        combined = pd.concat(frames, ignore_index=True)

        self.logger.info(
            "Collected {0} rows for class '{1}' from {2}".format(len(combined), label, dir_path)
        )
        return combined

    def prepare_parsed_domains(self):
        data_dir = self._resolve_data_dir()
        benign_dir = os.path.join(data_dir, "benign_data")
        phish_dir = os.path.join(data_dir, "phish_data")

        benign_df = self._collect_df_from_dir(benign_dir, "legitimate")
        phish_df = self._collect_df_from_dir(phish_dir, "phish")

        self.dataset_frames["legitimate"] = benign_df
        self.dataset_frames["phish"] = phish_df

        benign_filtered = self._filter_desktop_success(benign_df)
        phish_filtered = self._filter_desktop_success(phish_df)

        benign_urls = self._extract_urls_from_filtered(benign_filtered)
        phish_urls = self._extract_urls_from_filtered(phish_filtered)

        benign_meta = self._build_metadata_map(benign_filtered)
        phish_meta = self._build_metadata_map(phish_filtered)

        parsed_domains = []
        if benign_urls:
            parsed_domains += self.parser_object.parse(
                benign_urls,
                "legitimate",
                len(parsed_domains),
                benign_meta,
            )

        if phish_urls:
            parsed_domains += self.parser_object.parse(
                phish_urls,
                "phish",
                len(parsed_domains),
                phish_meta,
            )

        if not parsed_domains:
            self.logger.debug("No URLs were parsed from data directories.")

        return parsed_domains

    def json_to_file(self, name, path, data):
        time_now = str(datetime.datetime.now())[0:19].replace(" ", "_")
        file_name = name+"_" + time_now + ".txt"
        file = open(path + file_name, "w")
        file.write(json.dumps(data))
        file.close()
        self.logger.info("{0} written to file.".format(name))

    def csv_to_file(self, name, path, data):
        time_now = str(datetime.datetime.now())[0:19].replace(" ", "_")
        file_name = name + "_" + time_now + ".csv"
        file = open(path + file_name, "w")
        file.write(data)
        file.close()

        if name == "csv":
            default_file = open(path + "gsb.csv", "w")
            default_file.write(data)
            default_file.close()

        self.logger.info("{0} written to file.".format(name))


def main():

    """
    Load all CSV datasets under:
    - data/benign_data (labeled legitimate)
    - data/phish_data (labeled phish)

    Parsed domains are passed to rule_calculation for feature extraction,
    and the processed output is converted to CSV format and written to file.
    """

    pp_obj = Preprocessing()
    parsed_domains = pp_obj.prepare_parsed_domains()
    pp_obj.json_to_file("parse", pp_obj.path_parsed_domain, parsed_domains)

    features = pp_obj.rule_calculation.extraction(parsed_domains)
    pp_obj.json_to_file("features", pp_obj.path_features, features)


    csv_str = pp_obj.json2csv_object.convert_for_train(features, '')
    pp_obj.csv_to_file("csv", pp_obj.path_csv, csv_str)


if __name__=="__main__":
    main()
