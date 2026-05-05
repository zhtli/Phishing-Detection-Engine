from tqdm import tqdm

from traceback import format_exc

from ns_log import NsLog
from url_rules import url_rules
from active_rules import active_rules
from cert_features import cert_features


class rule_extraction:

    def __init__(self):
        self.logger = NsLog("log")
        self.url_rules_o = url_rules()
        self.active_rules_o = active_rules()
        self.cert_features_o = cert_features()

    def _dataset_feature_defaults(self):
        return {
            "redirect_count": -1,
            "cert_valid": -1,
        }

    def _dataset_features(self, info, url_metadata):
        features = {}
        features.update(self._dataset_feature_defaults())
        features.update(self.cert_features_o.feature_defaults())
        class_label = info.get("class")
        if not class_label:
            print("No class label in info for dataset features")
            return features

        if not url_metadata:
            record = info.get("dataset_meta")
            if not record:
                print("No dataset metadata in info for dataset features")
                return features
        else:
            class_meta = url_metadata.get(class_label)
            if class_meta is None:
                print(f"No metadata found for class '{class_label}' in dataset features")
                return features

            if hasattr(class_meta, "empty") and class_meta.empty:
                print(f"No metadata found for class '{class_label}' in dataset features")
                return features

            url = info.get("url")
            if not url:
                print("No URL in info for dataset features")
                return features

            record = None
            if hasattr(class_meta, "loc"):
                if url in class_meta.index:
                    record = class_meta.loc[url]
            else:
                record = class_meta.get(url)

            if record is None or (isinstance(record, dict) and not record):
                print(f"No record found for URL '{url}' in dataset features")
                return features

        features["redirect_count"] = record.get("redirect_count")
        cert_valid = record.get("cert_valid")
        if cert_valid is None:
            features["cert_valid"] = 0
        elif isinstance(cert_valid, str):
            features["cert_valid"] = 1 if cert_valid.strip().lower() in {"1", "true", "yes"} else 0
        elif isinstance(cert_valid, float) and cert_valid != cert_valid:
            features["cert_valid"] = 0
        else:
            features["cert_valid"] = 1 if bool(cert_valid) else 0

        cert_features = self.cert_features_o.from_cert_file(
            record.get("cert_file"),
            class_label,
        )
        features.update(cert_features)

        return features

    def extraction(self, parsed_domains, url_metadata=None):

        self.logger.info("rule_extraction.extraction() is running")

        domain_features = []
        try:
            for line in tqdm(parsed_domains):
                info = line

                nlp_info, url_features = self.url_rules_o.rules_main(info['domain'],
                                                                     info['tld'],
                                                                     info['subdomain'],
                                                                     info['path'],
                                                                     info['words_raw'])  # where URL rules are applied

                url_features.update(self._dataset_features(info, url_metadata))

                info['nlp_info'] = nlp_info
                info['nlp_info']['words_raw'] = info['words_raw']
                info.pop("words_raw", None)


                outputDict = {}


                outputDict['info'] = info
                outputDict['url_features'] = url_features

                domain_features.append(outputDict)

        except:
            self.logger.error("Error : {0}".format(format_exc()))

        return domain_features
