import csv
from io import StringIO
from traceback import format_exc

from url_analyzer.predictors.ns_log import NsLog


class json2csv:
    def __init__(self):
        self.logger = NsLog("log")

    def _write_csv(self, header, rows):
        output = StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)
        return output.getvalue()

    def convert_for_train(self, features, param):
        try:
            features_keys_url = list(features[0]['url_features'].keys())
            features_keys_active = []

            if param == '-a':
                features_keys_active = list(features[0]['active_features'].keys())

            header = features_keys_url + features_keys_active + ["class"]
        except:
            self.logger.debug(
                "Error - sample count received by json_to_csv: " + str(len(features)) +
                "\nurl_feature_keys: " + str(features_keys_url) +
                "\nactive_features_key: " + str(features_keys_active)
            )
            self.logger.error("Error CSV Header : {0}".format(format_exc()))
            return ""

        rows = []
        for each_domain in features:
            try:
                row = [each_domain['url_features'][key] for key in features_keys_url]

                if param == '-a':
                    row.extend(
                        each_domain['active_features'][key_a]
                        for key_a in features_keys_active
                    )

                row.append(each_domain['info']['class'])
                rows.append(row)
            except:
                self.logger.debug("Error in sample converted to CSV:\n" + str(each_domain))
                self.logger.error("Error CSV Body : {0}".format(format_exc()))

        return self._write_csv(header, rows)

    def convert_for_test(self, features, param):
        # TODO: update according to active rules
        try:
            features_keys_url = list(features[0]['url_features'].keys())

            features_keys_dns = []
            if param == '-dns':
                features_keys_dns = list(features[0]['dns_features'].keys())

            header = features_keys_url + features_keys_dns
        except:
            self.logger.error("Error CSV Header : {0}".format(format_exc()))
            return ""

        rows = []
        for each_domain in features:
            row = [each_domain['url_features'][key] for key in features_keys_url]

            if param == '-dns':
                row.extend(
                    each_domain['dns_features'][key_dns]
                    for key_dns in features_keys_dns
                )

            rows.append(row)

        return self._write_csv(header, rows)

    def convert_for_NLP_without_features(self, features):
        try:
            header = ["words", "class"]
            rows = []

            for sample in features:
                words = " ".join(sample['info']['nlp_info']['words_nlp']).strip()
                rows.append([words, sample['info']['class']])
        except:
            self.logger.error("Error CSV Header : {0}".format(format_exc()))
            return ""

        return self._write_csv(header, rows)

    def convert_for_NLP_with_features(self, features):
        try:
            features_keys_url = list(features[0]['url_features'].keys())
            header = ["words"] + features_keys_url + ["class"]
            rows = []

            for sample in features:
                words = " ".join(sample['info']['nlp_info']['words_nlp']).strip()
                row = [words]
                row.extend(sample['url_features'][key] for key in features_keys_url)
                row.append(sample['info']['class'])
                rows.append(row)
        except:
            self.logger.error("Error CSV Header : {0}".format(format_exc()))
            return ""

        return self._write_csv(header, rows)
