
import csv
import json
import datetime
import numpy as np
import os

from io import StringIO
from traceback import format_exc

from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from predictors.domain_parser import domain_parser
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score

from predictors.ns_log import NsLog
from predictors.json2csv import json2csv
from predictors.rule_extraction import rule_extraction


class machine_learning_algorithm():

    def __init__(self, algorithm, train_data_name="gsb.csv"):

        self.logger = NsLog("log")

        self.path_output_csv = "./output/csv/"
        self.path_test_output = ""
        os.makedirs("./output/test-output/", exist_ok=True)

        self.json2csv_object = json2csv()
        self.parser_object = domain_parser()
        self.train_data_name = train_data_name
        self.rule_calculation = rule_extraction()

        self.time_now = str(datetime.datetime.now())[0:19].replace(" ", "_")

        if algorithm == 'NB':
            self.model = self.create_model_NB()
        elif algorithm == 'RF':
            self.model = self.create_model_RF()
        elif algorithm == 'DT':
            self.model = self.create_model_DT()
        elif algorithm == 'KNN':
            self.model = self.create_model_KNN()

    def __txt_to_list(self, txt_object):

        lst = []

        for line in txt_object:
            lst.append(line.strip())

        txt_object.close()

        return lst

    def _read_csv_dataset(self, file_obj, has_class):

        reader = csv.DictReader(file_obj)
        if not reader.fieldnames:
            return np.asarray([], dtype=np.float32), np.array([])

        fieldnames = list(reader.fieldnames)
        label_col = None
        feature_cols = fieldnames

        if has_class:
            label_col = "class" if "class" in fieldnames else fieldnames[-1]
            feature_cols = [name for name in fieldnames if name != label_col]

        data = []
        labels = []

        for row in reader:
            data.append([float(row[name]) for name in feature_cols])
            if has_class:
                labels.append(row[label_col])

        return np.asarray(data, dtype=np.float32), np.array(labels)

    def preparing_train_data(self, file_name="gsb.csv"):

        train = []
        target = []

        try:
            with open("{0}{1}".format(self.path_output_csv, file_name), "r", newline="") as csv_file:
                train, target = self._read_csv_dataset(csv_file, has_class=True)

            target = np.array([str(t) for t in target])
        except:
            self.logger.debug(file_name + " caused an error during training")
            self.logger.error("Error : {0}".format(format_exc()))

        return train, target

    def preparing_test_data(self, test_dataset_list):

        try:
            feat_json = open("./output/test-output/json-" + self.time_now + ".txt", "w")
            feat_csv = open("./output/test-output/csv-" + self.time_now + ".csv", "w")

            "domain_parsed to json without class"
            self.test_parsed_domains = self.parser_object.parse_nonlabeled_samples(test_dataset_list)

            "rule calculation for test samples without class information -- output json format"
            test_features = self.rule_calculation.extraction(self.test_parsed_domains)

            "Convert generated test JSON samples to CSV. No class label included."
            csv_test_str = self.json2csv_object.convert_for_test(test_features, '')

           # feat_json.write(json.dumps(test_features))
            feat_csv.write(csv_test_str)

            feat_csv.close()
            feat_json.close()

            csv_raw = StringIO(csv_test_str)
            test, _ = self._read_csv_dataset(csv_raw, has_class=False)
        except:
            self.logger.error("Error while preparing test data / Error : {0}".format(format_exc()))

        return test, self.test_parsed_domains

    def create_model_NB(self):

        train, target = self.preparing_train_data()
        gnb = GaussianNB()
        model = gnb.fit(train, target)

        return model

    def create_model_RF(self):
        train, target = self.preparing_train_data()
        clf = RandomForestClassifier(n_estimators=10, random_state=0, verbose=1)
        model = clf.fit(train, target)

        return model

    def create_model_DT(self):
        train, target = self.preparing_train_data()
        clf = DecisionTreeClassifier(random_state=0)
        model = clf.fit(train, target)
        return model

    def create_model_KNN(self):
        train, target = self.preparing_train_data()
        clf = KNeighborsClassifier(n_neighbors=3)
        model = clf.fit(train, target)
        return model

    def model_run(self, test):

        model = self.model

        model_pre = model.predict(test)
        model_probability = model.predict_proba(test)

        model_pre_list = []
        for p in model_pre:
            model_pre_list.append(str(p).replace("b'", "").replace("'", ""))

        model_probability = model_probability.tolist()

        return model_pre_list, model_probability

    def output(self, test_data):

        test, test_parsed_domains = self.preparing_test_data(test_data)
        model_pre, model_probability = self.model_run(test)

        test_parsed_domain = self.test_parsed_domains
        result_list = []

        for test_domain in test_parsed_domain:
            result = {}
            result['domain'] = test_domain['url']
            result['id'] = test_domain['id']
            result['predicted_class'] = model_pre[test_domain['id']]
            result['probability_phish'] = (model_probability[test_domain['id']][1] / sum(model_probability[test_domain['id']])) * 100
            result['probability_legitimate'] = (model_probability[test_domain['id']][0] / sum(model_probability[test_domain['id']])) * 100
            result_list.append(result)

        test_result = open("./output/test-output/result-"+self.time_now+".txt", "w")
        test_result.write(json.dumps(result_list))
        test_result.close()

        return result_list

    def accuracy(self):
        model = self.model
        test_data, test_label = self.preparing_train_data()
        scores = cross_val_score(model, test_data, test_label, cv=10)
        return scores

    def confusion_matrix(self, name):
        """
        The model is trained with gsb.csv by default.
        The dataset for which we want to generate the confusion matrix is
        read in CSV format via preparing_train_data.
        The loaded file is split into data and labels.
        Data is evaluated by the model.
        Predicted labels are stored in model_pre.

        test_label is converted from bytes array format to unicode strings.

        Then confusion matrix is computed.
        :param name: 
        :return: 
        """

        test, test_label = self.preparing_train_data(file_name=name)
        model_pre, model_pro = self.model_run(test)

        test_label_unicode = []

        for t in test_label:
            test_label_unicode.append(t.decode('utf-8') if isinstance(t, (bytes, bytearray)) else str(t))

        return confusion_matrix(test_label_unicode, model_pre, labels=['phish', 'legitimate'])

