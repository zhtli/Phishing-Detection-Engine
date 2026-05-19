
import re
import pprint
import enchant
from traceback import format_exc
from predictors.ns_log import NsLog


class WordSplitterClass(object):

    def __init__(self):
        self.logger = NsLog("log")
        self.path_data = "./input/"
        self.name_brand_file = "allbrands.txt"
        self.dictionary_en = enchant.DictWithPWL("en_US", "{0}{1}".format(self.path_data, self.name_brand_file))
        #self.__file_capitalize(self.path_data, self.name_brand_file)

        self.pp = pprint.PrettyPrinter(indent=4)

    # Public wrappers kept for backward compatibility with existing callers.
    def split(self, gt7_word_list):
        return self._split(gt7_word_list)

    def splitl(self, gt7_word_list):
        return self._splitl(gt7_word_list)

    def splitw(self, word):
        return self._splitw(word)

    def _split(self, gt7_word_list):

        return_word_list = []

        for word in gt7_word_list:
            try:
                ss = {'raw': word,'splitted':[]}

                # Remove digits if present in the word.
                word = re.sub(r"\d+", "", word)
                sub_words = []

                if not self.dictionary_en.check(word):
                    # If the word is in the dictionary, return it directly.
                    # If not, continue with word splitting.

                    for number in range(len(word), 3, -1): # generate sub-words with length > 3
                        for l in range(0, len(word) - number + 1):
                            if self.dictionary_en.check(self.__capitalize(word[l:l + number])):

                                # Replace detected word with '*' so it does not cause false positives
                                # while detecting the remaining parts.
                                w = self.__check_last_char(word[l:l + number])
                                sub_words.append(w)
                                word = word.replace(w, "*" * len(w))

                    rest = max(re.split(r"\*+", word), key=len)
                    if len(rest) > 3:
                        sub_words.append(rest)

                    split_w = sub_words

                    for l in split_w:
                        for w in reversed(split_w):

                            """
                            If one detected word appears inside another larger detected word,
                            it is treated as a false positive and removed.
                            Example: secure, cure -> remove cure.
                            """

                            if l != w:  # todo edit distance eklenecek
                                if l.find(w) != -1 or l.find(w.lower()) != -1:
                                    sub_words.remove(w)

                    if len(sub_words) == 0:
                        # If no word is found, return the raw word as-is.
                        sub_words.append(word.lower())
                else:
                    sub_words.append(word.lower())

                ss['splitted']=sub_words
                return_word_list.append(ss)
            except:
                self.logger.debug("|" + word + "| caused an error during processing")
                self.logger.error("word_splitter.split() likely received an empty list / Error : {0}".format(format_exc()))

        return return_word_list

    def _splitl(self, gt7_word_list):

        result = []

        for val in self._split(gt7_word_list):
            result += val["splitted"]

        return result

    def _splitw(self, word):

        word_l = []
        word_l.append(word)

        result = self._split(word_l)

        return result

    def __check_last_char(self, word):

        confusing_char = ['s', 'y']
        last_char = word[len(word)-1]
        word_except_last_char = word[0:len(word)-1]
        if last_char in confusing_char:
            if self.dictionary_en.check(word_except_last_char):
                return word_except_last_char

        return word

    def __clear_fp(self, sub_words):

        length_check = 0
        for w in sub_words:
            if (length_check + len(w)) < self.length+1:
                length_check = length_check + len(w)
            else:
                sub_words.remove(w)

        sub_words = self.__to_lower(sub_words)
        return sub_words

    def __to_lower(self, sub_words):

        lower_sub_list = []

        for w in sub_words:
            lower_sub_list.append(str(w.lower()))

        return lower_sub_list

    def __capitalize(self, word):
        return word[0].upper() + word[1:]

    def __file_capitalize(self, path, name):

        """
        In enchant, custom words may require an uppercase first letter for matching.
        So before checking a word, I capitalize the first letter and query the dictionary.
        For this reason, words in the file are also capitalized and saved in that format.
        :return: 
        """

        personel_dict_txt = open("{0}{1}".format(path, name), "r")

        personel_dict = []

        for word in personel_dict_txt:
            personel_dict.append(self.__capitalize(word.strip()))

        personel_dict_txt.close()

        personel_dict_txt = open("{0}{1}-2".format(path, name), "w")

        for word in personel_dict:
            personel_dict_txt.write(word+"\n")
