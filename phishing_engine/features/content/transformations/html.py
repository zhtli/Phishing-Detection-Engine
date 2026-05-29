import re
import warnings
from collections import Counter, OrderedDict
from typing import Iterable

from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from pandas import DataFrame, isnull

from phishing_engine.features.common.base import Transformation

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


# TODO fix 'None' problems
class HTMLTransformation(Transformation):
    def __init__(self, _):
        super().__init__()
        self._patterns = OrderedDict({
            "createElement": re.compile(r"(createElement\()"),
            "write": re.compile(r"(write\()"),
            "charCodeAt": re.compile(r"(charCodeAt\()"),
            "concat": re.compile(r"(concat\()"),
            "escape": re.compile(r"((?<!n)escape\()"),
            "eval": re.compile(r"(eval\()"),
            "exec": re.compile(r"(exec\()"),
            "fromCharCode": re.compile(r"(fromCharCode\()"),
            "link": re.compile(r"(link\()"),
            "parseInt": re.compile(r"(parseInt\()"),
            "replace": re.compile(r"(replace\()"),
            "search": re.compile(r"(search\()"),
            "substring": re.compile(r"(substring\()"),
            "unescape": re.compile(r"(unescape\()"),
            "addEventListener": re.compile(r"(addEventListener\()"),
            "setInterval": re.compile(r"(setInterval\()"),
            "setTimeout": re.compile(r"(setTimeout\()"),
            "push": re.compile(r"(push\()"),
            "indexOf": re.compile(r"(indexOf\()"),
            "documentWrite": re.compile(r"(document\.write\()"),
            "get": re.compile(r"(get\()"),
            "find": re.compile(r"(find\()"),
            "documentCreateElement": re.compile(r"(document\.createElement\()"),
            "windowSetTimeout": re.compile(r"(window\.setTimeout\()"),
            "windowSetInterval": re.compile(r"(window\.setInterval\()"),
            "hexEncoding": re.compile(r'\\x[0-9A-Fa-f]{2}'),
            "unicodeEncoding": re.compile(r'\\u[0-9A-Fa-f]{4}'),
            "longVariableName": re.compile(r'\b[a-zA-Z0-9_]{20,}\b')
        })

    def get_text_pattern(self):
        return (re.compile(r"\b(suspended|blocked|forbidden|denied|restricted)\b", re.IGNORECASE),
                re.compile(r'\s{2,}'))

    def get_tags_f(self, soup: BeautifulSoup) -> list:
        if not soup:
            return [0] * 53

        name_counts = Counter()
        script_src = script_async = script_type = 0
        anchors = []
        hidden_inputs = 0
        hidden_elements = 0
        input_password = 0
        iframe_src = iframe_src_http = 0
        img_src = 0
        link_href = link_href_http = link_href_css = link_type = 0
        link_type_app = link_shortlink = 0
        icon_count = css_internal = css_external = 0
        icon_external = False
        any_href = 0
        form_actions = form_http = form_php = form_hash = form_js = 0
        malicious_form = False

        for el in soup.find_all(True):
            name = el.name
            name_counts[name] += 1
            style = el.get('style', '')

            if (el.has_attr('hidden') or
                    'display: none' in style or
                    'visibility: hidden' in style or
                    'opacity: 0' in style or
                    'position: absolute' in style):
                hidden_elements += 1

            if el.has_attr('href'):
                any_href += 1

            if name == 'script':
                if el.has_attr('src'):
                    script_src += 1
                if el.has_attr('async'):
                    script_async += 1
                if el.has_attr('type'):
                    script_type += 1
            elif name == 'a':
                anchors.append(el)
            elif name == 'input':
                if el.get('type') == 'password':
                    input_password += 1
                if (el.get('type') == 'hidden' or
                        'display: none' in style or
                        'visibility: hidden' in style or
                        'opacity: 0' in style or
                        'position: absolute' in style):
                    hidden_inputs += 1
            elif name == 'iframe':
                if el.has_attr('src'):
                    iframe_src += 1
                    if "http" in el.get('src', ''):
                        iframe_src_http += 1
            elif name == 'img':
                if el.has_attr('src'):
                    img_src += 1
            elif name == 'link':
                href = el.get('href', '')
                if el.has_attr('href'):
                    link_href += 1
                    if "http" in href:
                        link_href_http += 1
                    if ".css" in href:
                        link_href_css += 1
                if el.has_attr('type'):
                    link_type += 1
                    if el.get('type') == 'application/rss+xml':
                        link_type_app += 1
                # rel is a multi-valued attribute: bs4 returns it as a list.
                rel = el.get('rel')
                rel_val = ' '.join(rel) if isinstance(rel, list) else (rel or '')
                if rel_val == 'shortlink':
                    link_shortlink += 1
                elif rel_val == 'shortcut icon':
                    icon_count += 1
                    if "http" in href:
                        icon_external = True
                elif rel_val == 'stylesheet':
                    if "http" in href:
                        css_external += 1
                    else:
                        css_internal += 1
            elif name == 'form':
                if el.has_attr('action'):
                    form_actions += 1
                    action = el.get('action', '')
                    if "http" in action:
                        form_http += 1
                    if ".php" in action:
                        form_php += 1
                    if "#" in action:
                        form_hash += 1
                    if "javascript:void()" in action or "javascript:void(0)" in action:
                        form_js += 1
                    if ("http" in action or ".php" in action or
                            "#" in action or "javascript:void" in action):
                        malicious_form = True

        try:
            hrefs = [a.get('href') for a in anchors if a.get('href')]
            hrefs_http = [href for href in hrefs if "http" in href]
            hrefs_internal = [href for href in hrefs if "http" not in href]
            anchor_http = sum(1 for a in anchors if "http" in a.get('href', ''))
            anchor_com = sum(1 for a in anchors if ".com" in a.get('href', ''))
            anchor_hash = sum(1 for a in anchors if a.get('href') == '#')
            anchor_content = sum(1 for a in anchors if a.get('href') == '#content')
            anchor_void = sum(1 for a in anchors if a.get('href') == 'javascript:void(0)')
        except Exception:
            anchors, hrefs, hrefs_http, hrefs_internal = [], [], [], []
            anchor_http = anchor_com = 0
            anchor_hash = anchor_content = anchor_void = 0

        no_hrefs_flag = len(hrefs) == 0
        external_hrefs_flag = len(hrefs_http) / len(hrefs) > 0.5 if hrefs else 0
        internal_hrefs_flag = len(hrefs_internal) / len(hrefs) <= 0.5 if hrefs else 0
        most_common = Counter(hrefs).most_common(1)[0][1] / len(hrefs) if hrefs else 0

        return [len(name_counts), name_counts.get('p', 0), name_counts.get('div', 0), name_counts.get('title', 0),
                script_src,
                name_counts.get('link', 0), name_counts.get('script', 0), script_async,
                script_type,
                len(anchors), anchor_hash,
                anchor_http,
                anchor_com,
                name_counts.get('input', 0), input_password, hidden_elements,
                hidden_inputs, name_counts.get('object', 0), name_counts.get('embed', 0),
                name_counts.get('frame', 0), name_counts.get('iframe', 0), iframe_src,
                iframe_src_http,
                name_counts.get('center', 0), name_counts.get('img', 0), img_src,
                name_counts.get('meta', 0), link_href,
                link_href_http,
                link_href_css,
                link_type, link_type_app,
                link_shortlink, any_href,
                form_actions, form_http,
                name_counts.get('strong', 0), int(no_hrefs_flag), int(internal_hrefs_flag), len(hrefs_internal),
                int(external_hrefs_flag),
                len(hrefs_http), icon_count, int(icon_external),
                form_php,
                form_hash,
                form_js,
                int(malicious_form),
                most_common,
                css_internal,
                css_external,
                anchor_content, anchor_void
                ]

    @staticmethod
    def make_soup(html):
        if isnull(html):
            return None
        soup = BeautifulSoup(html, 'lxml')
        if soup.is_xml:
            soup = BeautifulSoup(html, 'xml')
        return soup

    def transform(self, df: DataFrame) -> DataFrame:
        df['soup'] = df['html'].apply(self.make_soup)
        df['js_inline'] = df['soup'].apply(
            lambda soup: [script for script in soup.find_all('script') if not script.has_attr('src')] if soup else [])

        (df["html_num_of_tags"], df["html_num_of_paragraphs"], df["html_num_of_divs"], df["html_num_of_titles"],
         df["html_num_of_external_js"],
         df["html_num_of_links"], df["html_num_of_scripts"], df["html_num_of_scripts_async"],
         df["html_num_of_scripts_type"], df["html_num_of_anchors"],
         df["html_num_of_anchors_to_hash"], df["html_num_of_anchors_to_https"], df["html_num_of_anchors_to_com"],
         df["html_num_of_inputs"], df["html_num_of_input_password"],
         df["html_num_of_hidden_elements"], df["html_num_of_input_hidden"], df["html_num_of_objects"],
         df["html_num_of_embeds"], df["html_num_of_frame"],
         df["html_num_of_iframe"], df["html_num_of_iframe_src"], df["html_num_of_iframe_src_https"],
         df["html_num_of_center"], df["html_num_of_imgs"],
         df["html_num_of_imgs_src"], df["html_num_of_meta"], df["html_num_of_links_href"],
         df["html_num_of_links_href_https"], df["html_num_of_links_href_css"],
         df["html_num_of_links_type"], df["html_num_of_link_type_app"], df["html_num_of_link_rel"],
         df["html_num_of_all_hrefs"], df["html_num_of_form_action"],
         df["html_num_of_form_http"], df["html_num_of_strong"], df["html_no_hrefs"], df["html_internal_href_ratio"],
         df["html_num_of_internal_hrefs"],
         df["html_external_href_ratio"], df["html_num_of_external_href"], df["html_num_of_icon"],
         df["html_icon_external"], df["html_num_of_form_php"],
         df["html_num_of_form_hash"], df["html_num_of_form_js"], df["html_malicious_form"], df["html_most_common"],
         df["html_num_of_css_internal"], df["html_num_of_css_external"],
         df["html_num_of_anchors_to_content"], df["html_num_of_anchors_to_void"]) = zip(
            *df["soup"].apply(self.get_tags_f))

        df["html_num_of_words"], df["html_num_of_lines"], df["html_unique_words"], df["html_average_word_len"], df[
            "html_blocked_keywords_label"], df["html_num_of_blank_spaces"] = zip(*df["html"].apply(self.get_text_f))

        (df["html_create_element"], df["html_write"], df["html_char_code_at"], df["html_concat"], df["html_escape"],
         df["html_eval"],
         df["html_exec"], df["html_from_char_code"], df["html_link"], df["html_parse_int"], df["html_replace"],
         df["html_search"],
         df["html_substring"], df["html_unescape"], df["html_add_event_listener"], df["html_set_interval"],
         df["html_set_timeout"],
         df["html_push"], df["html_index_of"], df["html_document_write"], df["html_get"], df["html_find"],
         df["html_document_create_element"],
         df["html_window_set_timeout"], df["html_window_set_interval"], df["html_hex_encoding"],
         df["html_unicode_encoding"],
         df["html_long_variable_name"]) = zip(*df["js_inline"].apply(self.get_js_f))

        df.drop("soup", axis=1, inplace=True)
        df.drop("js_inline", axis=1, inplace=True)
        return df

    def get_text_f(self, html: str) -> tuple[int, int, int, float, int, int]:
        if html is None or html == 'None':
            return 0, 0, 0, 0.0, 0, 0
        try:
            words = html.split()
            html_num_of_words = len(words)
            html_num_of_lines = len(html.splitlines())
            html_unique_words = len(set(words))
            html_average_word_len = sum(len(word) for word in words) / len(words) if words else 0
        except Exception as e:
            html_num_of_words, html_num_of_lines, html_unique_words, html_average_word_len = 0, 0, 0, 0

        patterns = self.get_text_pattern()
        try:
            html_num_of_blank_spaces = len(patterns[1].findall(html))
        except Exception as e:
            html_num_of_blank_spaces = 0
        try:
            blocked_keywords_count = len(patterns[0].findall(html))
        except Exception as e:
            blocked_keywords_count = 0

        if blocked_keywords_count > 0:
            html_blocked_keywords_label = 1
        else:
            html_blocked_keywords_label = 0

        return (html_num_of_words, html_num_of_lines, html_unique_words, html_average_word_len,
                html_blocked_keywords_label, html_num_of_blank_spaces)

    def get_js_f(self, js: list) -> Iterable[int | float]:
        if not js:
            return [0] * (len(self._patterns))

        regex_patterns = self._patterns
        dic: dict[str, int | float] = {key: 0 for key in regex_patterns.keys()}

        for script in js:
            for key, pattern in regex_patterns.items():
                dic[key] += len(pattern.findall(str(script)))

        return dic.values()

    @property
    def features(self) -> dict:
        return {
            "html_num_of_words": "Int64",
            "html_num_of_lines": "Int64",
            "html_unique_words": "Int64",
            "html_average_word_len": "float64",
            "html_blocked_keywords_label": "Int64",
            "html_num_of_blank_spaces": "Int64",

            "html_num_of_tags": "Int64",
            "html_num_of_paragraphs": "Int64",
            "html_num_of_divs": "Int64",
            "html_num_of_titles": "Int64",
            "html_num_of_external_js": "Int64",
            "html_num_of_links": "Int64",
            "html_num_of_scripts": "Int64",
            "html_num_of_scripts_async": "Int64",
            "html_num_of_scripts_type": "Int64",
            "html_num_of_anchors": "Int64",
            "html_num_of_anchors_to_hash": "Int64",
            "html_num_of_anchors_to_https": "Int64",
            "html_num_of_anchors_to_com": "Int64",
            "html_num_of_inputs": "Int64",
            "html_num_of_input_password": "Int64",
            "html_num_of_hidden_elements": "Int64",
            "html_num_of_input_hidden": "Int64",
            "html_num_of_objects": "Int64",
            "html_num_of_embeds": "Int64",
            "html_num_of_frame": "Int64",
            "html_num_of_iframe": "Int64",
            "html_num_of_iframe_src": "Int64",
            "html_num_of_iframe_src_https": "Int64",
            "html_num_of_center": "Int64",
            "html_num_of_imgs": "Int64",
            "html_num_of_imgs_src": "Int64",
            "html_num_of_meta": "Int64",
            "html_num_of_links_href": "Int64",
            "html_num_of_links_href_https": "Int64",
            "html_num_of_links_href_css": "Int64",
            "html_num_of_links_type": "Int64",
            "html_num_of_link_type_app": "Int64",
            "html_num_of_link_rel": "Int64",
            "html_num_of_all_hrefs": "Int64",
            "html_num_of_form_action": "Int64",
            "html_num_of_form_http": "Int64",
            "html_num_of_strong": "Int64",
            "html_no_hrefs": "Int64",
            "html_internal_href_ratio": "Int64",
            "html_num_of_internal_hrefs": "Int64",
            "html_external_href_ratio": "Int64",
            "html_num_of_external_href": "Int64",
            "html_num_of_icon": "Int64",
            "html_icon_external": "Int64",
            "html_num_of_form_php": "Int64",
            "html_num_of_form_hash": "Int64",
            "html_num_of_form_js": "Int64",
            "html_malicious_form": "Int64",
            "html_most_common": "float64",
            "html_num_of_css_internal": "Int64",
            "html_num_of_css_external": "Int64",
            "html_num_of_anchors_to_content": "Int64",
            "html_num_of_anchors_to_void": "Int64",

            "html_create_element": "Int64",
            "html_write": "Int64",
            "html_char_code_at": "Int64",
            "html_concat": "Int64",
            "html_escape": "Int64",
            "html_eval": "Int64",
            "html_exec": "Int64",
            "html_from_char_code": "Int64",
            "html_link": "Int64",
            "html_parse_int": "Int64",
            "html_replace": "Int64",
            "html_search": "Int64",
            "html_substring": "Int64",
            "html_unescape": "Int64",
            "html_add_event_listener": "Int64",
            "html_set_interval": "Int64",
            "html_set_timeout": "Int64",
            "html_push": "Int64",
            "html_index_of": "Int64",
            "html_document_write": "Int64",
            "html_get": "Int64",
            "html_find": "Int64",
            "html_document_create_element": "Int64",
            "html_window_set_timeout": "Int64",
            "html_window_set_interval": "Int64",
            "html_hex_encoding": "Int64",
            "html_unicode_encoding": "Int64",
            "html_long_variable_name": "Int64"
        }
